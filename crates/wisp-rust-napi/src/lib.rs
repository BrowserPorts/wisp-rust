#![deny(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use napi::bindgen_prelude::{Function, Promise};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Error, Result, Status};
use napi_derive::napi;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;
use wisp_config::{
    build_wisp_wt_options, minus_one_to_unlimited, parse_toml, unlimited_to_minus_one,
    WispAuthResolveFuture, WispAuthResolver, WispAuthTokenPolicy, WispServerOptions,
    WispWtConfigToml, WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_core::{Runtime, RuntimeConfig, ServeHandle};
use wisp_iphash::IpHashBans;
use wisp_reports::{set_report_hook, Report};
use wisp_wisp_server::EgressPlugin;

#[cfg(feature = "proxy-providers")]
mod egress;

#[napi(js_name = "WispRust")]
pub struct WispRust {
    state: Arc<Mutex<WispRustState>>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
}

struct WispRustState {
    config: RuntimeConfig,
    runtime: Option<Runtime>,
    ws_handle: Option<JoinHandle<()>>,
    wt_handle: Option<ServeHandle>,
    /// Set by `configure_egress`; the runtime takes it at the next start.
    egress: Option<Arc<dyn EgressPlugin>>,
    configured_auth_tokens: HashMap<String, WispAuthTokenPolicy>,
    configured_auth_handler: Option<AuthHandler>,
    configured_limit_profiles: HashMap<String, WispServerOptions>,
    /// Banned client IP hashes. Owned here, not by the runtime, so bans set
    /// before `start()` apply from the first connection and survive a restart.
    ip_bans: Arc<IpHashBans>,
}

/// One emitted report as the JS callback receives it. Absent values arrive as
/// `null`, not `undefined`.
#[napi(object, use_nullable = true)]
pub struct WispReport {
    /// Stable report code such as `WISP_IP_HASH_BANNED`.
    pub code: String,
    /// Snake_case name of the report type such as `ip_hash_banned`.
    pub kind: String,
    pub ip_hash: Option<String>,
    /// Unix time in milliseconds.
    pub at: i64,
    /// `key=value` summary of whatever the report carries, or `null`. Kept for
    /// compatibility; read the fields below instead of splitting it.
    pub detail: Option<String>,
    pub transport: Option<String>,
    pub origin: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u32>,
    pub stream_type: Option<String>,
    pub proxy_request_type: Option<String>,
    pub provider: Option<String>,
    pub limit_type: Option<String>,
    pub amount: Option<i64>,
    pub transport_close_code: Option<i32>,
    pub wisp_close_code: Option<i32>,
}

impl From<&Report> for WispReport {
    fn from(report: &Report) -> Self {
        Self {
            code: report.report_code.to_owned(),
            kind: report.error_type.kind().to_owned(),
            ip_hash: report.ip_hash.clone(),
            at: report.occurred_at,
            detail: report.detail(),
            transport: report.transport.map(|value| value.as_str().to_owned()),
            origin: report.origin.clone(),
            hostname: report.hostname.clone(),
            port: report.port.map(u32::from),
            stream_type: report.stream_type.map(|value| value.as_str().to_owned()),
            proxy_request_type: report.proxy_request_type.clone(),
            provider: report.provider.clone(),
            limit_type: report.limit_type.clone(),
            amount: report.amount,
            transport_close_code: report.protocol_code.transport_close_code,
            wisp_close_code: report.protocol_code.wisp_close_code,
        }
    }
}

/// Weak, so a registered callback never keeps the process alive, and bounded,
/// so a slow JS thread drops reports instead of growing a queue behind a flood.
type ReportCallback =
    Arc<ThreadsafeFunction<WispReport, (), WispReport, Status, false, true, 1024>>;

type AuthHandler = Arc<ThreadsafeFunction<String, Promise<Value>, String, Status, false>>;

/// A token the JS handler refused is remembered this long, so a client
/// retrying a bad token does not reach the handler each time.
const AUTH_NEGATIVE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// Refused tokens remembered at most; expired entries go first, then all.
const AUTH_NEGATIVE_CACHE_MAX: usize = 4096;
/// JS handler calls in flight at once. A token arriving while all are busy is
/// refused at once instead of queueing behind them.
const AUTH_HANDLER_MAX_IN_FLIGHT: usize = 64;
/// A handler call that has not settled by then is abandoned and its slot
/// freed, even if the listener stopped waiting for it earlier.
const AUTH_HANDLER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

struct NapiAuthResolver {
    tokens: HashMap<String, WispAuthTokenPolicy>,
    handler: Option<AuthHandler>,
    gate: Arc<AuthHandlerGate>,
}

/// Bounds the work unknown tokens can cause in the JS handler: a short-lived
/// cache of refused tokens (keyed by a keyed hash, never the token) and a cap
/// on calls in flight.
struct AuthHandlerGate {
    hasher: std::collections::hash_map::RandomState,
    refused: Mutex<HashMap<u64, std::time::Instant>>,
    in_flight: Arc<tokio::sync::Semaphore>,
}

impl AuthHandlerGate {
    fn new() -> Self {
        Self {
            hasher: std::collections::hash_map::RandomState::new(),
            refused: Mutex::new(HashMap::new()),
            in_flight: Arc::new(tokio::sync::Semaphore::new(AUTH_HANDLER_MAX_IN_FLIGHT)),
        }
    }

    fn key(&self, token: &str) -> u64 {
        use std::hash::BuildHasher;
        self.hasher.hash_one(token)
    }

    fn recently_refused(&self, key: u64) -> bool {
        let mut refused = self.refused.lock();
        match refused.get(&key) {
            Some(at) if at.elapsed() < AUTH_NEGATIVE_TTL => true,
            Some(_) => {
                refused.remove(&key);
                false
            }
            None => false,
        }
    }

    fn remember_refused(&self, key: u64) {
        let mut refused = self.refused.lock();
        if refused.len() >= AUTH_NEGATIVE_CACHE_MAX {
            refused.retain(|_, at| at.elapsed() < AUTH_NEGATIVE_TTL);
            if refused.len() >= AUTH_NEGATIVE_CACHE_MAX {
                refused.clear();
            }
        }
        refused.insert(key, std::time::Instant::now());
    }
}

/// What the JS handler said about a token: a policy, a refusal, or nothing
/// usable (the call failed or missed its deadline), which is not cached.
enum HandlerAnswer {
    Policy(Box<WispAuthTokenPolicy>),
    Refused,
    Unavailable,
}

fn handler_answer(val: Value) -> HandlerAnswer {
    if val.is_null() || val == Value::Bool(false) {
        return HandlerAnswer::Refused;
    }
    if val == Value::Bool(true) {
        return HandlerAnswer::Policy(Box::default());
    }
    // A policy with unknown keys is refused rather than read as unrestricted.
    match serde_json::from_value(val) {
        Ok(policy) => HandlerAnswer::Policy(Box::new(policy)),
        Err(_) => HandlerAnswer::Refused,
    }
}

impl WispAuthResolver for NapiAuthResolver {
    fn resolve(&self, token: String) -> WispAuthResolveFuture {
        let static_policy = self.tokens.get(&token).cloned();
        let handler = self.handler.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            if static_policy.is_some() {
                return static_policy;
            }
            let handler = handler?;
            let key = gate.key(&token);
            if gate.recently_refused(key) {
                return None;
            }
            let permit = gate.in_flight.clone().try_acquire_owned().ok()?;
            // The call runs in its own task that holds the slot until the
            // handler settles or the deadline passes, so a listener giving up
            // after resolver_timeout_ms cannot free the slot while JS still
            // works on the token.
            let call = tokio::spawn(async move {
                let _permit = permit;
                let settled = tokio::time::timeout(AUTH_HANDLER_DEADLINE, async {
                    let promise = handler.call_async_catch(token).await.ok()?;
                    promise.await.ok()
                })
                .await;
                match settled {
                    Ok(Some(val)) => handler_answer(val),
                    _ => HandlerAnswer::Unavailable,
                }
            });
            match call.await.unwrap_or(HandlerAnswer::Unavailable) {
                HandlerAnswer::Policy(policy) => Some(*policy),
                HandlerAnswer::Refused => {
                    gate.remember_refused(key);
                    None
                }
                HandlerAnswer::Unavailable => None,
            }
        })
    }
}

impl WispRustState {
    fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            runtime: None,
            ws_handle: None,
            wt_handle: None,
            egress: None,
            configured_auth_tokens: HashMap::new(),
            configured_auth_handler: None,
            configured_limit_profiles: HashMap::new(),
            ip_bans: Arc::new(IpHashBans::new()),
        }
    }
}

#[napi]
impl WispRust {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let config = RuntimeConfig::from_options(WispWtServerOptions::default()).map_err(js_err)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[napi(factory)]
    pub fn from_toml_path(path: String) -> Result<Self> {
        let config = RuntimeConfig::from_toml(Path::new(&path)).map_err(js_err)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[napi(factory)]
    pub fn from_toml(toml: String, source: Option<String>) -> Result<Self> {
        let source = source.unwrap_or_else(|| "wisp-rust-napi".to_owned());
        let parsed = parse_toml(&toml, &source).map_err(js_err)?;
        let options = build_wisp_wt_options(&parsed);
        let config = RuntimeConfig::from_options(options).map_err(js_err)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[napi(factory)]
    pub fn from_config(config: Value) -> Result<Self> {
        let config = runtime_config_from_value(config)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[napi]
    pub async fn start(&self) -> Result<Value> {
        let _lifecycle = self.lifecycle.lock().await;
        let (runtime, ws_handle, wt_enabled) = {
            let guard = self.state.lock();
            if guard.runtime.is_some() {
                return Ok(status_value(&guard));
            }
            let config = guard.config.clone().with_egress(guard.egress.clone());
            let runtime = Runtime::start(config)
                .map_err(js_err)?
                .with_ip_bans(guard.ip_bans.clone());
            apply_configured_auth(&runtime, &guard)?;
            let ws_handle = runtime.bind_ws().map_err(js_err)?;
            let wt_enabled = guard.config.options.enabled;
            (runtime, ws_handle, wt_enabled)
        };
        let wt_handle = if wt_enabled {
            match runtime.bind().await {
                Ok(handle) => Some(handle),
                Err(error) => {
                    runtime.shutdown().await;
                    if let Some(handle) = ws_handle {
                        handle.abort();
                        let _ = handle.await;
                    }
                    return Err(js_err(error));
                }
            }
        } else {
            None
        };
        let mut guard = self.state.lock();
        guard.ws_handle = ws_handle;
        guard.wt_handle = wt_handle;
        guard.runtime = Some(runtime);
        Ok(status_value(&guard))
    }

    #[napi]
    pub async fn stop(&self) -> Result<Value> {
        let _lifecycle = self.lifecycle.lock().await;
        let (runtime, ws_handle, wt_handle) = {
            let mut guard = self.state.lock();
            let runtime = guard.runtime.take();
            let ws_handle = guard.ws_handle.take();
            let wt_handle = guard.wt_handle.take();
            (runtime, ws_handle, wt_handle)
        };

        if let Some(runtime) = runtime {
            runtime.shutdown().await;
        }
        if let Some(handle) = ws_handle {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = wt_handle {
            // Closing waits for msquic to release every connection, which needs
            // the runtime's workers, so wait on a blocking thread instead.
            let _ = tokio::task::spawn_blocking(move || handle.close_blocking()).await;
        }

        let guard = self.state.lock();
        Ok(status_value(&guard))
    }

    #[napi]
    pub fn status(&self) -> Value {
        status_value(&self.state.lock())
    }

    // Replace the whole banned-IP-hash set. Applies to the next connection on
    // every transport, before or after `start()`, with no restart.
    #[napi(ts_return_type = "{ count: number }")]
    pub fn set_banned_ip_hashes(&self, hashes: Vec<String>) -> Value {
        let count = self.state.lock().ip_bans.replace(hashes);
        json!({ "count": count })
    }

    #[napi]
    pub fn banned_ip_hashes(&self) -> Vec<String> {
        let mut hashes: Vec<String> = self
            .state
            .lock()
            .ip_bans
            .snapshot()
            .iter()
            .cloned()
            .collect();
        hashes.sort();
        hashes
    }

    // Receive every emitted report. Replaces any earlier callback. Calls are
    // queued without blocking the connection path and dropped if the queue
    // is full. The hook is process-wide, like the report log target.
    #[napi(ts_args_type = "callback: (report: WispReport) => void")]
    pub fn on_report(&self, callback: Function<'_, WispReport, ()>) -> Result<()> {
        let sink: ReportCallback = Arc::new(
            callback
                .build_threadsafe_function::<WispReport>()
                .weak::<true>()
                .max_queue_size::<1024>()
                .build()?,
        );
        // The hook owns the callback, so replacing the hook releases the old one.
        set_report_hook(Some(Arc::new(move |report: &Report| {
            sink.call(
                WispReport::from(report),
                ThreadsafeFunctionCallMode::NonBlocking,
            );
        })));
        Ok(())
    }

    #[napi]
    pub fn bound_urls(&self) -> Vec<String> {
        bound_urls(&self.state.lock().config)
    }

    /// Build the egress plugin from its configuration. It decides how
    /// upstream streams leave the server and answers the proxy-control
    /// channel; without one every stream is dialed directly. Call it before
    /// `start`, since the runtime takes the plugin when it starts. Only a
    /// build with the `proxy-providers` feature has a plugin to build.
    #[napi]
    pub fn configure_egress(&self, config: Value) -> Result<Value> {
        let plugin = build_egress(&config)?;
        let status = plugin.status();
        self.state.lock().egress = Some(plugin);
        Ok(status)
    }

    /// One operator call to the egress plugin, by the plugin's name for it.
    #[napi]
    pub async fn egress_admin(&self, op: String, args: Option<Value>) -> Result<Value> {
        let plugin = self.require_egress()?;
        plugin
            .admin(&op, args.unwrap_or(Value::Null))
            .await
            .map_err(js_err)
    }

    #[napi]
    pub async fn set_route(&self, route: Value) -> Result<Value> {
        self.egress_admin("set_route".to_owned(), Some(route)).await
    }

    #[napi]
    pub async fn remove_route(&self, route_id: String) -> Result<Value> {
        self.egress_admin(
            "remove_route".to_owned(),
            Some(json!({ "routeId": route_id })),
        )
        .await
    }

    #[napi]
    pub async fn list_routes(&self) -> Result<Value> {
        self.egress_admin("list_routes".to_owned(), None).await
    }

    #[napi]
    pub async fn rotate_route(&self, route_id: String) -> Result<Value> {
        self.egress_admin(
            "rotate_route".to_owned(),
            Some(json!({ "routeId": route_id })),
        )
        .await
    }

    #[napi]
    pub async fn locations(&self, provider: Option<String>) -> Result<Value> {
        self.egress_admin(
            "locations".to_owned(),
            Some(json!({ "provider": provider })),
        )
        .await
    }

    #[napi]
    pub async fn refresh_locations(&self, provider: Option<String>) -> Result<Value> {
        self.locations(provider).await
    }

    #[napi]
    pub async fn provider_status(&self) -> Result<Value> {
        self.egress_admin("provider_status".to_owned(), None).await
    }

    #[napi]
    pub async fn egress_inventory(&self) -> Result<Value> {
        self.egress_admin("egress_inventory".to_owned(), None).await
    }

    #[napi]
    pub async fn block_egress_ip(&self, ip: String) -> Result<Value> {
        self.egress_admin("block_egress_ip".to_owned(), Some(json!({ "ip": ip })))
            .await
    }

    #[napi]
    pub async fn release_egress_ip(&self, ip: String) -> Result<Value> {
        self.egress_admin("release_egress_ip".to_owned(), Some(json!({ "ip": ip })))
            .await
    }

    #[napi]
    pub async fn get_policy(&self) -> Result<Value> {
        self.egress_admin("get_policy".to_owned(), None).await
    }

    #[napi]
    pub async fn set_policy(&self, policy: Value) -> Result<Value> {
        self.egress_admin("set_policy".to_owned(), Some(policy))
            .await
    }

    #[napi]
    pub fn get_limits(&self) -> Value {
        limits_to_js(&current_base_limits(&self.state.lock()))
    }

    #[napi]
    pub fn patch_limits(&self, patch: Value) -> Result<Value> {
        let mut guard = self.state.lock();
        let next = patch_wisp_options(&current_base_limits(&guard), patch)?;
        set_config_base_limits(&mut guard, next.clone());
        if let Some(runtime) = guard.runtime.as_ref() {
            runtime.register_limit_profile(WISP_BASE_LIMIT_PROFILE.to_owned(), next.clone());
        }
        Ok(limits_to_js(&next))
    }

    #[napi]
    pub fn set_limit_profile(&self, name: String, limits: Value) -> Result<Value> {
        if !profile_name_is_valid(&name) {
            return Err(Error::new(
                Status::InvalidArg,
                "limit profile name is invalid",
            ));
        }
        let mut guard = self.state.lock();
        let base = guard
            .configured_limit_profiles
            .get(&name)
            .cloned()
            .unwrap_or_else(|| current_base_limits(&guard));
        let next = patch_wisp_options(&base, limits)?;
        guard
            .configured_limit_profiles
            .insert(name.clone(), next.clone());
        if let Some(runtime) = guard.runtime.as_ref() {
            runtime.register_limit_profile(name.clone(), next.clone());
        }
        Ok(json!({
            "name": name,
            "limits": limits_to_js(&next),
        }))
    }

    #[napi]
    pub fn patch_limit_profile(&self, name: String, patch: Value) -> Result<Value> {
        self.set_limit_profile(name, patch)
    }

    // Forget a named limit profile, in the stored config and in the running
    // runtime. True when a profile was removed. The base profile holds the
    // limits every unnamed connection uses, so it cannot be removed.
    #[napi]
    pub fn remove_limit_profile(&self, name: String) -> Result<bool> {
        if name == WISP_BASE_LIMIT_PROFILE {
            return Err(Error::new(
                Status::InvalidArg,
                "the base limit profile cannot be removed",
            ));
        }
        let mut guard = self.state.lock();
        let configured = guard.configured_limit_profiles.remove(&name).is_some();
        let running = guard
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.remove_limit_profile(&name).is_some());
        Ok(configured || running)
    }

    #[napi]
    pub fn limit_profile(&self, name: String) -> Value {
        let guard = self.state.lock();
        if let Some(runtime) = guard.runtime.as_ref() {
            runtime
                .limit_profile(&name)
                .map(|limits| limits_to_js(&limits))
                .unwrap_or(Value::Null)
        } else {
            guard
                .configured_limit_profiles
                .get(&name)
                .map(limits_to_js)
                .unwrap_or(Value::Null)
        }
    }

    #[napi]
    pub fn list_limit_profiles(&self) -> Value {
        let guard = self.state.lock();
        if let Some(runtime) = guard.runtime.as_ref() {
            let profiles: Vec<Value> = runtime
                .list_limit_profiles()
                .into_iter()
                .map(|(name, limits)| {
                    json!({
                        "name": name,
                        "limits": limits_to_js(&limits),
                    })
                })
                .collect();
            json!(profiles)
        } else {
            let mut profiles: Vec<Value> = guard
                .configured_limit_profiles
                .iter()
                .map(|(name, limits)| {
                    json!({
                        "name": name,
                        "limits": limits_to_js(limits),
                    })
                })
                .collect();
            profiles.sort_by(|a, b| {
                let left = a.get("name").and_then(Value::as_str).unwrap_or_default();
                let right = b.get("name").and_then(Value::as_str).unwrap_or_default();
                left.cmp(right)
            });
            Value::Array(profiles)
        }
    }

    #[napi]
    pub fn register_auth_token(&self, token: String, policy: Value) -> Result<Value> {
        if !token_is_valid(&token) {
            return Err(Error::new(Status::InvalidArg, "auth token is invalid"));
        }
        let policy: WispAuthTokenPolicy = serde_json::from_value(policy).map_err(js_err)?;
        {
            let mut guard = self.state.lock();
            guard
                .configured_auth_tokens
                .insert(token.clone(), policy.clone());
            if let Some(runtime) = guard.runtime.as_ref() {
                install_auth_resolver(runtime, &guard);
            }
        }
        Ok(json!({
            "registered": true,
            "token": token,
            "policy": policy,
        }))
    }

    #[napi]
    pub fn revoke_auth_token(&self, token: String) -> Value {
        let removed = {
            let mut guard = self.state.lock();
            let pending = guard.configured_auth_tokens.remove(&token).is_some();
            if let Some(runtime) = guard.runtime.as_ref() {
                install_auth_resolver(runtime, &guard);
            }
            pending
        };
        json!({
            "removed": removed,
        })
    }

    #[napi]
    pub fn list_auth_tokens(&self) -> Value {
        let guard = self.state.lock();
        let mut tokens: Vec<Value> = guard
            .configured_auth_tokens
            .iter()
            .map(|(token, policy)| {
                json!({
                    "token": token,
                    "policy": policy,
                })
            })
            .collect();
        tokens.sort_by(|a, b| {
            let left = a.get("token").and_then(Value::as_str).unwrap_or_default();
            let right = b.get("token").and_then(Value::as_str).unwrap_or_default();
            left.cmp(right)
        });
        Value::Array(tokens)
    }

    #[napi]
    pub fn set_auth_token_handler(
        &self,
        handler: Option<Function<'_, String, Promise<Value>>>,
    ) -> Result<Value> {
        let configured = handler.is_some();
        let auth_handler = handler
            .map(|handler| {
                handler
                    .build_threadsafe_function::<String>()
                    .build()
                    .map(Arc::new)
            })
            .transpose()?;
        {
            let mut guard = self.state.lock();
            guard.configured_auth_handler = auth_handler;
            if let Some(runtime) = guard.runtime.as_ref() {
                install_auth_resolver(runtime, &guard);
            }
        }
        Ok(json!({
            "configured": configured,
        }))
    }

    #[napi]
    pub fn auth_token_policy(&self, token: String) -> Value {
        self.state
            .lock()
            .configured_auth_tokens
            .get(&token)
            .map(|policy| json!(policy))
            .unwrap_or(Value::Null)
    }
}

impl WispRust {
    fn require_egress(&self) -> Result<Arc<dyn EgressPlugin>> {
        self.state.lock().egress.clone().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "no egress plugin is configured, so every stream is dialed directly",
            )
        })
    }
}

fn runtime_config_from_value(value: Value) -> Result<RuntimeConfig> {
    let Some(obj) = value.as_object() else {
        return Err(Error::new(Status::InvalidArg, "config must be an object"));
    };

    if let Some(path) = string_field(obj, "tomlPath") {
        let config = RuntimeConfig::from_toml(Path::new(&path)).map_err(js_err)?;
        return apply_config_flags(config, obj);
    }

    if let Some(raw) = string_field(obj, "toml") {
        let source = string_field(obj, "source").unwrap_or_else(|| "wisp-rust-napi".to_owned());
        let parsed = parse_toml(&raw, &source).map_err(js_err)?;
        let options = build_wisp_wt_options(&parsed);
        let config = RuntimeConfig::from_options(options).map_err(js_err)?;
        return apply_config_flags(config, obj);
    }

    let config_value = obj.get("config").cloned().unwrap_or_else(|| value.clone());
    let parsed: WispWtConfigToml = serde_json::from_value(config_value).map_err(js_err)?;
    let options = build_wisp_wt_options(&parsed);
    let config = RuntimeConfig::from_options(options).map_err(js_err)?;
    apply_config_flags(config, obj)
}

/// `logLevel` installs the process-wide tracing subscriber with that filter
/// (the addon installs none otherwise, so without it every log line is
/// dropped). An invalid filter is an error, and a subscriber that already
/// exists is left in charge.
fn apply_config_flags(
    mut config: RuntimeConfig,
    obj: &Map<String, Value>,
) -> Result<RuntimeConfig> {
    if let Some(log_level) = string_field(obj, "logLevel") {
        config = config.with_log_level(log_level);
        config
            .init_tracing()
            .map_err(|message| Error::new(Status::InvalidArg, message))?;
    }
    Ok(config)
}

#[cfg(feature = "proxy-providers")]
fn build_egress(config: &Value) -> Result<Arc<dyn EgressPlugin>> {
    egress::plugin_from_config(config).map_err(|message| Error::new(Status::InvalidArg, message))
}

#[cfg(not(feature = "proxy-providers"))]
fn build_egress(_config: &Value) -> Result<Arc<dyn EgressPlugin>> {
    Err(Error::new(
        Status::GenericFailure,
        "this build has no proxy providers; build it with the proxy-providers feature",
    ))
}

fn apply_configured_auth(runtime: &Runtime, state: &WispRustState) -> Result<()> {
    for (name, options) in &state.configured_limit_profiles {
        if !runtime.register_limit_profile(name.clone(), options.clone()) {
            return Err(Error::new(Status::InvalidArg, "limit profile is invalid"));
        }
    }
    if let Some(base) = state.configured_limit_profiles.get(WISP_BASE_LIMIT_PROFILE) {
        runtime.register_limit_profile(WISP_BASE_LIMIT_PROFILE.to_owned(), base.clone());
    }
    install_auth_resolver(runtime, state);
    Ok(())
}

fn install_auth_resolver(runtime: &Runtime, state: &WispRustState) {
    if state.configured_auth_tokens.is_empty() && state.configured_auth_handler.is_none() {
        runtime.clear_auth_resolver();
        return;
    }
    runtime.set_auth_resolver(Arc::new(NapiAuthResolver {
        tokens: state.configured_auth_tokens.clone(),
        handler: state.configured_auth_handler.clone(),
        gate: Arc::new(AuthHandlerGate::new()),
    }));
}

fn current_base_limits(state: &WispRustState) -> WispServerOptions {
    if let Some(runtime) = state.runtime.as_ref() {
        if let Some(options) = runtime.limit_profile(WISP_BASE_LIMIT_PROFILE) {
            return options;
        }
    }
    state.config.options.base.clone()
}

fn set_config_base_limits(state: &mut WispRustState, options: WispServerOptions) {
    Arc::make_mut(&mut state.config.options).base = options.clone();
    state
        .configured_limit_profiles
        .insert(WISP_BASE_LIMIT_PROFILE.to_owned(), options);
}

/// Serialize options for JS, reporting the no-cap sentinel as `-1`.
fn limits_to_js(options: &WispServerOptions) -> Value {
    let mut value = serde_json::to_value(options).unwrap_or(Value::Null);
    unlimited_to_minus_one(&mut value);
    value
}

/// Options a limits patch cannot change on a running server: they are read
/// once at startup (routing, the limiter backend, ingress trust, protocol
/// version, authentication), so accepting a new value would report success
/// and change nothing. Re-sending the current value is fine, because
/// `getLimits()` output is routinely fed back into `setLimitProfile`.
const STARTUP_ONLY_FIELDS: &[&str] = &[
    "endpoint",
    "rateLimitBackend",
    "redisRateLimitUrl",
    "redisRateLimitKeyPrefix",
    "redisRateLimitHashTag",
    "rateLimitIpv6Prefix",
    "parseRealIp",
    "parseRealIpFrom",
    "wispVersion",
    "auth",
];

fn same_json(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        _ => left == right,
    }
}

/// Fail a patch that names a field `WispServerOptions` does not have, or a
/// startup-only field with a different value.
fn check_patch_keys(current: &Value, patch: &Value) -> Result<()> {
    let Some(fields) = patch.as_object() else {
        return Err(Error::new(
            Status::InvalidArg,
            "limits patch must be an object",
        ));
    };
    let mut unknown = Vec::new();
    let mut unsupported = Vec::new();
    for (key, value) in fields {
        match current.get(key) {
            None => unknown.push(key.as_str()),
            Some(existing)
                if STARTUP_ONLY_FIELDS.contains(&key.as_str()) && !same_json(existing, value) =>
            {
                unsupported.push(key.as_str());
            }
            Some(_) => {}
        }
    }
    if unknown.is_empty() && unsupported.is_empty() {
        return Ok(());
    }
    let mut message = String::new();
    if !unknown.is_empty() {
        message.push_str(&format!("unknown limit option(s): {}", unknown.join(", ")));
    }
    if !unsupported.is_empty() {
        if !message.is_empty() {
            message.push_str("; ");
        }
        message.push_str(&format!(
            "option(s) fixed at startup and not patchable: {}",
            unsupported.join(", ")
        ));
    }
    Err(Error::new(Status::InvalidArg, message))
}

fn patch_wisp_options(base: &WispServerOptions, mut patch: Value) -> Result<WispServerOptions> {
    minus_one_to_unlimited(&mut patch);
    let mut merged = serde_json::to_value(base).map_err(js_err)?;
    check_patch_keys(&merged, &patch)?;
    merge_json(&mut merged, patch);
    let options: WispServerOptions = serde_json::from_value(merged).map_err(js_err)?;
    options.validate().map_err(js_err)?;
    Ok(options)
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, val) in patch {
                if let Some(current) = target.get_mut(&key) {
                    merge_json(current, val);
                } else {
                    target.insert(key, val);
                }
            }
        }
        (target, patch) => {
            *target = patch;
        }
    }
}

fn token_is_valid(token: &str) -> bool {
    !token.trim().is_empty() && !token.contains('/')
}

fn profile_name_is_valid(name: &str) -> bool {
    !name.trim().is_empty() && !name.contains('/')
}

fn status_value(state: &WispRustState) -> Value {
    json!({
        "started": state.runtime.is_some(),
        "webtransportEnabled": state.config.options.enabled,
        "websocketEnabled": state.config.options.websocket.enabled,
        "proxyControlEnabled": state.config.options.proxy_control_enabled,
        "egress": state.egress.as_ref().map(|plugin| plugin.status()),
        "authRequired": state.config.options.base.auth.required,
        "configuredAuthTokens": state.configured_auth_tokens.len(),
        "authHandlerConfigured": state.configured_auth_handler.is_some(),
        "configuredLimitProfiles": state.configured_limit_profiles.len(),
        "connections": {
            "active": state.runtime.as_ref().map(|r| r.active_connections()).unwrap_or(0),
        },
        "boundUrls": bound_urls(&state.config),
    })
}

fn bound_urls(config: &RuntimeConfig) -> Vec<String> {
    let opts = &config.options;
    let mut urls = Vec::new();
    if opts.enabled {
        urls.push(format!(
            "https://{}:{}{}",
            public_host(&opts.host),
            opts.port,
            opts.base.endpoint
        ));
    }
    if !opts.websocket.enabled {
        return urls;
    }
    let scheme = if matches!(
        opts.websocket.ingress_mode,
        wisp_config::IngressMode::TrustedEdge | wisp_config::IngressMode::DirectPlain
    ) {
        "ws"
    } else {
        "wss"
    };
    let endpoint = opts
        .websocket
        .endpoint
        .clone()
        .unwrap_or_else(|| opts.base.endpoint.clone());
    let port = opts.websocket.port;
    let mut host = opts.websocket.host.clone();
    if let Some(bind_addr) = opts.websocket.bind_addr.as_deref() {
        if let Some((parsed_host, parsed_port)) = split_bind_addr(bind_addr) {
            host = parsed_host;
            urls.push(format!(
                "{scheme}://{}:{}{}",
                public_host(&host),
                parsed_port,
                endpoint
            ));
            return urls;
        }
    }
    urls.push(format!(
        "{scheme}://{}:{}{}",
        public_host(&host),
        port,
        endpoint
    ));
    urls
}

fn split_bind_addr(bind_addr: &str) -> Option<(String, u16)> {
    let trimmed = bind_addr.trim();
    let idx = trimmed.rfind(':')?;
    let host = trimmed[..idx]
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = trimmed[idx + 1..].parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

fn public_host(host: &str) -> String {
    match host {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1".to_owned(),
        other => other.to_owned(),
    }
}

fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(|value| value.to_owned())
}

/// Hash a client IP exactly as the listeners do, with the process-wide key from
/// `WISP_IP_HASH_KEY` when it is set. Returns `null` for text that is not an IP
/// address. The link panel uses this so the ban hashes it writes match the
/// hashes the listeners check.
#[napi]
pub fn hash_client_ip(ip: String) -> Result<Option<String>> {
    wisp_iphash::init_process_key().map_err(js_err)?;
    Ok(wisp_iphash::hash_client_ip_keyed(Some(&ip)))
}

fn js_err(error: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, error.to_string())
}

#[cfg(test)]
mod patch_tests {
    use super::*;

    #[test]
    fn patch_applies_known_limits_and_minus_one() {
        let base = WispServerOptions::default();
        let next = patch_wisp_options(
            &base,
            json!({ "maxTcpBytesPerIpPerSecond": -1, "maxConnectionStartsPerMinute": 90000 }),
        )
        .expect("known limits patch");
        assert_eq!(next.max_tcp_bytes_per_ip_per_second, u64::MAX);
        assert_eq!(next.max_connection_starts_per_minute, 90_000);
    }

    #[test]
    fn patch_rejects_unknown_keys() {
        let base = WispServerOptions::default();
        let error = patch_wisp_options(&base, json!({ "maxTcpBytesPerIpPerSeconds": 5 }))
            .expect_err("typo must fail");
        assert!(
            error.reason.contains("maxTcpBytesPerIpPerSeconds"),
            "{error}"
        );
        assert!(patch_wisp_options(&base, json!(7)).is_err());
    }

    #[test]
    fn patch_rejects_changes_to_startup_only_keys_but_not_a_round_trip() {
        let base = WispServerOptions::default();
        let error = patch_wisp_options(&base, json!({ "endpoint": "/other" }))
            .expect_err("endpoint is fixed at startup");
        assert!(error.reason.contains("endpoint"), "{error}");
        assert!(patch_wisp_options(&base, json!({ "rateLimitBackend": "redis" })).is_err());
        assert!(patch_wisp_options(&base, json!({ "auth": { "required": false } })).is_err());

        // What getLimits() reports can be sent straight back.
        let reported = limits_to_js(&base);
        let again = patch_wisp_options(&base, reported).expect("round trip");
        assert_eq!(again, base);
    }

    #[test]
    fn missing_toml_path_is_an_error() {
        assert!(WispRust::from_toml_path("/nonexistent/wispd.toml".to_owned()).is_err());
        let value = json!({ "tomlPath": "/nonexistent/wispd.toml" });
        assert!(runtime_config_from_value(value).is_err());
    }

    #[test]
    fn invalid_log_level_is_an_error() {
        let config = RuntimeConfig::from_options(WispWtServerOptions::default()).unwrap();
        let flags = json!({ "logLevel": "wisp_core=notalevel[" });
        let error = apply_config_flags(config, flags.as_object().unwrap())
            .expect_err("bad filter must not be ignored");
        assert!(error.reason.contains("log level"), "{error}");
    }
}

#[cfg(test)]
mod auth_gate_tests {
    use super::*;

    #[test]
    fn handler_answers_with_unknown_keys_are_refusals() {
        assert!(matches!(
            handler_answer(json!({ "portWhitlist": [443] })),
            HandlerAnswer::Refused
        ));
        assert!(matches!(
            handler_answer(Value::Null),
            HandlerAnswer::Refused
        ));
        assert!(matches!(
            handler_answer(Value::Bool(false)),
            HandlerAnswer::Refused
        ));
        assert!(matches!(
            handler_answer(Value::Bool(true)),
            HandlerAnswer::Policy(_)
        ));
        match handler_answer(json!({ "hostnameBlacklist": ["bad.example"] })) {
            HandlerAnswer::Policy(policy) => {
                assert_eq!(
                    policy.domain_blacklist,
                    Some(vec!["bad.example".to_owned()])
                )
            }
            _ => panic!("documented policy keys must parse"),
        }
    }

    #[test]
    fn refused_tokens_are_remembered_briefly_and_the_cache_is_bounded() {
        let gate = AuthHandlerGate::new();
        let key = gate.key("bad-token");
        assert!(!gate.recently_refused(key));
        gate.remember_refused(key);
        assert!(gate.recently_refused(key));
        assert!(!gate.recently_refused(gate.key("other-token")));
        for n in 0..(AUTH_NEGATIVE_CACHE_MAX as u64 * 2) {
            gate.remember_refused(n);
        }
        assert!(gate.refused.lock().len() <= AUTH_NEGATIVE_CACHE_MAX);
    }

    #[test]
    fn empty_destination_whitelists_are_rejected_in_patches() {
        let base = WispServerOptions::default();
        assert!(patch_wisp_options(&base, json!({ "portWhitelist": [] })).is_err());
        let next = patch_wisp_options(&base, json!({ "udpPortWhitelist": [443] }))
            .expect("udp port list is patchable");
        assert_eq!(next.udp_port_whitelist, Some(vec![443]));
    }
}
