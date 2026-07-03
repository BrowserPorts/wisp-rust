use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use napi::bindgen_prelude::Function;
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Error, Result, Status};
use napi_derive::napi;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;
use wisp_config::{
    build_wisp_wt_options, parse_toml, WispAuthResolveFuture, WispAuthResolver,
    WispAuthTokenPolicy, WispServerOptions, WispWtConfigToml, WispWtServerOptions,
    WISP_BASE_LIMIT_PROFILE,
};
use wisp_core::{Runtime, RuntimeConfig};
use wisp_wisp_server::{
    ProxyControlLimits, ProxyControlRequest, ProxyControllerTemplate, ProxyRouteConfig,
    ProxyRuntimePolicy,
};

#[napi(js_name = "WispRust")]
pub struct WispRust {
    state: Arc<Mutex<WispRustState>>,
}

struct WispRustState {
    config: RuntimeConfig,
    runtime: Option<Runtime>,
    ws_handle: Option<JoinHandle<()>>,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    pending_routes: HashMap<String, ProxyRouteConfig>,
    configured_auth_tokens: HashMap<String, WispAuthTokenPolicy>,
    configured_auth_handler: Option<AuthHandler>,
    configured_limit_profiles: HashMap<String, WispServerOptions>,
    pending_policy: ProxyRuntimePolicy,
    pending_blocked_ips: HashSet<String>,
}

type AuthHandler = Arc<ThreadsafeFunction<String, Value, String, Status, false>>;

struct NapiAuthResolver {
    tokens: HashMap<String, WispAuthTokenPolicy>,
    handler: Option<AuthHandler>,
}

impl WispAuthResolver for NapiAuthResolver {
    fn resolve(&self, token: String) -> WispAuthResolveFuture {
        let static_policy = self.tokens.get(&token).cloned();
        let handler = self.handler.clone();
        Box::pin(async move {
            if static_policy.is_some() {
                return static_policy;
            }
            let handler = handler?;
            let val = handler.call_async_catch(token).await.ok()?;
            if val.is_null() || val == Value::Bool(false) {
                return None;
            }
            serde_json::from_value(val).ok()
        })
    }
}

impl WispRustState {
    fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            runtime: None,
            ws_handle: None,
            proxy_template: None,
            pending_routes: HashMap::new(),
            configured_auth_tokens: HashMap::new(),
            configured_auth_handler: None,
            configured_limit_profiles: HashMap::new(),
            pending_policy: ProxyRuntimePolicy::default(),
            pending_blocked_ips: HashSet::new(),
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
        })
    }

    #[napi(factory)]
    pub fn from_toml_path(path: String) -> Result<Self> {
        let config = RuntimeConfig::from_toml(Path::new(&path)).map_err(js_err)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
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
        })
    }

    #[napi(factory)]
    pub fn from_config(config: Value) -> Result<Self> {
        let config = runtime_config_from_value(config)?;
        Ok(Self {
            state: Arc::new(Mutex::new(WispRustState::new(config))),
        })
    }

    #[napi]
    pub async fn start(&self) -> Result<Value> {
        let mut guard = self.state.lock();
        if guard.runtime.is_some() {
            return Ok(status_value(&guard));
        }

        let runtime = Runtime::start(guard.config.clone()).map_err(js_err)?;
        let template = runtime.proxy_template();
        apply_configured_auth(&runtime, &guard)?;
        if let Some(template) = template.as_ref() {
            apply_pending(template, &guard)?;
        }
        let ws_handle = runtime.bind_ws().map_err(js_err)?;

        guard.proxy_template = template;
        guard.ws_handle = ws_handle;
        guard.runtime = Some(runtime);
        Ok(status_value(&guard))
    }

    #[napi]
    pub async fn stop(&self) -> Result<Value> {
        let (runtime, ws_handle) = {
            let mut guard = self.state.lock();
            let runtime = guard.runtime.take();
            let ws_handle = guard.ws_handle.take();
            guard.proxy_template = None;
            (runtime, ws_handle)
        };

        if let Some(runtime) = runtime {
            runtime.cancel_token().cancel();
        }
        if let Some(handle) = ws_handle {
            handle.abort();
            let _ = handle.await;
        }

        let guard = self.state.lock();
        Ok(status_value(&guard))
    }

    #[napi]
    pub fn status(&self) -> Value {
        status_value(&self.state.lock())
    }

    #[napi]
    pub fn bound_urls(&self) -> Vec<String> {
        bound_urls(&self.state.lock().config)
    }

    #[napi]
    pub async fn set_route(&self, route: Value) -> Result<Value> {
        let route: ProxyRouteConfig = serde_json::from_value(route).map_err(js_err)?;
        let route_id = route.route_id.clone();
        let template = {
            let mut guard = self.state.lock();
            guard.pending_routes.insert(route_id, route.clone());
            guard.proxy_template.clone()
        };

        if let Some(template) = template {
            let snapshot = template.set_route(route).map_err(js_err)?;
            Ok(json!({
                "applied": true,
                "route": snapshot,
            }))
        } else {
            Ok(json!({
                "applied": false,
                "route": route,
            }))
        }
    }

    #[napi]
    pub fn remove_route(&self, route_id: String) -> Value {
        let template = {
            let mut guard = self.state.lock();
            guard.pending_routes.remove(&route_id);
            guard.proxy_template.clone()
        };

        if let Some(template) = template {
            json!({
                "removed": template.remove_route(&route_id),
            })
        } else {
            json!({
                "removed": Value::Null,
            })
        }
    }

    #[napi]
    pub fn list_routes(&self) -> Value {
        let guard = self.state.lock();
        if let Some(template) = guard.proxy_template.as_ref() {
            json!(template.list_routes())
        } else {
            let mut routes: Vec<Value> = guard
                .pending_routes
                .values()
                .map(|route| serde_json::to_value(route).unwrap_or(Value::Null))
                .collect();
            routes.sort_by(|a, b| {
                let left = a.get("routeId").and_then(Value::as_str).unwrap_or_default();
                let right = b.get("routeId").and_then(Value::as_str).unwrap_or_default();
                left.cmp(right)
            });
            Value::Array(routes)
        }
    }

    #[napi]
    pub async fn rotate_route(&self, route_id: String) -> Result<Option<Value>> {
        let template = self.state.lock().proxy_template.clone();
        let Some(template) = template else {
            return Ok(None);
        };
        template
            .rotate_route(&route_id)
            .await
            .map(|snapshot| snapshot.map(|route| json!(route)))
            .map_err(js_err)
    }

    #[napi]
    pub async fn locations(&self, provider: Option<String>) -> Result<Value> {
        let template = self.require_template()?;
        let controller = template.spawn(
            ProxyControlLimits::default(),
            Some(vec!["resi".to_owned(), "mysterium".to_owned()]),
        );
        Ok(controller
            .dispatch(ProxyControlRequest::ProxyLocations { provider })
            .await)
    }

    #[napi]
    pub async fn refresh_locations(&self, provider: Option<String>) -> Result<Value> {
        self.locations(provider).await
    }

    #[napi]
    pub fn provider_status(&self) -> Value {
        let guard = self.state.lock();
        let Some(template) = guard.proxy_template.as_ref() else {
            return json!({
                "type": "proxy_list",
                "providers": [],
            });
        };

        let providers: Vec<Value> = template
            .providers()
            .iter()
            .map(|provider| {
                json!({
                    "id": provider.id(),
                    "name": provider.name(),
                    "aliases": provider.aliases(),
                    "configured": provider.is_configured(),
                })
            })
            .collect();
        json!({
            "type": "proxy_list",
            "providers": providers,
        })
    }

    #[napi]
    pub fn egress_inventory(&self) -> Value {
        let guard = self.state.lock();
        if let Some(template) = guard.proxy_template.as_ref() {
            template.egress_inventory()
        } else {
            let mut blocked: Vec<String> = guard.pending_blocked_ips.iter().cloned().collect();
            blocked.sort();
            json!({
                "routes": guard.pending_routes.values().collect::<Vec<_>>(),
                "blockedEgressIps": blocked,
                "policy": guard.pending_policy,
            })
        }
    }

    #[napi]
    pub fn block_egress_ip(&self, ip: String) -> Value {
        let template = {
            let mut guard = self.state.lock();
            guard.pending_blocked_ips.insert(ip.clone());
            guard.proxy_template.clone()
        };
        if let Some(template) = template {
            json!({
                "blockedEgressIps": template.block_egress_ip(ip),
            })
        } else {
            self.egress_inventory()
        }
    }

    #[napi]
    pub fn release_egress_ip(&self, ip: String) -> Value {
        let template = {
            let mut guard = self.state.lock();
            guard.pending_blocked_ips.remove(&ip);
            guard.proxy_template.clone()
        };
        if let Some(template) = template {
            json!({
                "blockedEgressIps": template.release_egress_ip(&ip),
            })
        } else {
            self.egress_inventory()
        }
    }

    #[napi]
    pub fn get_policy(&self) -> Value {
        let guard = self.state.lock();
        if let Some(template) = guard.proxy_template.as_ref() {
            json!(template.policy())
        } else {
            json!(guard.pending_policy)
        }
    }

    #[napi]
    pub fn set_policy(&self, policy: Value) -> Result<Value> {
        let policy: ProxyRuntimePolicy = serde_json::from_value(policy).map_err(js_err)?;
        let template = {
            let mut guard = self.state.lock();
            guard.pending_policy = policy.clone();
            guard.proxy_template.clone()
        };
        if let Some(template) = template {
            Ok(json!(template.set_policy(policy)))
        } else {
            Ok(json!(policy))
        }
    }

    #[napi]
    pub fn get_limits(&self) -> Value {
        json!(current_base_limits(&self.state.lock()))
    }

    #[napi]
    pub fn patch_limits(&self, patch: Value) -> Result<Value> {
        let mut guard = self.state.lock();
        let next = patch_wisp_options(&current_base_limits(&guard), patch)?;
        set_config_base_limits(&mut guard, next.clone());
        if let Some(runtime) = guard.runtime.as_ref() {
            runtime.register_limit_profile(WISP_BASE_LIMIT_PROFILE.to_owned(), next.clone());
        }
        Ok(json!(next))
    }

    #[napi]
    pub fn set_limit_profile(&self, name: String, limits: Value) -> Result<Value> {
        if !profile_name_is_valid(&name) {
            return Err(Error::new(Status::InvalidArg, "limit profile name is invalid"));
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
            "limits": next,
        }))
    }

    #[napi]
    pub fn patch_limit_profile(&self, name: String, patch: Value) -> Result<Value> {
        self.set_limit_profile(name, patch)
    }

    #[napi]
    pub fn limit_profile(&self, name: String) -> Value {
        let guard = self.state.lock();
        if let Some(runtime) = guard.runtime.as_ref() {
            runtime
                .limit_profile(&name)
                .map(|limits| json!(limits))
                .unwrap_or(Value::Null)
        } else {
            guard
                .configured_limit_profiles
                .get(&name)
                .map(|limits| json!(limits))
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
                        "limits": limits,
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
                        "limits": limits,
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
        handler: Option<Function<'_, String, Value>>,
    ) -> Result<Value> {
        let configured = handler.is_some();
        let auth_handler = handler
            .map(|handler| handler.build_threadsafe_function::<String>().build().map(Arc::new))
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
    fn require_template(&self) -> Result<Arc<ProxyControllerTemplate>> {
        self.state
            .lock()
            .proxy_template
            .clone()
            .ok_or_else(|| Error::new(Status::GenericFailure, "wisp runtime is not started"))
    }
}

fn runtime_config_from_value(value: Value) -> Result<RuntimeConfig> {
    let Some(obj) = value.as_object() else {
        return Err(Error::new(Status::InvalidArg, "config must be an object"));
    };

    if let Some(path) = string_field(obj, "tomlPath") {
        let config = RuntimeConfig::from_toml(Path::new(&path)).map_err(js_err)?;
        return Ok(apply_config_flags(config, obj));
    }

    if let Some(raw) = string_field(obj, "toml") {
        let source = string_field(obj, "source").unwrap_or_else(|| "wisp-rust-napi".to_owned());
        let parsed = parse_toml(&raw, &source).map_err(js_err)?;
        let options = build_wisp_wt_options(&parsed);
        let config = RuntimeConfig::from_options(options).map_err(js_err)?;
        return Ok(apply_config_flags(config, obj));
    }

    let config_value = obj.get("config").cloned().unwrap_or_else(|| value.clone());
    let parsed: WispWtConfigToml = serde_json::from_value(config_value).map_err(js_err)?;
    let options = build_wisp_wt_options(&parsed);
    let config = RuntimeConfig::from_options(options).map_err(js_err)?;
    Ok(apply_config_flags(config, obj))
}

fn apply_config_flags(mut config: RuntimeConfig, obj: &Map<String, Value>) -> RuntimeConfig {
    if let Some(bench_mode) = bool_field(obj, "benchMode") {
        config = config.with_bench_mode(bench_mode);
    }
    if let Some(log_level) = string_field(obj, "logLevel") {
        config = config.with_log_level(log_level);
    }
    config
}

fn apply_pending(template: &ProxyControllerTemplate, state: &WispRustState) -> Result<()> {
    template.set_policy(state.pending_policy.clone());
    for route in state.pending_routes.values() {
        template.set_route(route.clone()).map_err(js_err)?;
    }
    for ip in &state.pending_blocked_ips {
        template.block_egress_ip(ip.clone());
    }
    Ok(())
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

fn patch_wisp_options(base: &WispServerOptions, patch: Value) -> Result<WispServerOptions> {
    let mut merged = serde_json::to_value(base).map_err(js_err)?;
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
        "websocketEnabled": state.config.options.websocket.enabled,
        "proxyControlEnabled": state.config.options.proxy_control_enabled,
        "providersConfigured": state.proxy_template.as_ref().map(|t| t.providers().len()).unwrap_or(0),
        "authRequired": state.config.options.base.auth.required,
        "configuredAuthTokens": state.configured_auth_tokens.len(),
        "authHandlerConfigured": state.configured_auth_handler.is_some(),
        "configuredLimitProfiles": state.configured_limit_profiles.len(),
        "boundUrls": bound_urls(&state.config),
    })
}

fn bound_urls(config: &RuntimeConfig) -> Vec<String> {
    let opts = &config.options;
    if !opts.websocket.enabled {
        return Vec::new();
    }
    let scheme = if opts.websocket.plain { "ws" } else { "wss" };
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
            return vec![format!(
                "{scheme}://{}:{}{}",
                public_host(&host),
                parsed_port,
                endpoint
            )];
        }
    }
    vec![format!(
        "{scheme}://{}:{}{}",
        public_host(&host),
        port,
        endpoint
    )]
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

fn bool_field(obj: &Map<String, Value>, key: &str) -> Option<bool> {
    obj.get(key).and_then(Value::as_bool)
}

fn js_err(error: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, error.to_string())
}
