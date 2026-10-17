const PRODUCTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../configs/wispd.production.toml"
);

// The production seed has to load and validate with the destination and
// origin rules this crate enforces, including the UDP port list and the
// origin allowlist.
#[test]
fn production_wispd_toml_parses_and_validates() {
    let raw = std::fs::read_to_string(PRODUCTION).expect("read production config");
    let parsed = wisp_config::parse_toml(&raw, PRODUCTION).expect("production must parse");
    let options = wisp_config::build_wisp_wt_options(&parsed);
    options.validate().expect("production must pass validate()");
    assert_eq!(options.base.udp_port_whitelist, Some(vec![443]));
    let origins = options.base.origin_whitelist.as_deref().unwrap_or_default();
    assert!(!origins.is_empty());
    for origin in origins {
        wisp_config::parse_origin_pattern(origin).expect("origin entry parses");
    }
}
