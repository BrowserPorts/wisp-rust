const EXAMPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/wispd.example.toml"
);

#[test]
fn example_wispd_toml_parses() {
    let raw = std::fs::read_to_string(EXAMPLE).expect("read example");
    let parsed: wisp_config::WispWtConfigToml =
        toml::from_str(&raw).expect("example must parse against schema");
    let ws = parsed.wisp_websocket.expect("wisp.websocket present");
    let wt = parsed.wisp_wt.expect("wisp_wt present");
    assert_eq!(ws.port, Some(4242));
    assert_eq!(wt.port, Some(4243));
}

// The reference config is what operators copy, so it has to pass the same
// checks the server runs at startup.
#[test]
fn example_wispd_toml_validates() {
    let raw = std::fs::read_to_string(EXAMPLE).expect("read example");
    let parsed = wisp_config::parse_toml(&raw, EXAMPLE).expect("example must parse");
    let options = wisp_config::build_wisp_wt_options(&parsed);
    options.validate().expect("example must pass validate()");
}

#[test]
fn missing_config_file_is_an_error_unless_defaults_are_requested() {
    let path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/does-not-exist/wispd.toml"
    ));
    assert!(wisp_config::load_toml(path).is_err());
    assert!(wisp_config::load_wisp_wt_options(path).is_err());
    assert!(wisp_config::load_toml_or_default(path).is_ok());
}
