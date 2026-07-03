#[test]
fn example_wispd_toml_parses() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/wispd.example.toml"
    ))
    .expect("read example");
    let parsed: wisp_config::WispWtConfigToml =
        toml::from_str(&raw).expect("example must parse against schema");
    let ws = parsed.wisp_websocket.expect("wisp.websocket present");
    let wt = parsed.wisp_wt.expect("wisp_wt present");
    assert_eq!(ws.port, Some(4242));
    assert_eq!(wt.port, Some(4243));
}
