//! Checks this connector's `declaration.ttl` against Contreforts' own
//! meta-shapes and lints, exactly as ds-identity-hub-rs's
//! `identity-hub-contreforts/tests/declaration_validates.rs` does.

const DECLARATION_TTL: &str = include_str!("../src/declaration.ttl");

#[test]
fn declaration_validates_against_contreforts_meta_shapes() {
    match contreforts_declaration::validate(DECLARATION_TTL) {
        Ok(_declaration) => {}
        Err(violations) => panic!("declaration.ttl failed validation:\n{violations}"),
    }
}
