//! Cross-platform "seconds since Unix epoch" helper.
//!
//! `std::time::SystemTime::now()` panics at runtime on `wasm32-unknown-unknown`
//! ("time not implemented on this platform") — it compiles fine (nothing in
//! the type system catches this), so the panic only surfaces when the code
//! actually runs in a browser. Every plugin needs a timestamp for
//! `created_at`/`updated_at` fields, so this is shared rather than
//! duplicated per plugin.

/// Current time as seconds since the Unix epoch.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Current time as seconds since the Unix epoch, via `Date.now()`.
/// Every wasm32 build in this crate goes through the `wasm` feature, which
/// always pulls in `js-sys` — see the `wasm` feature definition in
/// Cargo.toml.
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_unix() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}
