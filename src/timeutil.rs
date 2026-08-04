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
/// `js-sys` is only available when the `wasm` feature is enabled (it's an
/// optional dependency), so this is gated on that feature specifically —
/// not just target_arch — to fail at compile time with a clear message
/// (below) rather than a confusing "crate not found" error if someone
/// builds a wasm32 target without the `wasm` feature (e.g.
/// `--target wasm32-unknown-unknown --no-default-features --features
/// plugin-softkey-pure`).
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub(crate) fn now_unix() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
compile_error!(
    "siros-wscd-manager: building for wasm32 requires the \"wasm\" feature \
     (needed for timeutil::now_unix's js_sys::Date::now() — \
     std::time::SystemTime::now() panics at runtime on wasm32)."
);
