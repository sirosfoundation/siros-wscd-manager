#[cfg(feature = "plugin-fido2")]
pub mod preview_sign;
pub mod softkey;

#[cfg(feature = "plugin-r2ps")]
pub mod r2ps;

/// Allocates a plugin key identifier.
///
/// # Why this is random rather than sequential
///
/// Both the FIDO2 and softkey plugins used to mint identifiers from a
/// per-plugin counter (`fido-0`, `sw-1`, …). A counter is a shared
/// allocator, and the key metadata it numbers is synchronised between every
/// device on an account — so two devices enrolling while unsynchronised both
/// start from the same value and mint the *same identifier for different
/// keys*.
///
/// That is not one key lost. It is an id collision: two distinct keys
/// claiming one identifier, of which one silently becomes unaddressable
/// while still appearing present in `listKeys`. The FIDO2 plugin made it
/// worse by exporting `next_id` as part of its state, putting the allocator
/// itself into the synchronised blob, where merging two values means
/// nothing.
///
/// 128 bits of randomness removes the allocator entirely: no coordination,
/// no shared counter to diverge. The R2PS plugin already had this property
/// for free, taking its identifiers from the remote service.
///
/// The `prefix` is retained deliberately. `fido-` and `sw-` keep the two
/// plugins' identifier spaces disjoint, so a consumer keying per `kid`
/// across plugins — `privatedata-spec`'s `org.siros.wscd` namespace — cannot
/// see a collision between them.
pub(crate) fn allocate_kid(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    let mut out = String::with_capacity(prefix.len() + 32);
    out.push_str(prefix);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod kid_tests {
    use super::allocate_kid;

    /// The property the counter did not have: two allocations that never
    /// coordinated must not collide.
    #[test]
    fn allocations_are_unique_without_coordination() {
        let n = 10_000;
        let ids: std::collections::HashSet<String> =
            (0..n).map(|_| allocate_kid("fido-")).collect();
        assert_eq!(ids.len(), n, "allocate_kid produced a duplicate");
    }

    #[test]
    fn the_prefix_keeps_plugin_spaces_disjoint() {
        let fido = allocate_kid("fido-");
        let soft = allocate_kid("sw-");
        assert!(fido.starts_with("fido-"));
        assert!(soft.starts_with("sw-"));
        // 16 random octets, hex encoded.
        assert_eq!(fido.len(), "fido-".len() + 32);
        assert_eq!(soft.len(), "sw-".len() + 32);
    }
}
