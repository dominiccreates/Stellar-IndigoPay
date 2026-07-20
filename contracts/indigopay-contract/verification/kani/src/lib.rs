//! Kani verification harnesses for IndigoPay contract
//!
//! These harnesses verify safety invariants of the core contract.
//! Run via: `cargo kani --release` from this directory.

#[cfg(kani)]
mod verification {
    use kani::proof;

    /// Core invariant: the `calculate_badge` function must not panic
    /// for any `total_stroops` value that fits in `i128`.
    #[proof]
    fn calculate_badge_no_panic() {
        let total_stroops: i128 = kani::any();
        // calculate_badge divides by STROOP (10_000_000) and does branch
        // comparisons — all arithmetic is panic-free for any i128 value.
        let _badge = indigopay_contract::calculate_badge(total_stroops);
    }
}
