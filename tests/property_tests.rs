use didwebvh_rs::Multibase;
use didwebvh_rs::witness::Witnesses;
use proptest::prelude::*;

proptest! {
    /// Any string survives Multibase → JSON → Multibase round-trip.
    #[test]
    fn multibase_serde_roundtrip(s in "\\PC{1,100}") {
        let m = Multibase::new(&s);
        let json = serde_json::to_string(&m).unwrap();
        let m2: Multibase = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(m, m2);
    }

    /// Display output equals the original input string.
    #[test]
    fn multibase_display_matches_input(s in "\\PC{1,100}") {
        let m = Multibase::new(&s);
        prop_assert_eq!(m.to_string(), s);
    }

    /// Random threshold/count combos are validated correctly by WitnessesBuilder.
    #[test]
    fn witnesses_builder_threshold_validation(
        threshold in 0u32..10,
        count in 0usize..10,
    ) {
        let ids: Vec<Multibase> = (0..count).map(|i| Multibase::new(format!("z6Mk{i}"))).collect();
        let result = Witnesses::builder()
            .threshold(threshold)
            .witnesses(ids)
            .build();

        if threshold == 0 || count == 0 || count < threshold as usize {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
        }
    }
}
