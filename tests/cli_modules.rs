/*!
 * Tests for the CLI interactive modules (cli_create, cli_update, cli_common).
 *
 * These tests focus on the public API: builder construction, UpdateSecrets
 * operations, and fully pre-configured flows where no dialoguer prompts
 * are triggered.
 */

#[cfg(feature = "cli")]
mod cli_tests {
    use didwebvh_rs::{
        affinidi_secrets_resolver::secrets::Secret,
        cli_create::{InteractiveCreateConfig, VerificationMethodInput, VerificationRelationship},
        cli_update::{UpdateOperation, UpdateSecrets},
    };
    use serde_json::json;

    // ─────────── Helper ───────────

    fn generate_signing_key() -> Secret {
        let mut key = Secret::generate_ed25519(None, None);
        let pk = key.get_public_keymultibase().unwrap();
        key.id = format!("did:key:{pk}#{pk}");
        key
    }

    // ─────────── VerificationRelationship ───────────

    #[test]
    fn verification_relationship_equality() {
        assert_eq!(
            VerificationRelationship::Authentication,
            VerificationRelationship::Authentication
        );
        assert_ne!(
            VerificationRelationship::Authentication,
            VerificationRelationship::KeyAgreement
        );
    }

    // ─────────── UpdateSecrets tests ───────────

    #[test]
    fn update_secrets_add_and_find_by_hash() {
        let mut secrets = UpdateSecrets::default();
        let key = generate_signing_key();
        let hash = key.get_public_keymultibase_hash().unwrap();

        secrets.add_key(&key).unwrap();

        let found = secrets.find_by_hash(&hash);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().get_public_keymultibase().unwrap(),
            key.get_public_keymultibase().unwrap()
        );
    }

    #[test]
    fn update_secrets_find_by_public_key() {
        let mut secrets = UpdateSecrets::default();
        let key = generate_signing_key();
        let pk = key.get_public_keymultibase().unwrap();

        secrets.add_key(&key).unwrap();

        let found = secrets.find_by_public_key(&pk);
        assert!(found.is_some());
    }

    #[test]
    fn update_secrets_find_missing_returns_none() {
        let secrets = UpdateSecrets::default();
        assert!(secrets.find_by_hash("nonexistent").is_none());
        assert!(secrets.find_by_public_key("nonexistent").is_none());
    }

    #[test]
    fn update_secrets_witness_storage() {
        let mut secrets = UpdateSecrets::default();
        let key = generate_signing_key();
        secrets
            .witnesses
            .insert("did:key:witness1".to_string(), key);
        assert!(secrets.witnesses.contains_key("did:key:witness1"));
    }

    #[test]
    fn update_secrets_multiple_keys() {
        let mut secrets = UpdateSecrets::default();
        let k1 = generate_signing_key();
        let k2 = generate_signing_key();
        let pk1 = k1.get_public_keymultibase().unwrap();
        let pk2 = k2.get_public_keymultibase().unwrap();

        secrets.add_key(&k1).unwrap();
        secrets.add_key(&k2).unwrap();

        assert!(secrets.find_by_public_key(&pk1).is_some());
        assert!(secrets.find_by_public_key(&pk2).is_some());
        assert_eq!(secrets.keys_hash.len(), 2);
        assert_eq!(secrets.key_map.len(), 2);
    }

    // ─────────── UpdateOperation ───────────

    #[test]
    fn update_operation_equality() {
        assert_eq!(UpdateOperation::Modify, UpdateOperation::Modify);
        assert_ne!(UpdateOperation::Modify, UpdateOperation::Revoke);
        assert_ne!(UpdateOperation::Migrate, UpdateOperation::Revoke);
    }

    // ─────────── Integration: fully pre-configured create ───────────

    #[tokio::test]
    async fn create_did_fully_preconfigured() {
        let key = generate_signing_key();
        let vm_key = generate_signing_key();

        let config = InteractiveCreateConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .verification_method(VerificationMethodInput {
                id: Some("{DID}#key-0".to_string()),
                secret: vm_key,
                relationships: vec![
                    VerificationRelationship::Authentication,
                    VerificationRelationship::AssertionMethod,
                ],
            })
            .no_services()
            .no_controller()
            .also_known_as(vec![])
            .portable(true)
            .no_next_keys()
            .no_witnesses()
            .no_watchers()
            .no_ttl()
            .also_known_as_web(false)
            .also_known_as_scid(false)
            .build();

        let result = didwebvh_rs::cli_create::interactive_create_did(config)
            .await
            .expect("fully pre-configured create should succeed");

        // DID should be resolved with a real SCID (not {SCID})
        assert!(result.did().starts_with("did:webvh:"));
        assert!(!result.did().contains("{SCID}"));

        // Log entry should be valid
        assert!(
            !serde_json::to_string(result.log_entry())
                .unwrap()
                .is_empty()
        );

        // Secrets should be populated
        assert_eq!(result.authorization_secrets().len(), 1);
        assert_eq!(result.verification_method_secrets().len(), 1);
        assert!(result.next_key_secrets().is_empty());
        assert!(result.witness_secrets().is_empty());

        // VM secret key should have resolved DID in its ID (no {SCID})
        for id in result.verification_method_secrets().keys() {
            assert!(!id.contains("{SCID}"));
            assert!(!id.contains("{DID}"));
            assert!(id.contains("#key-0"));
        }
    }

    #[tokio::test]
    async fn create_did_with_services_placeholder_rewriting() {
        let key = generate_signing_key();
        let vm_key = generate_signing_key();

        let config = InteractiveCreateConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .verification_method(VerificationMethodInput {
                id: None, // auto-generated
                secret: vm_key,
                relationships: vec![VerificationRelationship::Authentication],
            })
            .service(json!({
                "id": "{DID}#messaging",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/didcomm"
            }))
            .no_controller()
            .also_known_as(vec![])
            .portable(false)
            .no_next_keys()
            .no_witnesses()
            .no_watchers()
            .no_ttl()
            .also_known_as_web(false)
            .also_known_as_scid(false)
            .build();

        let result = didwebvh_rs::cli_create::interactive_create_did(config)
            .await
            .expect("create with services should succeed");

        // Service ID should have been rewritten with the actual DID
        let log_json = serde_json::to_string(result.log_entry()).unwrap();
        assert!(log_json.contains("#messaging"));
        assert!(!log_json.contains("{DID}"));
    }

    #[tokio::test]
    async fn create_did_with_also_known_as_aliases() {
        let key = generate_signing_key();
        let vm_key = generate_signing_key();

        let config = InteractiveCreateConfig::builder()
            .address("https://example.com/")
            .authorization_key(key)
            .verification_method(VerificationMethodInput {
                id: None,
                secret: vm_key,
                relationships: vec![VerificationRelationship::Authentication],
            })
            .no_services()
            .no_controller()
            .also_known_as(vec![])
            .portable(false)
            .no_next_keys()
            .no_witnesses()
            .no_watchers()
            .no_ttl()
            .also_known_as_web(true)
            .also_known_as_scid(true)
            .build();

        let result = didwebvh_rs::cli_create::interactive_create_did(config)
            .await
            .expect("create with aliases should succeed");

        let log_json = serde_json::to_string(result.log_entry()).unwrap();
        // Should have did:web alias
        assert!(log_json.contains("did:web:"));
        // Should have did:scid:vh alias
        assert!(log_json.contains("did:scid:vh:"));
    }

    #[tokio::test]
    async fn create_result_secrets_chain_to_update_secrets() {
        let key = generate_signing_key();
        let pk = key.get_public_keymultibase().unwrap();
        let vm_key = generate_signing_key();

        let config = InteractiveCreateConfig::builder()
            .address("https://example.com/chain-test/")
            .authorization_key(key)
            .verification_method(VerificationMethodInput {
                id: None,
                secret: vm_key,
                relationships: vec![VerificationRelationship::Authentication],
            })
            .no_services()
            .no_controller()
            .also_known_as(vec![])
            .portable(false)
            .no_next_keys()
            .no_witnesses()
            .no_watchers()
            .no_ttl()
            .also_known_as_web(false)
            .also_known_as_scid(false)
            .build();

        let create_result = didwebvh_rs::cli_create::interactive_create_did(config)
            .await
            .expect("create should succeed");

        // Build UpdateSecrets from create result — verifies compatibility
        let mut update_secrets = UpdateSecrets::default();
        for secret in create_result.authorization_secrets() {
            update_secrets.add_key(secret).unwrap();
        }

        // Should be able to find the key by public key
        assert!(update_secrets.find_by_public_key(&pk).is_some());
    }
}
