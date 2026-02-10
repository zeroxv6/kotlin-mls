use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::fs;

use openmls::prelude::*;
use openmls::prelude::tls_codec::{Serialize as TlsSerialize, Deserialize as TlsDeserialize};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Serialize, Deserialize};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("Generic MLS error: {msg}")]
    Generic { msg: String },
    #[error("Group not found: {group_id}")]
    GroupNotFound { group_id: String },
    #[error("Crypto error: {msg}")]
    CryptoError { msg: String },
    #[error("IO error: {msg}")]
    IoError { msg: String },
    #[error("Serialization error: {msg}")]
    SerializationError { msg: String },
}

// Helper to convert errors
impl MlsError {
    fn generic(msg: impl Into<String>) -> Self {
        MlsError::Generic { msg: msg.into() }
    }

    fn crypto(msg: impl Into<String>) -> Self {
        MlsError::CryptoError { msg: msg.into() }
    }

    fn io(msg: impl Into<String>) -> Self {
        MlsError::IoError { msg: msg.into() }
    }

    fn serialization(msg: impl Into<String>) -> Self {
        MlsError::SerializationError { msg: msg.into() }
    }
}

struct MlsClientState {
    groups: HashMap<String, MlsGroup>,
    crypto: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

#[derive(Serialize, Deserialize, Clone)]
struct SerializableCredential {
    credential_type: String,
    identity: Vec<u8>,
    signature_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct GroupState {
    group_id: String,
    epoch: u64,
    // Store the serialized group info for verification
    group_info_data: Vec<u8>,
    // Store credential info to help recreate groups
    credential: SerializableCredential,
}

#[derive(uniffi::Object)]
pub struct MlsClient {
    state: Arc<Mutex<MlsClientState>>,
    storage_path: PathBuf,
}

#[uniffi::export]
impl MlsClient {
    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Self {
        let crypto = OpenMlsRustCrypto::default();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        // Create signature keypair
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("Failed to generate signature keys");

        // Create credential
        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, b"default_user".to_vec()),
            signature_key: signer.to_public_vec().into(),
        };

        let client = Self {
            state: Arc::new(Mutex::new(MlsClientState {
                groups: HashMap::new(),
                crypto,
                signer,
                credential,
            })),
            storage_path: PathBuf::from(storage_path),
        };

        // Auto-load existing state
        let _ = client.load_state();

        client
    }

    /// Creates a new identity and returns the key package as hex
    pub fn create_identity(&self, name: String) -> Result<String, MlsError> {
        let state = self.state.lock().unwrap();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        // Create new signature keypair for this identity
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::crypto(format!("Failed to create signature keys: {:?}", e)))?;

        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, name.into_bytes()),
            signature_key: signer.to_public_vec().into(),
        };

        // Create key package
        let key_package_bundle = KeyPackage::builder()
            .build(
                ciphersuite,
                &state.crypto,
                &signer,
                credential,
            )
            .map_err(|e| MlsError::crypto(format!("Failed to build key package: {:?}", e)))?;

        let bytes = key_package_bundle.key_package()
            .tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("Failed to serialize key package: {:?}", e)))?;

        Ok(hex::encode(bytes))
    }

    /// Lists all active group IDs currently in memory
    pub fn list_active_groups(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state.groups.keys().cloned().collect()
    }

    /// Gets information about a specific group
    pub fn get_group_info(&self, group_id: String) -> Result<String, MlsError> {
        let state = self.state.lock().unwrap();
        
        let group = state.groups.get(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound { group_id: group_id.clone() })?;

        let info = format!(
            r#"{{"group_id":"{}","epoch":{},"member_count":{}}}"#,
            group_id,
            group.epoch().as_u64(),
            group.members().count()
        );

        Ok(info)
    }

    /// Creates a new group and returns the group ID
    pub fn create_group(&self, _group_id: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().unwrap();

        // Configure group to use ratchet tree extension for Welcome messages
        let group_config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let group = MlsGroup::new(
            &state.crypto,
            &state.signer,
            &group_config,
            state.credential.clone(),
        )
        .map_err(|e| MlsError::generic(format!("Failed to create group: {:?}", e)))?;

        // Use the auto-generated group ID from OpenMLS
        let actual_group_id = hex::encode(group.group_id().as_slice());
        state.groups.insert(actual_group_id.clone(), group);

        Ok(actual_group_id)
    }

    /// Adds a member to the group. Returns JSON with "commit" and "welcome" fields (both hex-encoded)
    pub fn add_member(&self, group_id: String, new_member_key_package_hex: String) -> Result<String, MlsError> {
        let state = self.state.lock().unwrap();

        // Decode the key package hex
        let kp_bytes = hex::decode(&new_member_key_package_hex)
            .map_err(|e| MlsError::serialization(format!("Failed to decode key package hex: {:?}", e)))?;

        // For OpenMLS 0.8, KeyPackage deserialization is different
        // We need to use KeyPackageIn first, then convert to KeyPackage
        let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Failed to deserialize key package: {:?}", e)))?;

        // Verify and convert KeyPackageIn to KeyPackage
        let key_package = key_package_in
            .validate(state.crypto.crypto(), ProtocolVersion::default())
            .map_err(|e| MlsError::crypto(format!("Failed to validate key package: {:?}", e)))?;

        // Get raw pointers to work around borrow checker
        let crypto_ptr = &state.crypto as *const OpenMlsRustCrypto;
        let signer_ptr = &state.signer as *const SignatureKeyPair;
        let state_ptr = &*state as *const MlsClientState as *mut MlsClientState;

        let group = unsafe {
            (*state_ptr).groups.get_mut(&group_id)
                .ok_or_else(|| MlsError::GroupNotFound { group_id: group_id.clone() })?
        };

        // Add the member - use add_members_with_ratchet_tree to include ratchet tree in Welcome
        let (commit, welcome, _group_info) = unsafe {
            group.add_members(&*crypto_ptr, &*signer_ptr, &[key_package])
                .map_err(|e| MlsError::generic(format!("Failed to add member: {:?}", e)))?
        };

        // Merge the pending commit
        unsafe {
            group.merge_pending_commit(&*crypto_ptr)
                .map_err(|e| MlsError::generic(format!("Failed to merge pending commit: {:?}", e)))?;
        }

        // Serialize the results
        let commit_bytes = commit.tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("Failed to serialize commit: {:?}", e)))?;

        let welcome_bytes = welcome.tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("Failed to serialize welcome: {:?}", e)))?;

        // Return as JSON with both commit and welcome
        let result = format!(
            r#"{{"commit":"{}","welcome":"{}"}}"#,
            hex::encode(commit_bytes),
            hex::encode(welcome_bytes)
        );

        Ok(result)
    }

    /// Processes a commit message from another member
    pub fn process_commit(&self, group_id: String, commit_hex: String) -> Result<(), MlsError> {
        let state = self.state.lock().unwrap();

        // Decode the commit
        let commit_bytes = hex::decode(&commit_hex)
            .map_err(|e| MlsError::serialization(format!("Failed to decode commit hex: {:?}", e)))?;

        let mls_message = MlsMessageIn::tls_deserialize(&mut commit_bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Failed to deserialize commit: {:?}", e)))?;

        // Convert to protocol message
        let protocol_message = mls_message.try_into_protocol_message()
            .map_err(|e| MlsError::serialization(format!("Failed to convert to protocol message: {:?}", e)))?;

        // Get raw pointers
        let crypto_ptr = &state.crypto as *const OpenMlsRustCrypto;
        let state_ptr = &*state as *const MlsClientState as *mut MlsClientState;

        let group = unsafe {
            (*state_ptr).groups.get_mut(&group_id)
                .ok_or_else(|| MlsError::GroupNotFound { group_id: group_id.clone() })?
        };

        // Process the message
        let processed = unsafe {
            group.process_message(&*crypto_ptr, protocol_message)
                .map_err(|e| MlsError::generic(format!("Failed to process commit: {:?}", e)))?
        };

        // If it's a staged commit, merge it
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) = processed.into_content() {
            unsafe {
                group.merge_staged_commit(&*crypto_ptr, *staged_commit)
                    .map_err(|e| MlsError::generic(format!("Failed to merge staged commit: {:?}", e)))?;
            }
        }

        Ok(())
    }

    /// Processes a Welcome message to join a group. Returns the group ID
    pub fn process_welcome(&self, welcome_hex: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().unwrap();

        // Decode the Welcome message
        let welcome_bytes = hex::decode(&welcome_hex)
            .map_err(|e| MlsError::serialization(format!("Failed to decode welcome hex: {:?}", e)))?;

        let mls_message = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Failed to deserialize welcome: {:?}", e)))?;

        // Extract the Welcome
        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::generic("Expected Welcome message, got different type")),
        };

        // Process the Welcome to join the group
        let mls_group_config = MlsGroupJoinConfig::builder().build();

        let staged_welcome = StagedWelcome::new_from_welcome(
            &state.crypto,
            &mls_group_config,
            welcome,
            None, // No ratchet tree provided
        )
        .map_err(|e| MlsError::generic(format!("Failed to stage welcome: {:?}", e)))?;

        // Convert staged welcome into actual group
        let group = staged_welcome.into_group(&state.crypto)
            .map_err(|e| MlsError::generic(format!("Failed to create group from welcome: {:?}", e)))?;

        // Get the group ID
        let group_id = hex::encode(group.group_id().as_slice());

        // Store the group
        state.groups.insert(group_id.clone(), group);

        Ok(group_id)
    }

    /// Encrypts a message for the group. Returns hex-encoded ciphertext
    pub fn encrypt_message(&self, group_id: String, plaintext: String) -> Result<String, MlsError> {
        let state = self.state.lock().unwrap();

        // Get raw pointers to work around borrow checker
        let crypto_ptr = &state.crypto as *const OpenMlsRustCrypto;
        let signer_ptr = &state.signer as *const SignatureKeyPair;
        let state_ptr = &*state as *const MlsClientState as *mut MlsClientState;

        let group = unsafe {
            (*state_ptr).groups.get_mut(&group_id)
                .ok_or_else(|| MlsError::GroupNotFound { group_id: group_id.clone() })?
        };

        let msg = unsafe {
            group.create_message(&*crypto_ptr, &*signer_ptr, plaintext.as_bytes())
                .map_err(|e| MlsError::generic(format!("Failed to encrypt message: {:?}", e)))?
        };

        let bytes = msg
            .tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("Failed to serialize message: {:?}", e)))?;

        Ok(hex::encode(bytes))
    }

    /// Decrypts a message from the group. Returns plaintext
    pub fn decrypt_message(&self, group_id: String, ciphertext_hex: String) -> Result<String, MlsError> {
        let state = self.state.lock().unwrap();

        let bytes = hex::decode(&ciphertext_hex)
            .map_err(|e| MlsError::serialization(format!("Failed to decode ciphertext hex: {:?}", e)))?;

        let mls_message = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Failed to deserialize message: {:?}", e)))?;

        // Convert MlsMessageIn to ProtocolMessage
        let protocol_message = mls_message.try_into_protocol_message()
            .map_err(|e| MlsError::serialization(format!("Failed to convert to protocol message: {:?}", e)))?;

        // Work around borrow checker with raw pointers
        let crypto_ptr = &state.crypto as *const OpenMlsRustCrypto;
        let state_ptr = &*state as *const MlsClientState as *mut MlsClientState;

        let group = unsafe {
            (*state_ptr).groups.get_mut(&group_id)
                .ok_or_else(|| MlsError::GroupNotFound { group_id: group_id.clone() })?
        };

        let processed = unsafe {
            group.process_message(&*crypto_ptr, protocol_message)
                .map_err(|e| MlsError::generic(format!("Failed to decrypt message: {:?}", e)))?
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                String::from_utf8(app_msg.into_bytes())
                    .map_err(|e| MlsError::serialization(format!("Failed to convert message to UTF-8: {:?}", e)))
            }
            _ => Ok("".to_string()),
        }
    }

    /// Saves all group states to disk
    ///
    /// Saves group metadata and public state. Note that private key material
    /// is not persisted for security reasons. Groups will need to be recreated
    /// or rejoined after app restart.
    pub fn save_state(&self) -> Result<(), MlsError> {
        let state = self.state.lock().unwrap();

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&self.storage_path)
            .map_err(|e| MlsError::io(format!("Failed to create storage directory: {:?}", e)))?;

        // Save each group's metadata
        for (group_id, group) in &state.groups {
            // Export the group's public state (requires crypto provider, signer, and external_pub flag)
            let group_info = group.export_group_info(state.crypto.crypto(), &state.signer, false)
                .map_err(|e| MlsError::generic(format!("Failed to export group info: {:?}", e)))?;
            
            // Serialize the group info
            let group_info_data = group_info.tls_serialize_detached()
                .map_err(|e| MlsError::serialization(format!("Failed to serialize group info: {:?}", e)))?;

            // Get credential information
            let own_leaf = group.own_leaf().unwrap();
            let cred = own_leaf.credential();
            
            // Serialize credential for reference
            let serializable_cred = SerializableCredential {
                credential_type: format!("{:?}", cred.credential_type()),
                identity: cred.serialized_content().to_vec(),
                signature_key: own_leaf.signature_key().as_slice().to_vec(),
            };

            let group_state = GroupState {
                group_id: group_id.clone(),
                epoch: group.epoch().as_u64(),
                group_info_data,
                credential: serializable_cred,
            };

            // Save to file
            let file_path = self.storage_path.join(format!("{}.json", group_id));
            let json = serde_json::to_string_pretty(&group_state)
                .map_err(|e| MlsError::serialization(format!("Failed to serialize group state: {:?}", e)))?;

            fs::write(&file_path, json)
                .map_err(|e| MlsError::io(format!("Failed to write group file {}: {:?}", group_id, e)))?;
        }

        Ok(())
    }

    /// Loads group metadata from disk
    ///
    /// Returns a list of group IDs that were previously saved.
    /// Note: This only loads metadata. The actual MlsGroup objects cannot be
    /// fully restored because they contain private cryptographic state.
    /// 
    /// To restore functionality:
    /// - For groups you created: call create_group() again
    /// - For groups you joined: you'll need a new Welcome message
    pub fn load_state(&self) -> Result<(), MlsError> {
        // Check if storage directory exists
        if !self.storage_path.exists() {
            return Ok(()); // Nothing to load
        }

        let entries = fs::read_dir(&self.storage_path)
            .map_err(|e| MlsError::io(format!("Failed to read storage directory: {:?}", e)))?;

        let mut loaded_groups = Vec::new();
        
        for entry in entries {
            let entry = entry.map_err(|e| MlsError::io(format!("Failed to read directory entry: {:?}", e)))?;
            let path = entry.path();

            // Only process .json files
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            // Read and parse the file
            let json = fs::read_to_string(&path)
                .map_err(|e| MlsError::io(format!("Failed to read group file: {:?}", e)))?;

            let group_state: GroupState = serde_json::from_str(&json)
                .map_err(|e| MlsError::serialization(format!("Failed to deserialize group state: {:?}", e)))?;

            loaded_groups.push(group_state.group_id.clone());
        }

        if !loaded_groups.is_empty() {
            eprintln!("Found {} saved group(s): {:?}", loaded_groups.len(), loaded_groups);
            eprintln!("Note: Groups contain private keys and cannot be fully restored from disk.");
            eprintln!("You'll need to recreate or rejoin these groups in this session.");
        }

        Ok(())
    }

    /// Lists group IDs that have been saved to disk
    pub fn list_saved_groups(&self) -> Result<Vec<String>, MlsError> {
        if !self.storage_path.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.storage_path)
            .map_err(|e| MlsError::io(format!("Failed to read storage directory: {:?}", e)))?;

        let mut group_ids = Vec::new();
        
        for entry in entries {
            let entry = entry.map_err(|e| MlsError::io(format!("Failed to read directory entry: {:?}", e)))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let json = fs::read_to_string(&path)
                .map_err(|e| MlsError::io(format!("Failed to read group file: {:?}", e)))?;

            let group_state: GroupState = serde_json::from_str(&json)
                .map_err(|e| MlsError::serialization(format!("Failed to deserialize group state: {:?}", e)))?;

            group_ids.push(group_state.group_id);
        }

        Ok(group_ids)
    }
}

uniffi::setup_scaffolding!();