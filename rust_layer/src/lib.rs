use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::fs::{self, File};

use openmls::prelude::*;
use openmls::prelude::tls_codec::{Serialize as TlsSerialize, Deserialize as TlsDeserialize};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Serialize, Deserialize};
use openmls::treesync::LeafNodeParameters;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

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
    #[error("Identity not initialized. Call create_identity() first.")]
    IdentityNotInitialized { msg: String },
}

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
    fn no_identity() -> Self {
        MlsError::IdentityNotInitialized {
            msg: "Call create_identity() before performing group operations.".into(),
        }
    }
    fn lock_poisoned() -> Self {
        MlsError::Generic {
            msg: "Internal lock was poisoned by a previous panic.".into(),
        }
    }
}

// ── Persistence types ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    name: String,
    /// The full SignatureKeyPair serialized via serde
    signer_json: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedGroupMeta {
    group_id: String,
    epoch: u64,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    identity: Option<PersistedIdentity>,
    groups: Vec<PersistedGroupMeta>,
}

// ── Member info returned to Kotlin ─────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub index: u32,
    pub identity: Vec<u8>,
}

// ── Internal state (behind Mutex) ──────────────────────────────────────────

struct MlsClientState {
    groups: HashMap<String, MlsGroup>,
    crypto: OpenMlsRustCrypto,
    /// `None` until `create_identity()` is called.
    signer: Option<SignatureKeyPair>,
    /// `None` until `create_identity()` is called.
    credential: Option<CredentialWithKey>,
    identity_name: Option<String>,
}

// ── Public API ─────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct MlsClient {
    state: Arc<Mutex<MlsClientState>>,
    storage_path: PathBuf,
}

#[uniffi::export]
impl MlsClient {
    // ── Constructor ────────────────────────────────────────────────────

    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Self {
        let crypto = OpenMlsRustCrypto::default();

        let client = Self {
            state: Arc::new(Mutex::new(MlsClientState {
                groups: HashMap::new(),
                crypto,
                signer: None,
                credential: None,
                identity_name: None,
            })),
            storage_path: PathBuf::from(storage_path),
        };

        // Attempt to restore a previously-persisted identity.
        let _ = client.load_state();

        client
    }

    // ── Identity management ────────────────────────────────────────────

    /// Creates (or recreates) this client's cryptographic identity.
    ///
    /// **Must** be called before any group operations.
    /// Returns the identity name on success.
    pub fn create_identity(&self, name: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| MlsError::crypto(format!("Failed to create signature keys: {:?}", e)))?;

        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, name.clone().into_bytes()),
            signature_key: signer.to_public_vec().into(),
        };

        // Store the key pair in the crypto provider so that OpenMLS can find
        // the private key when processing Welcome messages later.
        signer
            .store(state.crypto.storage())
            .map_err(|e| MlsError::crypto(format!("Failed to store signer: {:?}", e)))?;

        state.signer = Some(signer);
        state.credential = Some(credential);
        state.identity_name = Some(name.clone());

        // Persist identity to disk so it survives restarts.
        drop(state);
        let _ = self.persist_state();

        Ok(name)
    }

    /// Generates a fresh key package for the current identity.
    ///
    /// Key packages are single-use; call this each time you need to be
    /// added to a new group.  Returns a hex-encoded key package.
    pub fn generate_key_package(&self) -> Result<String, MlsError> {
        let state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let signer = state.signer.as_ref().ok_or_else(MlsError::no_identity)?;
        let credential = state.credential.as_ref().ok_or_else(MlsError::no_identity)?;

        let kp = KeyPackage::builder()
            .build(CIPHERSUITE, &state.crypto, signer, credential.clone())
            .map_err(|e| MlsError::crypto(format!("Failed to build key package: {:?}", e)))?;

        let bytes = kp
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("Failed to serialize key package: {:?}", e)))?;

        Ok(hex::encode(bytes))
    }

    /// Returns whether an identity has been created.
    pub fn has_identity(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.signer.is_some())
            .unwrap_or(false)
    }

    // ── Group lifecycle ────────────────────────────────────────────────

    /// Creates a new MLS group.  Returns the hex-encoded group ID.
    pub fn create_group(&self, _group_id: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let signer = state.signer.as_ref().ok_or_else(MlsError::no_identity)?;
        let credential = state.credential.as_ref().ok_or_else(MlsError::no_identity)?;

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let group = MlsGroup::new(&state.crypto, signer, &config, credential.clone())
            .map_err(|e| MlsError::generic(format!("Failed to create group: {:?}", e)))?;

        let gid = hex::encode(group.group_id().as_slice());
        state.groups.insert(gid.clone(), group);
        Ok(gid)
    }

    /// Adds a member to an existing group.
    ///
    /// Returns JSON: `{"commit":"<hex>","welcome":"<hex>"}`.
    /// * Send the **commit** to all *existing* members (via `process_commit`).
    /// * Send the **welcome** to the *new* member (via `process_welcome`).
    pub fn add_member(
        &self,
        group_id: String,
        new_member_key_package_hex: String,
    ) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let kp_bytes = hex::decode(&new_member_key_package_hex)
            .map_err(|e| MlsError::serialization(format!("Invalid hex: {:?}", e)))?;

        let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Invalid key package: {:?}", e)))?;

        // Destructure so the borrow-checker can see independent borrows.
        let MlsClientState {
            groups,
            crypto,
            signer,
            ..
        } = &mut *state;

        let signer = signer.as_ref().ok_or_else(MlsError::no_identity)?;

        let key_package = kp_in
            .validate(crypto.crypto(), ProtocolVersion::default())
            .map_err(|e| MlsError::crypto(format!("Key package validation failed: {:?}", e)))?;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let (commit, welcome, _gi) = group
            .add_members(crypto, signer, &[key_package])
            .map_err(|e| MlsError::generic(format!("Failed to add member: {:?}", e)))?;

        group
            .merge_pending_commit(crypto)
            .map_err(|e| MlsError::generic(format!("Failed to merge pending commit: {:?}", e)))?;

        let commit_hex = hex::encode(
            commit
                .tls_serialize_detached()
                .map_err(|e| MlsError::serialization(format!("{:?}", e)))?,
        );
        let welcome_hex = hex::encode(
            welcome
                .tls_serialize_detached()
                .map_err(|e| MlsError::serialization(format!("{:?}", e)))?,
        );

        Ok(format!(
            r#"{{"commit":"{}","welcome":"{}"}}"#,
            commit_hex, welcome_hex
        ))
    }

    /// Removes a member from the group by leaf index.
    ///
    /// Use `get_members()` to discover leaf indices.
    /// Returns JSON: `{"commit":"<hex>"}`.
    /// Broadcast the commit to all remaining members.
    pub fn remove_member(
        &self,
        group_id: String,
        member_index: u32,
    ) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let MlsClientState {
            groups,
            crypto,
            signer,
            ..
        } = &mut *state;
        let signer = signer.as_ref().ok_or_else(MlsError::no_identity)?;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let leaf = LeafNodeIndex::new(member_index);

        let (commit, _welcome, _gi) = group
            .remove_members(crypto, signer, &[leaf])
            .map_err(|e| MlsError::generic(format!("Failed to remove member: {:?}", e)))?;

        group
            .merge_pending_commit(crypto)
            .map_err(|e| MlsError::generic(format!("Failed to merge commit: {:?}", e)))?;

        let commit_hex = hex::encode(
            commit
                .tls_serialize_detached()
                .map_err(|e| MlsError::serialization(format!("{:?}", e)))?,
        );

        Ok(format!(r#"{{"commit":"{}"}}"#, commit_hex))
    }

    /// Performs a self-update, rotating this member's leaf key material.
    ///
    /// This is essential for **post-compromise security**: even if your
    /// keys were leaked, future messages become secure after an update.
    /// Returns JSON: `{"commit":"<hex>"}`.
    /// Broadcast the commit to all other members.
    pub fn self_update(&self, group_id: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let MlsClientState {
            groups,
            crypto,
            signer,
            ..
        } = &mut *state;
        let signer = signer.as_ref().ok_or_else(MlsError::no_identity)?;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let bundle = group
            .self_update(crypto, signer, LeafNodeParameters::default())
            .map_err(|e| MlsError::generic(format!("Failed to self-update: {:?}", e)))?;

        let commit = bundle.into_commit();

        group
            .merge_pending_commit(crypto)
            .map_err(|e| MlsError::generic(format!("Failed to merge commit: {:?}", e)))?;

        let commit_hex = hex::encode(
            commit
                .tls_serialize_detached()
                .map_err(|e| MlsError::serialization(format!("{:?}", e)))?,
        );

        Ok(format!(r#"{{"commit":"{}"}}"#, commit_hex))
    }

    /// Processes a Welcome message to join a group.  Returns the group ID.
    pub fn process_welcome(&self, welcome_hex: String) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let bytes = hex::decode(&welcome_hex)
            .map_err(|e| MlsError::serialization(format!("Invalid hex: {:?}", e)))?;

        let mls_msg = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Invalid MLS message: {:?}", e)))?;

        let welcome = match mls_msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::generic("Expected a Welcome message")),
        };

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let staged = StagedWelcome::new_from_welcome(&state.crypto, &join_config, welcome, None)
            .map_err(|e| MlsError::generic(format!("Failed to stage welcome: {:?}", e)))?;

        let group = staged
            .into_group(&state.crypto)
            .map_err(|e| MlsError::generic(format!("Failed to join group: {:?}", e)))?;

        let gid = hex::encode(group.group_id().as_slice());
        state.groups.insert(gid.clone(), group);
        Ok(gid)
    }

    /// Processes a commit message from another member.
    pub fn process_commit(&self, group_id: String, commit_hex: String) -> Result<(), MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let bytes = hex::decode(&commit_hex)
            .map_err(|e| MlsError::serialization(format!("Invalid hex: {:?}", e)))?;

        let mls_msg = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Invalid MLS message: {:?}", e)))?;

        let protocol_msg = mls_msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::serialization(format!("Not a protocol message: {:?}", e)))?;

        let MlsClientState { groups, crypto, .. } = &mut *state;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let processed = group
            .process_message(crypto, protocol_msg)
            .map_err(|e| MlsError::generic(format!("Failed to process commit: {:?}", e)))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(crypto, *staged)
                    .map_err(|e| MlsError::generic(format!("Failed to merge commit: {:?}", e)))?;
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                // Proposals arriving standalone are stored for later commit.
                let _ = group.store_pending_proposal(crypto.storage(), *proposal);
            }
            _ => {
                return Err(MlsError::generic(
                    "Expected a Commit message but received a different type.",
                ));
            }
        }

        Ok(())
    }

    // ── Messaging ──────────────────────────────────────────────────────

    /// Encrypts a plaintext message for the group.  Returns hex ciphertext.
    pub fn encrypt_message(
        &self,
        group_id: String,
        plaintext: String,
    ) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let MlsClientState {
            groups,
            crypto,
            signer,
            ..
        } = &mut *state;
        let signer = signer.as_ref().ok_or_else(MlsError::no_identity)?;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let msg = group
            .create_message(crypto, signer, plaintext.as_bytes())
            .map_err(|e| MlsError::generic(format!("Encryption failed: {:?}", e)))?;

        let bytes = msg
            .tls_serialize_detached()
            .map_err(|e| MlsError::serialization(format!("{:?}", e)))?;

        Ok(hex::encode(bytes))
    }

    /// Decrypts an application message from the group.  Returns plaintext.
    ///
    /// If the incoming bytes are actually a **Commit**, they are
    /// automatically merged and an error is returned indicating so.
    /// Use `process_commit()` if you want explicit commit handling.
    pub fn decrypt_message(
        &self,
        group_id: String,
        ciphertext_hex: String,
    ) -> Result<String, MlsError> {
        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let bytes = hex::decode(&ciphertext_hex)
            .map_err(|e| MlsError::serialization(format!("Invalid hex: {:?}", e)))?;

        let mls_msg = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .map_err(|e| MlsError::serialization(format!("Invalid MLS message: {:?}", e)))?;

        let protocol_msg = mls_msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::serialization(format!("Not a protocol message: {:?}", e)))?;

        let MlsClientState { groups, crypto, .. } = &mut *state;

        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let processed = group
            .process_message(crypto, protocol_msg)
            .map_err(|e| MlsError::generic(format!("Decryption failed: {:?}", e)))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                String::from_utf8(app.into_bytes())
                    .map_err(|e| MlsError::serialization(format!("Invalid UTF-8: {:?}", e)))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Auto-merge so the group doesn't get stuck.
                group
                    .merge_staged_commit(crypto, *staged)
                    .map_err(|e| MlsError::generic(format!("Failed to merge commit: {:?}", e)))?;
                Err(MlsError::generic(
                    "Received a Commit, not an application message. \
                     The commit has been merged. Group epoch advanced.",
                ))
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                let _ = group.store_pending_proposal(crypto.storage(), *proposal);
                Err(MlsError::generic(
                    "Received a Proposal, not an application message. \
                     The proposal has been stored.",
                ))
            }
            _ => Err(MlsError::generic("Unknown MLS message type received.")),
        }
    }

    // ── Group queries ──────────────────────────────────────────────────

    /// Lists hex-encoded IDs of all groups currently in memory.
    pub fn list_active_groups(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.groups.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns JSON with group metadata: group_id, epoch, member_count.
    pub fn get_group_info(&self, group_id: String) -> Result<String, MlsError> {
        let state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let group = state
            .groups
            .get(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        Ok(format!(
            r#"{{"group_id":"{}","epoch":{},"member_count":{}}}"#,
            group_id,
            group.epoch().as_u64(),
            group.members().count()
        ))
    }

    /// Returns the list of members (leaf index + credential identity bytes).
    pub fn get_members(&self, group_id: String) -> Result<Vec<MemberInfo>, MlsError> {
        let state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        let group = state
            .groups
            .get(&group_id)
            .ok_or_else(|| MlsError::GroupNotFound {
                group_id: group_id.clone(),
            })?;

        let members: Vec<MemberInfo> = group
            .members()
            .map(|m| MemberInfo {
                index: m.index.u32(),
                identity: m.credential.serialized_content().to_vec(),
            })
            .collect();

        Ok(members)
    }

    // ── Persistence ────────────────────────────────────────────────────

    /// Persists ALL state to disk: identity keys, group secrets, ratchet
    /// trees — everything OpenMLS needs to resume after a cold restart.
    ///
    /// Writes two files:
    /// - `state.json`: identity metadata
    /// - `openmls_store.json`: full OpenMLS key store (via MemoryStorage)
    pub fn save_state(&self) -> Result<(), MlsError> {
        self.persist_state()
    }

    /// Loads previously-persisted state from disk, including full group
    /// recovery.  Called automatically by the constructor.
    pub fn load_state(&self) -> Result<(), MlsError> {
        self.restore_state()
    }

    /// Lists group IDs that are currently active (in memory).
    /// After `load_state()`, this includes groups restored from disk.
    pub fn list_saved_groups(&self) -> Result<Vec<String>, MlsError> {
        let path = self.storage_path.join("state.json");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let json = fs::read_to_string(&path)
            .map_err(|e| MlsError::io(format!("Failed to read state file: {:?}", e)))?;

        let persisted: PersistedState = serde_json::from_str(&json)
            .map_err(|e| MlsError::serialization(format!("Corrupt state file: {:?}", e)))?;

        Ok(persisted.groups.into_iter().map(|g| g.group_id).collect())
    }
}

// ── Private helpers (not exported via UniFFI) ──────────────────────────────

impl MlsClient {
    fn persist_state(&self) -> Result<(), MlsError> {
        let state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        fs::create_dir_all(&self.storage_path)
            .map_err(|e| MlsError::io(format!("Failed to create directory: {:?}", e)))?;

        // ── 1. Save identity metadata ──────────────────────────────────
        let identity = match (&state.signer, &state.identity_name) {
            (Some(signer), Some(name)) => {
                let signer_json = serde_json::to_string(signer)
                    .map_err(|e| MlsError::serialization(format!("Failed to serialize signer: {:?}", e)))?;
                Some(PersistedIdentity {
                    name: name.clone(),
                    signer_json,
                })
            }
            _ => None,
        };

        let groups: Vec<PersistedGroupMeta> = state
            .groups
            .iter()
            .map(|(id, g)| PersistedGroupMeta {
                group_id: id.clone(),
                epoch: g.epoch().as_u64(),
            })
            .collect();

        let persisted = PersistedState { identity, groups };

        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| MlsError::serialization(format!("{:?}", e)))?;

        fs::write(self.storage_path.join("state.json"), json)
            .map_err(|e| MlsError::io(format!("Failed to write state: {:?}", e)))?;

        // ── 2. Save full OpenMLS key store (groups, secrets, etc.) ─────
        let store_path = self.storage_path.join("openmls_store.json");
        let store_file = File::create(&store_path)
            .map_err(|e| MlsError::io(format!("Failed to create store file: {:?}", e)))?;
        state
            .crypto
            .storage()
            .save_to_file(&store_file)
            .map_err(|e| MlsError::io(format!("Failed to save key store: {:?}", e)))?;

        Ok(())
    }

    fn restore_state(&self) -> Result<(), MlsError> {
        let state_path = self.storage_path.join("state.json");
        if !state_path.exists() {
            return Ok(());
        }

        let json = fs::read_to_string(&state_path)
            .map_err(|e| MlsError::io(format!("Failed to read state: {:?}", e)))?;

        let persisted: PersistedState = serde_json::from_str(&json)
            .map_err(|e| MlsError::serialization(format!("Corrupt state: {:?}", e)))?;

        let mut state = self.state.lock().map_err(|_| MlsError::lock_poisoned())?;

        // ── 1. Restore the OpenMLS key store from disk ────────────────
        let store_path = self.storage_path.join("openmls_store.json");
        if store_path.exists() {
            let store_file = File::open(&store_path)
                .map_err(|e| MlsError::io(format!("Failed to open store file: {:?}", e)))?;

            // MemoryStorage::load_from_file requires &mut self, but we only
            // have &MemoryStorage via the provider. Since `values` is pub and
            // behind RwLock, we can load manually:
            let reader = std::io::BufReader::new(store_file);
            let ser_store: std::collections::HashMap<String, String> =
                serde_json::from_reader(reader)
                    .map(|wrapper: serde_json::Value| {
                        // The format is {"values":{"base64key":"base64val",...}}
                        wrapper
                            .get("values")
                            .and_then(|v| v.as_object())
                            .map(|obj| {
                                obj.iter()
                                    .map(|(k, v)| {
                                        (k.clone(), v.as_str().unwrap_or("").to_string())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .map_err(|e| MlsError::io(format!("Failed to parse store: {:?}", e)))?;

            // Decode base64 and insert into the storage's RwLock
            use base64::Engine;
            let storage = state.crypto.storage();
            let mut values = storage.values.write().map_err(|_| MlsError::lock_poisoned())?;
            for (key_b64, val_b64) in &ser_store {
                if let (Ok(key), Ok(val)) = (
                    base64::prelude::BASE64_STANDARD.decode(key_b64),
                    base64::prelude::BASE64_STANDARD.decode(val_b64),
                ) {
                    values.insert(key, val);
                }
            }
            drop(values);
        }

        // ── 2. Restore identity ───────────────────────────────────────
        if let Some(id) = persisted.identity {
            let signer: SignatureKeyPair = serde_json::from_str(&id.signer_json)
                .map_err(|e| MlsError::serialization(format!("Failed to deserialize signer: {:?}", e)))?;

            // The key store was already loaded above, but re-register just
            // in case it was created fresh (e.g. store file was deleted).
            let _ = signer.store(state.crypto.storage());

            let credential = CredentialWithKey {
                credential: Credential::new(CredentialType::Basic, id.name.clone().into_bytes()),
                signature_key: signer.to_public_vec().into(),
            };

            state.signer = Some(signer);
            state.credential = Some(credential);
            state.identity_name = Some(id.name);
        }

        // ── 3. Restore groups from the loaded key store ───────────────
        for group_meta in &persisted.groups {
            let gid_bytes = hex::decode(&group_meta.group_id)
                .map_err(|e| MlsError::serialization(format!("Invalid group ID hex: {:?}", e)))?;

            let group_id = GroupId::from_slice(&gid_bytes);

            match MlsGroup::load(state.crypto.storage(), &group_id) {
                Ok(Some(group)) => {
                    state.groups.insert(group_meta.group_id.clone(), group);
                }
                Ok(None) => {
                    // Group data was not found in the store — skip silently.
                    // This can happen if the store was corrupted or truncated.
                }
                Err(e) => {
                    // Log but don't fail — partial restore is better than none.
                    eprintln!(
                        "Warning: Failed to restore group {}: {:?}",
                        group_meta.group_id, e
                    );
                }
            }
        }

        Ok(())
    }
}

uniffi::setup_scaffolding!();