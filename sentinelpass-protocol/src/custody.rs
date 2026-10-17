//! Personal custody v1 metadata. No value, password, DEK or bearer handle is a
//! wire field. This module does not grant access or advertise an adapter.
//!
//! Unlike legacy IPC messages, this new contract rejects unknown fields and
//! versions. Rust validates even when callers bypass the bounded JSON decoder.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const SECRET_BYTES: usize = 32;
pub const MAX_METADATA_BYTES: usize = 4096;
pub const MAX_LIVE_LEASES: usize = 8;
pub const LEASE_SECONDS: u64 = 120;
pub const DELIVERY_SECONDS: u64 = 5;
/// Reserved bridge feature; not advertised by any production adapter yet.
pub const FEATURE_CUSTODY_V1: u32 = 1 << 3;

/// The descriptors below drive generated TS and native metadata bindings.
pub struct FieldSpec {
    pub name: &'static str,
    pub rule: &'static str,
}

pub struct TypeSpec {
    pub name: &'static str,
    pub fields: &'static [FieldSpec],
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $wire)] $variant),+
        }
        impl $name {
            pub const VALUES: &'static [&'static str] = &[$($wire),+];
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
    };
}

wire_enum!(Purpose {
    MailRecovery => "mail-recovery",
    StorageRecovery => "storage-recovery",
});
wire_enum!(Assurance {
    Software => "software", OsProtected => "os-protected",
    HardwareBacked => "hardware-backed", Unknown => "unknown",
});
wire_enum!(UserVerification { PerUse => "per-use", Session => "session", None => "none" });
wire_enum!(ScopeEnforcement { App => "app", Os => "os", Hardware => "hardware" });
wire_enum!(CustodyError {
    Unavailable => "unavailable", Unsupported => "unsupported", Locked => "locked",
    InteractionRequired => "interaction_required", Denied => "denied",
    NotFound => "not_found", StaleReference => "stale_reference", Conflict => "conflict",
    Cancelled => "cancelled", Expired => "expired", Capacity => "capacity",
    Invalidated => "invalidated", IntegrityFailed => "integrity_failed",
});

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for CustodyError {}

pub type Result<T> = std::result::Result<T, CustodyError>;

// Derive the wire shape and schema descriptors from ONE field declaration.
// Deserialize into a typed struct (duplicate keys cannot be collapsed by Value),
// then validate. Public field mutation never bypasses validation at a port.
macro_rules! wire_struct {
    ($name:ident { $($field:ident : $ty:ty => ($wire:literal, $rule:literal)),+ $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        pub struct $name { $(#[serde(rename = $wire)] pub $field: $ty),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Wire { $(#[serde(rename = $wire)] $field: $ty),+ }
                let wire = Wire::deserialize(d)?;
                let result = Self { $($field: wire.$field),+ };
                result.validate().map_err(serde::de::Error::custom)?;
                Ok(result)
            }
        }
        impl $name {
            pub const SCHEMA: TypeSpec = TypeSpec {
                name: stringify!($name),
                fields: &[$(FieldSpec {name: $wire, rule: $rule}),+],
            };
            pub fn decode(bytes: &[u8]) -> Result<Self> {
                if bytes.len() > MAX_METADATA_BYTES { return Err(CustodyError::Denied); }
                serde_json::from_slice(bytes).map_err(|_| CustodyError::Denied)
            }
        }
    };
}

wire_struct!(CustodyScope {
    version: u32 => ("version", "version"),
    namespace: String => ("namespace", "id128"),
    issuer: String => ("issuer", "id512"),
    subject: String => ("subject", "id512"),
    mailbox_id: String => ("mailboxId", "id512"),
    purpose: Purpose => ("purpose", "Purpose"),
});

wire_struct!(ObjectRef {
    object_id: String => ("objectId", "id128"),
    revision: String => ("revision", "decimal"),
    key_epoch: String => ("keyEpoch", "decimal"),
    binding_sha256: String => ("bindingSha256", "sha256"),
});

wire_struct!(ProviderCapabilities {
    protocol: u32 => ("protocol", "version"),
    provider_id: String => ("providerId", "id128"),
    assurance: Assurance => ("assurance", "Assurance"),
    user_verification: UserVerification => ("userVerification", "UserVerification"),
    scope_enforcement: ScopeEnforcement => ("scopeEnforcement", "ScopeEnforcement"),
    can_sync: bool => ("canSync", "bool"),
    can_transfer_to_runtime: bool => ("canTransferToRuntime", "bool"),
    can_portable_export: bool => ("canPortableExport", "bool"),
    max_secret_bytes: u32 => ("maxSecretBytes", "secretBytes"),
});

fn identity(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'*')
}

pub fn decimal(s: &str) -> Result<u64> {
    if s.is_empty() || s.len() > 20 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(CustodyError::Denied);
    }
    s.parse().map_err(|_| CustodyError::Denied)
}

impl CustodyScope {
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION
            || !identity(&self.namespace, 128)
            || !identity(&self.issuer, 512)
            || !identity(&self.subject, 512)
            || !identity(&self.mailbox_id, 512)
        {
            return Err(CustodyError::Denied);
        }
        Ok(())
    }
    /// The purpose is part of an object, not a separate session/quota domain.
    pub fn same_owner_application(&self, other: &Self) -> bool {
        self.version == other.version
            && self.namespace == other.namespace
            && self.issuer == other.issuer
            && self.subject == other.subject
            && self.mailbox_id == other.mailbox_id
    }
}

impl ObjectRef {
    pub fn validate(&self) -> Result<()> {
        decimal(&self.revision)?;
        decimal(&self.key_epoch)?;
        if !identity(&self.object_id, 128)
            || self.binding_sha256.len() != 64
            || !self
                .binding_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CustodyError::Denied);
        }
        Ok(())
    }
}

impl ProviderCapabilities {
    pub fn validate(&self) -> Result<()> {
        if self.protocol != PROTOCOL_VERSION
            || !identity(&self.provider_id, 128)
            || self.max_secret_bytes != SECRET_BYTES as u32
        {
            return Err(CustodyError::Unsupported);
        }
        Ok(())
    }
    /// Metadata-only descriptor: it never implies a usable custody transport.
    pub fn unavailable() -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            provider_id: "sentinelpass".into(),
            assurance: Assurance::Unknown,
            user_verification: UserVerification::None,
            scope_enforcement: ScopeEnforcement::App,
            can_sync: false,
            can_transfer_to_runtime: false,
            can_portable_export: false,
            max_secret_bytes: SECRET_BYTES as u32,
        }
    }
    pub fn require_native_transfer(&self, protocol: u32) -> Result<()> {
        self.validate()?;
        if protocol != PROTOCOL_VERSION || !self.can_transfer_to_runtime {
            return Err(CustodyError::Unsupported);
        }
        Ok(())
    }
}

/// Metadata only, generated from the same declarations as serde's structs.
pub const TYPES: &[TypeSpec] = &[
    CustodyScope::SCHEMA,
    ObjectRef::SCHEMA,
    ProviderCapabilities::SCHEMA,
];
pub const ENUMS: &[(&str, &[&str])] = &[
    ("Purpose", Purpose::VALUES),
    ("Assurance", Assurance::VALUES),
    ("UserVerification", UserVerification::VALUES),
    ("ScopeEnforcement", ScopeEnforcement::VALUES),
    ("CustodyError", CustodyError::VALUES),
];
