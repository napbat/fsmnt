pub mod bek;
pub mod password;
pub mod protector;
pub mod recovery;
pub mod stretch;

use secrecy::SecretBox;
use secrecy::SecretString;

/// Workspace alias: `SecretBox<[u8]>` (= `SecretSlice`) from `secrecy` 0.10+.
pub type SecretBytes = SecretBox<[u8]>;

/// User-facing authentication material.
///
/// Secret-bearing variants use `secrecy` wrappers for zeroize-on-drop.
pub enum Credential {
    /// VMK stored unencrypted in metadata (protector type 0x0000).
    ClearKey,
    /// 48-digit grouped recovery password (8 groups of 6 digits, dash-separated).
    RecoveryPassword(SecretString),
    /// User password (SHA-256 stretched).
    UserPassword(SecretString),
    /// Raw BEK file bytes (caller does I/O).
    BekFile(SecretBytes),
}

/// Resolved key material for forensic short-circuit or credential-based unlock.
pub enum UnlockMethod {
    /// Derive keys from a user credential.
    Credential(Credential),
    /// Already-unwrapped VMK (bypasses protector unwrapping).
    Vmk(SecretBytes),
    /// Already-unwrapped FVEK (bypasses all key derivation).
    Fvek(SecretBytes),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_clear_key_variant() {
        let _cred = Credential::ClearKey;
    }

    #[test]
    fn credential_recovery_password_variant() {
        let _cred = Credential::RecoveryPassword(SecretString::from("test"));
    }

    #[test]
    fn unlock_method_credential_variant() {
        let _method = UnlockMethod::Credential(Credential::ClearKey);
    }

    #[test]
    fn unlock_method_fvek_variant() {
        let key = vec![0u8; 32];
        let _method = UnlockMethod::Fvek(SecretBytes::new(Box::from(key.as_slice())));
    }
}
