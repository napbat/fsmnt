//! fscrypt reporting shared by every adapter whose format supports it.
//!
//! fscrypt is a VFS-level facility, not an ext4 one: ext4, f2fs (Android's
//! newer `/data`), UBIFS and Ceph all store the same policy structures,
//! derive keys the same way and use the same ciphers. So the parts that
//! only read a policy — naming its ciphers and flags, deciding what a
//! missing key should tell the operator, and turning a survey of the tree
//! into the notices a mount prints — live here rather than under any one
//! adapter. What stays with an adapter is the walk itself, because only it
//! knows how to enumerate that filesystem's directories.
//!
//! Policies arrive as [`FscryptPolicy`], read through whichever parser
//! opened the volume; nothing here touches anything deeper than that type's
//! public fields.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fs_ext::{FscryptPolicy, FscryptPolicyKind};

/// How far below the mounted root a key census should look.
///
/// Android's `/data` puts its policies within three levels — `data/<pkg>`,
/// `user_de/0/<pkg>`, `system_ce/0`, `media/0`, `misc_ce/0`, `vendor_ce/0`
/// — and a policy covers everything under the directory carrying it, so
/// descending further finds no key that is not already named.
pub(crate) const CENSUS_MAX_DEPTH: usize = 3;

/// Ceiling on directories a census reads, so a volume with a very wide
/// upper tree cannot turn "say which keys are needed" into a full walk.
pub(crate) const CENSUS_MAX_DIRECTORIES: usize = 2000;

/// How many example paths each key's notice carries before it just counts
/// the rest.
const CENSUS_EXAMPLES: usize = 3;

/// Human-readable summary of a policy: version, ciphers, flags.
///
/// Mode numbers are the on-disk `FSCRYPT_MODE_*` values from
/// `include/uapi/linux/fscrypt.h`; flag bits from the same header are
/// `PAD_*` (`0x03`), `DIRECT_KEY` (`0x04`), `IV_INO_LBLK_64` (`0x08`) and
/// `IV_INO_LBLK_32` (`0x10`). An unrecognised cipher is reported by its
/// number rather than guessed at.
pub(crate) fn describe_policy(policy: &FscryptPolicy) -> String {
    let mut flags = vec![format!("PAD_{}", 4u32 << (policy.flags & 0x03))];
    if policy.flags & 0x04 != 0 {
        flags.push("DIRECT_KEY".to_string());
    }
    if policy.flags & 0x08 != 0 {
        flags.push("IV_INO_LBLK_64".to_string());
    }
    if policy.flags & 0x10 != 0 {
        flags.push("IV_INO_LBLK_32".to_string());
    }
    if policy.log2_data_unit_size != 0 {
        flags.push(format!(
            "{}-byte data units",
            1u32 << policy.log2_data_unit_size
        ));
    }
    format!(
        "{}, {}/{}, {}",
        version(policy),
        mode_name(policy.contents_mode),
        mode_name(policy.filenames_mode),
        flags.join(" | ")
    )
}

/// `"v1"` or `"v2"` for a parsed policy.
fn version(policy: &FscryptPolicy) -> &'static str {
    match policy.kind {
        FscryptPolicyKind::V1 => "v1",
        FscryptPolicyKind::V2 => "v2",
    }
}

/// Cipher name for an on-disk `FSCRYPT_MODE_*` number.
fn mode_name(mode: u8) -> String {
    match mode {
        1 => "AES-256-XTS".to_string(),
        4 => "AES-256-CTS".to_string(),
        5 => "AES-128-CBC".to_string(),
        6 => "AES-128-CTS".to_string(),
        7 => "SM4-XTS".to_string(),
        8 => "SM4-CTS".to_string(),
        9 => "Adiantum".to_string(),
        10 => "AES-256-HCTR2".to_string(),
        other => format!("mode {other}"),
    }
}

/// How a policy names the master key it needs: the word for it, and its
/// hex.
///
/// A v1 policy points at an operator-chosen 8-byte descriptor; a v2 policy
/// at the 16-byte identifier the kernel derives from the key itself.
pub(crate) fn key_reference(policy: &FscryptPolicy) -> (&'static str, String) {
    if let Some(descriptor) = policy.key_descriptor {
        return ("descriptor", hex(&descriptor.0));
    }
    if let Some(identifier) = policy.key_identifier {
        return ("identifier", hex(&identifier.0));
    }
    ("reference", "<none>".to_string())
}

/// What to tell the operator when a read needs a key that is not there.
///
/// `key_ref` is the hex the volume itself stores, so it is exactly what has
/// to be matched against the keys in hand — and for a v1 policy it is also
/// half of the spec that supplies one.
pub(crate) fn missing_key_message(inode: u32, policy_kind: &str, key_ref: &str) -> String {
    let how = if policy_kind.eq_ignore_ascii_case("v1") {
        format!("--fscrypt-key v1:{key_ref}:<KEY>")
    } else {
        "--fscrypt-key <KEY> (a v2 identifier is derived from the key, so it is not typed)"
            .to_string()
    };
    format!(
        "inode {inode} is fscrypt-encrypted and the master key it names is not registered \
         (policy {policy_kind}, key {key_ref}); supply it with {how}"
    )
}

/// Lowercase hex of a descriptor or identifier. Never of key material.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

/// Join a directory path and a child name for display in a census.
pub(crate) fn child_path(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// One distinct policy a census found, and where.
struct Sighting {
    /// `"descriptor"` (v1) or `"identifier"` (v2), for the notice's wording.
    key_label: &'static str,
    /// Whether a registered key covers this policy.
    registered: bool,
    /// The first few directory paths carrying it.
    examples: Vec<String>,
    /// How many directories carried it in total.
    directories: usize,
}

/// The distinct fscrypt policies a walk of the tree ran into.
///
/// An adapter walks its own directories and calls [`Self::record`] for each
/// one carrying a policy; [`Self::into_notices`] then turns the result into
/// the lines a mount prints. Policies are keyed by (key reference,
/// description), so a volume that uses one key under two different cipher
/// or flag combinations says so instead of averaging them.
#[derive(Default)]
pub(crate) struct KeyCensus {
    found: BTreeMap<(String, String), Sighting>,
}

impl KeyCensus {
    /// Note that `path` is covered by `policy`.
    ///
    /// `casefolded` is the directory inode's own casefolding, which is not
    /// part of the policy but changes how names are hashed under it, so it
    /// is worth distinguishing. `registered` is the adapter's answer to
    /// "does one of the keys I hold unlock this?", which only the parser
    /// that owns the keystore can give.
    pub(crate) fn record(
        &mut self,
        policy: &FscryptPolicy,
        casefolded: bool,
        registered: bool,
        path: String,
    ) {
        let mut description = describe_policy(policy);
        if casefolded {
            description.push_str(" | casefold");
        }
        let (key_label, key_ref) = key_reference(policy);
        let sighting = self
            .found
            .entry((key_ref, description))
            .or_insert_with(|| Sighting {
                key_label,
                registered,
                examples: Vec::new(),
                directories: 0,
            });
        sighting.directories += 1;
        if sighting.examples.len() < CENSUS_EXAMPLES {
            sighting.examples.push(path);
        }
    }

    /// Whether the walk found no policy at all.
    pub(crate) fn is_empty(&self) -> bool {
        self.found.is_empty()
    }

    /// The notices this census produces, one per distinct policy, after a
    /// leading line saying how many master keys are registered.
    ///
    /// Sorted by key reference, so the same volume reports the same thing
    /// in the same order every time it is mounted.
    pub(crate) fn into_notices(self, registered_keys: usize) -> Vec<String> {
        let mut notices = vec![if registered_keys == 0 {
            "filesystem uses fscrypt (file-based encryption); no keys registered — encrypted \
             names appear in the kernel's no-key form and encrypted files cannot be read"
                .to_string()
        } else {
            format!(
                "filesystem uses fscrypt (file-based encryption); {registered_keys} master \
                 key(s) registered"
            )
        }];
        for ((key_ref, description), sighting) in self.found {
            let mut line = format!(
                "fscrypt key {} {key_ref}: {description} — {}",
                sighting.key_label,
                if sighting.registered {
                    "registered"
                } else {
                    "NOT registered"
                }
            );
            if let Some((first, rest)) = sighting.examples.split_first() {
                let _ = write!(line, "; e.g. {first}");
                for path in rest {
                    let _ = write!(line, ", {path}");
                }
                let remaining = sighting.directories - sighting.examples.len();
                if remaining > 0 {
                    let _ = write!(line, " (+{remaining} more)");
                }
            }
            notices.push(line);
        }
        notices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_ext::{FscryptKeyDescriptor, FscryptKeyIdentifier};

    fn v2_policy(contents: u8, filenames: u8, flags: u8) -> FscryptPolicy {
        FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: contents,
            filenames_mode: filenames,
            flags,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0x4f; 16])),
            nonce: [0; 16],
        }
    }

    fn v1_policy() -> FscryptPolicy {
        FscryptPolicy {
            kind: FscryptPolicyKind::V1,
            contents_mode: 5,
            filenames_mode: 6,
            flags: 0x00,
            log2_data_unit_size: 0,
            key_descriptor: Some(FscryptKeyDescriptor([0xaa; 8])),
            key_identifier: None,
            nonce: [0; 16],
        }
    }

    #[test]
    fn a_policy_reads_as_version_ciphers_and_flags() {
        assert_eq!(
            describe_policy(&v2_policy(1, 4, 0x02)),
            "v2, AES-256-XTS/AES-256-CTS, PAD_16"
        );
        assert_eq!(
            describe_policy(&v2_policy(1, 4, 0x02 | 0x08)),
            "v2, AES-256-XTS/AES-256-CTS, PAD_16 | IV_INO_LBLK_64"
        );
        assert_eq!(
            describe_policy(&v2_policy(9, 9, 0x02 | 0x04)),
            "v2, Adiantum/Adiantum, PAD_16 | DIRECT_KEY"
        );
        assert_eq!(
            describe_policy(&v1_policy()),
            "v1, AES-128-CBC/AES-128-CTS, PAD_4"
        );
    }

    #[test]
    fn an_unknown_cipher_is_reported_by_its_number_rather_than_guessed_at() {
        assert_eq!(
            describe_policy(&v2_policy(3, 4, 0x03)),
            "v2, mode 3/AES-256-CTS, PAD_32"
        );
    }

    #[test]
    fn sub_block_data_units_are_stated_because_they_change_how_content_decrypts() {
        let mut sub_block = v2_policy(1, 4, 0x02);
        sub_block.log2_data_unit_size = 9;
        assert_eq!(
            describe_policy(&sub_block),
            "v2, AES-256-XTS/AES-256-CTS, PAD_16 | 512-byte data units"
        );
    }

    #[test]
    fn a_policy_names_its_key_the_way_its_version_does() {
        assert_eq!(
            key_reference(&v2_policy(1, 4, 0x02)),
            ("identifier", "4f".repeat(16))
        );
        assert_eq!(key_reference(&v1_policy()), ("descriptor", "aa".repeat(8)));
    }

    #[test]
    fn a_missing_key_says_which_one_and_how_to_pass_it() {
        let v2 = missing_key_message(42, "V2", "4f2a");
        assert!(v2.contains("inode 42"), "{v2}");
        assert!(v2.contains("4f2a"), "{v2}");
        assert!(v2.contains("--fscrypt-key <KEY>"), "{v2}");

        let v1 = missing_key_message(7, "V1", "aabbccddeeff0011");
        assert!(
            v1.contains("--fscrypt-key v1:aabbccddeeff0011:<KEY>"),
            "{v1}"
        );
    }

    #[test]
    fn paths_join_without_doubling_the_root_separator() {
        assert_eq!(child_path("/", "data"), "/data");
        assert_eq!(child_path("/data", "user_de"), "/data/user_de");
    }

    #[test]
    fn a_census_with_no_keys_says_what_that_costs() {
        let mut census = KeyCensus::default();
        census.record(&v2_policy(1, 4, 0x02), false, false, "/data".to_string());
        let notices = census.into_notices(0);
        assert_eq!(notices.len(), 2);
        assert!(
            notices[0].contains("no keys registered"),
            "{:?}",
            notices[0]
        );
        assert_eq!(
            notices[1],
            format!(
                "fscrypt key identifier {}: v2, AES-256-XTS/AES-256-CTS, PAD_16 — NOT registered; \
                 e.g. /data",
                "4f".repeat(16)
            )
        );
    }

    #[test]
    fn a_census_lists_three_examples_and_counts_the_rest() {
        let mut census = KeyCensus::default();
        for index in 0..44 {
            census.record(
                &v2_policy(1, 4, 0x02),
                false,
                true,
                format!("/data/app-{index}"),
            );
        }
        let notices = census.into_notices(1);
        assert!(
            notices[0].contains("1 master key(s) registered"),
            "{notices:?}"
        );
        assert!(
            notices[1]
                .ends_with("— registered; e.g. /data/app-0, /data/app-1, /data/app-2 (+41 more)"),
            "{}",
            notices[1]
        );
    }

    #[test]
    fn one_key_used_under_two_policies_is_reported_twice() {
        let mut census = KeyCensus::default();
        census.record(&v2_policy(1, 4, 0x02), false, true, "/plain".to_string());
        census.record(
            &v2_policy(1, 4, 0x02),
            true,
            true,
            "/casefolded".to_string(),
        );
        let notices = census.into_notices(1);
        assert_eq!(notices.len(), 3, "{notices:?}");
        assert!(notices.iter().any(|line| line.contains("| casefold")));
    }
}
