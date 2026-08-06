#![cfg(feature = "arbitrary")]

use std::fs;
use std::path::Path;

use arbitrary::{Arbitrary, Unstructured};
use fs_ntfs::structured_values::{NtfsAceType, NtfsAcl, NtfsSecurityDescriptor, NtfsSid};
use fs_ntfs::types::NtfsPosition;

/// Regression harnesses for libFuzzer crashes found in `fuzz_ntfs_security`.
///
/// Each test loads a specific crashing input from disk and exercises the same
/// security-descriptor parsing paths as the `fuzz_ntfs_security` fuzz target so
/// you can debug it under `cargo test`.

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    raw: Vec<u8>,
    sid: NtfsSid,
}

fn exercise_acl(acl: &NtfsAcl<'_>) {
    for ace in acl.entries().flatten() {
        let _ = ace.ace_type();
        let _ = ace.ace_type_raw();
        let _ = ace.flags();
        let _ = ace.size();

        match ace.ace_type() {
            NtfsAceType::AccessAllowed
            | NtfsAceType::AccessDenied
            | NtfsAceType::SystemAudit
            | NtfsAceType::SystemAlarm
            | NtfsAceType::SystemMandatoryLabel => {
                let _ = ace.access_mask();
                if let Ok(sid) = ace.sid() {
                    let _ = sid.to_sid_string();
                }
            }
            _ => {}
        }
    }
}

fn run_fuzz_ntfs_security_artifact(file_name: &str) {
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crashes/libfuzzer/fuzz_ntfs_security")
        .join(file_name);

    if !artifact_path.exists() {
        panic!("Artifact not found at {}.", artifact_path.display());
    }

    let data =
        fs::read(&artifact_path).expect("failed to read fuzz artifact for fuzz_ntfs_security");

    let mut u = Unstructured::new(&data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };

    let pos = NtfsPosition::none();

    // Fuzz NtfsSid::from_bytes with raw data.
    if let Ok(sid) = NtfsSid::from_bytes(&input.raw, pos) {
        let _ = sid.revision();
        let _ = sid.authority();
        let _ = sid.sub_authorities();
        let _ = sid.byte_size();
        let _ = sid.well_known_name();
        let _ = sid.to_sid_string();
        let _ = format!("{sid}");
    }

    // Fuzz NtfsSecurityDescriptor::from_bytes with raw data.
    if let Ok(sd) = NtfsSecurityDescriptor::from_bytes(&input.raw, pos) {
        let _ = sd.revision();
        let _ = sd.control();

        if let Some(Ok(owner)) = sd.owner_sid() {
            let _ = owner.to_sid_string();
            let _ = owner.well_known_name();
        }
        if let Some(Ok(group)) = sd.group_sid() {
            let _ = group.to_sid_string();
            let _ = group.well_known_name();
        }
        if let Some(Ok(dacl)) = sd.dacl() {
            let _ = dacl.revision();
            let _ = dacl.ace_count();
            exercise_acl(&dacl);
        }
        if let Some(Ok(sacl)) = sd.sacl() {
            let _ = sacl.revision();
            let _ = sacl.ace_count();
            exercise_acl(&sacl);
        }
        let _ = format!("{sd}");
    }

    // Fuzz NtfsAcl::from_bytes with raw data.
    if let Ok(acl) = NtfsAcl::from_bytes(&input.raw, pos) {
        let _ = acl.revision();
        let _ = acl.ace_count();
        let _ = acl.size();
        exercise_acl(&acl);
    }

    // Exercise the structurally valid Arbitrary SID.
    let _ = input.sid.revision();
    let _ = input.sid.authority();
    let _ = input.sid.sub_authorities();
    let _ = input.sid.byte_size();
    let _ = input.sid.well_known_name();
    let _ = input.sid.to_sid_string();
    let _ = format!("{}", input.sid);
}

#[test]
fn fuzz_ntfs_security_crash_028507f3fb52b479bc9694e857d32b5abfe6e86c() {
    run_fuzz_ntfs_security_artifact("crash-028507f3fb52b479bc9694e857d32b5abfe6e86c");
}

#[test]
fn fuzz_ntfs_security_crash_0b2ce1246f839e929c4e82f970adfe622ce49014() {
    run_fuzz_ntfs_security_artifact("crash-0b2ce1246f839e929c4e82f970adfe622ce49014");
}

#[test]
fn fuzz_ntfs_security_crash_0bf85278f747f037694a7dc6a38417ffbfe26c6f() {
    run_fuzz_ntfs_security_artifact("crash-0bf85278f747f037694a7dc6a38417ffbfe26c6f");
}

#[test]
fn fuzz_ntfs_security_crash_21e54cc78e94697191ffe33892ae93211c87f398() {
    run_fuzz_ntfs_security_artifact("crash-21e54cc78e94697191ffe33892ae93211c87f398");
}

#[test]
fn fuzz_ntfs_security_crash_428742897f5ba8a86a03309ec37956bf52c99332() {
    run_fuzz_ntfs_security_artifact("crash-428742897f5ba8a86a03309ec37956bf52c99332");
}

#[test]
fn fuzz_ntfs_security_crash_44c0811b98b423998ac24ae3ec5be948b36fb2c2() {
    run_fuzz_ntfs_security_artifact("crash-44c0811b98b423998ac24ae3ec5be948b36fb2c2");
}

#[test]
fn fuzz_ntfs_security_crash_473422f48e6e4674a08cc5e86aa207544937e45f() {
    run_fuzz_ntfs_security_artifact("crash-473422f48e6e4674a08cc5e86aa207544937e45f");
}

#[test]
fn fuzz_ntfs_security_crash_5b887b4ff68282655c40f7efb5418f3274a4dbaf() {
    run_fuzz_ntfs_security_artifact("crash-5b887b4ff68282655c40f7efb5418f3274a4dbaf");
}

#[test]
fn fuzz_ntfs_security_crash_5c6067eed9ab15858dadc1183ca040ccf8b35bc2() {
    run_fuzz_ntfs_security_artifact("crash-5c6067eed9ab15858dadc1183ca040ccf8b35bc2");
}

#[test]
fn fuzz_ntfs_security_crash_79efc74b12c01b33f6fbf20226028e5e74dc5528() {
    run_fuzz_ntfs_security_artifact("crash-79efc74b12c01b33f6fbf20226028e5e74dc5528");
}

#[test]
fn fuzz_ntfs_security_crash_7a8b14231b25f12895f45c7c1fc585e6f249da02() {
    run_fuzz_ntfs_security_artifact("crash-7a8b14231b25f12895f45c7c1fc585e6f249da02");
}

#[test]
fn fuzz_ntfs_security_crash_86105df4371d1f16f2717a4b65702438288a6c56() {
    run_fuzz_ntfs_security_artifact("crash-86105df4371d1f16f2717a4b65702438288a6c56");
}

#[test]
fn fuzz_ntfs_security_crash_8fc6117ee174627368b86e1cdcb847c1b14ef060() {
    run_fuzz_ntfs_security_artifact("crash-8fc6117ee174627368b86e1cdcb847c1b14ef060");
}

#[test]
fn fuzz_ntfs_security_crash_9608720d74f0d5be3e4e40a7548f914cd0b20da5() {
    run_fuzz_ntfs_security_artifact("crash-9608720d74f0d5be3e4e40a7548f914cd0b20da5");
}

#[test]
fn fuzz_ntfs_security_crash_98c26e3ee06c9ad8254ded4123619193e5c18a17() {
    run_fuzz_ntfs_security_artifact("crash-98c26e3ee06c9ad8254ded4123619193e5c18a17");
}

#[test]
fn fuzz_ntfs_security_crash_9c44f6cc219a99d3f9f70b922457d15cd3608718() {
    run_fuzz_ntfs_security_artifact("crash-9c44f6cc219a99d3f9f70b922457d15cd3608718");
}

#[test]
fn fuzz_ntfs_security_crash_b11fc7a6eb215e8184a5a7d4bbb43ef6ebfa04a7() {
    run_fuzz_ntfs_security_artifact("crash-b11fc7a6eb215e8184a5a7d4bbb43ef6ebfa04a7");
}

#[test]
fn fuzz_ntfs_security_crash_e3d13ae7fac284ef2e1f7b314b150d166b4f92bb() {
    run_fuzz_ntfs_security_artifact("crash-e3d13ae7fac284ef2e1f7b314b150d166b4f92bb");
}

#[test]
fn fuzz_ntfs_security_crash_eac5b9013a53573e06289a11864134fd4fee52bb() {
    run_fuzz_ntfs_security_artifact("crash-eac5b9013a53573e06289a11864134fd4fee52bb");
}
