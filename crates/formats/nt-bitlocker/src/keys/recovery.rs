use crate::{BitLockerError, Result};

/// Parse a 48-digit `BitLocker` recovery password into 8 decoded `u16` values.
///
/// Format: `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`
///
/// Each 6-digit group must be divisible by 11. The quotient yields a `u16`
/// value. 8 groups produce a 128-bit (16-byte) intermediate key.
///
/// # Errors
///
/// Returns `InvalidCredentialFormat` if the format is invalid.
pub fn parse_recovery_password(password: &str) -> Result<[u16; 8]> {
    let groups: Vec<&str> = password.split('-').collect();
    if groups.len() != 8 {
        return Err(BitLockerError::InvalidCredentialFormat {
            detail: "recovery password must have 8 groups separated by hyphens",
        });
    }

    let mut result = [0u16; 8];
    for (i, group) in groups.iter().enumerate() {
        let value: u32 = group
            .parse()
            .map_err(|_| BitLockerError::InvalidCredentialFormat {
                detail: "recovery password groups must be numeric",
            })?;
        if !value.is_multiple_of(11) {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "recovery password groups must be divisible by 11",
            });
        }
        let decoded = value / 11;
        if decoded > u32::from(u16::MAX) {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "recovery password group value exceeds u16 range after division",
            });
        }
        // decoded is verified <= u16::MAX above
        #[expect(clippy::cast_possible_truncation)]
        {
            result[i] = decoded as u16;
        }
    }
    Ok(result)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_recovery_password_valid() {
        // Each group must be divisible by 11, max 720885 (0xFFFF * 11)
        // 231748 / 11 = 21068
        let pw = "231748-209352-537911-146476-641091-095062-249920-499796";
        let groups = parse_recovery_password(pw).unwrap();
        assert_eq!(groups.len(), 8);
        assert_eq!(groups[0], 21068);
    }

    #[test]
    fn reject_group_not_divisible_by_11() {
        let pw = "123457-789012-345678-901234-567890-123456-789012-345678";
        let err = parse_recovery_password(pw).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_group_exceeds_max() {
        // 999999 / 11 = 90909 which exceeds u16::MAX (65535)
        let pw = "999999-000011-000011-000011-000011-000011-000011-000011";
        let err = parse_recovery_password(pw).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_wrong_group_count() {
        let pw = "123456-789012-345678";
        let err = parse_recovery_password(pw).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_non_numeric() {
        let pw = "abcdef-000011-000011-000011-000011-000011-000011-000011";
        let err = parse_recovery_password(pw).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn all_zeros_valid() {
        // 0 is divisible by 11, quotient is 0
        let pw = "000000-000000-000000-000000-000000-000000-000000-000000";
        let groups = parse_recovery_password(pw).unwrap();
        assert_eq!(groups, [0; 8]);
    }
}
