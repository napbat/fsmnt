//! Bounded RAID5/6 data reconstruction.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::{BtrfsError, Result};

/// Reconstruct one data-stripe segment.
///
/// Stripes are addressed in logical order: data stripes first, followed by P
/// and, for RAID6, Q. `target_data` is always treated as unavailable.
pub(crate) fn reconstruct_data(
    data_stripes: usize,
    parity_stripes: usize,
    target_data: usize,
    forced_missing: Option<usize>,
    output: &mut [u8],
    mut read_stripe: impl FnMut(usize, &mut [u8]) -> Result<()>,
) -> Result<()> {
    if data_stripes == 0 || !matches!(parity_stripes, 1 | 2) || target_data >= data_stripes {
        return Err(BtrfsError::Raid56RecoveryFailed {
            failures: 0,
            parity_stripes,
        });
    }
    let mut recovery = RecoveryState::new(data_stripes, parity_stripes, output.len())?;
    recovery.collect(target_data, forced_missing, &mut read_stripe);
    recovery.reconstruct(target_data, output)
}

struct RecoveryState {
    data_stripes: usize,
    parity_stripes: usize,
    known_p: Vec<u8>,
    known_q: Option<Vec<u8>>,
    p: Vec<u8>,
    q: Option<Vec<u8>>,
    scratch: Vec<u8>,
    missing_data: Vec<usize>,
    p_available: bool,
    q_available: bool,
}

impl RecoveryState {
    fn new(data_stripes: usize, parity_stripes: usize, length: usize) -> Result<Self> {
        Ok(Self {
            data_stripes,
            parity_stripes,
            known_p: zeroed(length)?,
            known_q: (parity_stripes == 2).then(|| zeroed(length)).transpose()?,
            p: zeroed(length)?,
            q: (parity_stripes == 2).then(|| zeroed(length)).transpose()?,
            scratch: zeroed(length)?,
            missing_data: Vec::with_capacity(parity_stripes),
            p_available: false,
            q_available: false,
        })
    }

    fn collect(
        &mut self,
        target_data: usize,
        forced_missing: Option<usize>,
        read_stripe: &mut impl FnMut(usize, &mut [u8]) -> Result<()>,
    ) {
        for stripe in 0..self.data_stripes + self.parity_stripes {
            if stripe == target_data || forced_missing == Some(stripe) {
                self.record_missing(stripe);
                continue;
            }
            let result = match stripe.cmp(&self.data_stripes) {
                Ordering::Less => self.read_data(stripe, read_stripe),
                Ordering::Equal => self.read_p(stripe, read_stripe),
                Ordering::Greater => self.read_q(stripe, read_stripe),
            };
            if result.is_err() {
                self.record_missing(stripe);
            }
        }
    }

    fn read_data(
        &mut self,
        stripe: usize,
        read_stripe: &mut impl FnMut(usize, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.scratch.fill(0);
        read_stripe(stripe, &mut self.scratch)?;
        xor_assign(&mut self.known_p, &self.scratch);
        if let Some(known_q) = &mut self.known_q {
            multiply_xor_assign(known_q, &self.scratch, gf_pow2(stripe));
        }
        Ok(())
    }

    fn read_p(
        &mut self,
        stripe: usize,
        read_stripe: &mut impl FnMut(usize, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.p.fill(0);
        read_stripe(stripe, &mut self.p)?;
        self.p_available = true;
        Ok(())
    }

    fn read_q(
        &mut self,
        stripe: usize,
        read_stripe: &mut impl FnMut(usize, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        let Some(q) = self.q.as_mut() else {
            return Err(BtrfsError::Raid56RecoveryFailed {
                failures: 1,
                parity_stripes: self.parity_stripes,
            });
        };
        q.fill(0);
        read_stripe(stripe, q)?;
        self.q_available = true;
        Ok(())
    }

    fn record_missing(&mut self, stripe: usize) {
        match stripe.cmp(&self.data_stripes) {
            Ordering::Less => self.missing_data.push(stripe),
            Ordering::Equal => self.p_available = false,
            Ordering::Greater => self.q_available = false,
        }
    }

    fn reconstruct(&mut self, target_data: usize, output: &mut [u8]) -> Result<()> {
        self.missing_data.sort_unstable();
        self.missing_data.dedup();
        let missing_parity = usize::from(!self.p_available)
            + usize::from(self.parity_stripes == 2 && !self.q_available);
        let failures = self.missing_data.len().saturating_add(missing_parity);
        if failures > self.parity_stripes || !self.missing_data.contains(&target_data) {
            return Err(self.error(failures));
        }
        match self.missing_data.as_slice() {
            [missing] => self.recover_one(*missing, failures, output),
            [first, second] if self.p_available && self.q_available => {
                self.recover_two(*first, *second, target_data, failures, output)
            }
            _ => Err(self.error(failures)),
        }
    }

    fn recover_one(&self, missing: usize, failures: usize, output: &mut [u8]) -> Result<()> {
        if self.p_available {
            for ((byte, parity), known) in output.iter_mut().zip(&self.p).zip(&self.known_p) {
                *byte = *parity ^ *known;
            }
            return Ok(());
        }
        let known_q = self
            .known_q
            .as_ref()
            .filter(|_| self.q_available)
            .ok_or_else(|| self.error(failures))?;
        let q = self.q.as_ref().ok_or_else(|| self.error(failures))?;
        let inverse = gf_inverse(gf_pow2(missing));
        for ((byte, parity), known) in output.iter_mut().zip(q).zip(known_q) {
            *byte = gf_multiply(*parity ^ *known, inverse);
        }
        Ok(())
    }

    fn recover_two(
        &self,
        first: usize,
        second: usize,
        target_data: usize,
        failures: usize,
        output: &mut [u8],
    ) -> Result<()> {
        let known_q = self.known_q.as_ref().ok_or_else(|| self.error(failures))?;
        let q = self.q.as_ref().ok_or_else(|| self.error(failures))?;
        let first_coefficient = gf_pow2(first);
        let second_coefficient = gf_pow2(second);
        let denominator_inverse = gf_inverse(first_coefficient ^ second_coefficient);
        for index in 0..output.len() {
            let delta_p = self.p[index] ^ self.known_p[index];
            let delta_q = q[index] ^ known_q[index];
            let first_value = gf_multiply(
                delta_q ^ gf_multiply(second_coefficient, delta_p),
                denominator_inverse,
            );
            let second_value = first_value ^ delta_p;
            output[index] = if target_data == first {
                first_value
            } else {
                second_value
            };
        }
        Ok(())
    }

    const fn error(&self, failures: usize) -> BtrfsError {
        BtrfsError::Raid56RecoveryFailed {
            failures,
            parity_stripes: self.parity_stripes,
        }
    }
}

fn zeroed(length: usize) -> Result<Vec<u8>> {
    let reported_size =
        u64::try_from(length).map_err(|_| BtrfsError::FileTooLarge { size: u64::MAX })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| BtrfsError::FileTooLarge {
            size: reported_size,
        })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn xor_assign(output: &mut [u8], input: &[u8]) {
    for (output, input) in output.iter_mut().zip(input) {
        *output ^= *input;
    }
}

fn multiply_xor_assign(output: &mut [u8], input: &[u8], coefficient: u8) {
    let mut table = [0_u8; 256];
    for (value, product) in (0_u8..=u8::MAX).zip(&mut table) {
        *product = gf_multiply(value, coefficient);
    }
    for (output, input) in output.iter_mut().zip(input) {
        *output ^= table[usize::from(*input)];
    }
}

const fn gf_pow2(exponent: usize) -> u8 {
    let mut value = 1_u8;
    let mut index = 0;
    while index < exponent {
        value = gf_double(value);
        index += 1;
    }
    value
}

const fn gf_inverse(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    let mut result = 1_u8;
    let mut exponent = 254_u16;
    let mut base = value;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_multiply(result, base);
        }
        base = gf_multiply(base, base);
        exponent >>= 1;
    }
    result
}

const fn gf_multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0_u8;
    let mut bit = 0;
    while bit < 8 {
        if right & 1 != 0 {
            product ^= left;
        }
        left = gf_double(left);
        right >>= 1;
        bit += 1;
    }
    product
}

const fn gf_double(value: u8) -> u8 {
    let shifted = value << 1;
    if value & 0x80 == 0 {
        shifted
    } else {
        shifted ^ 0x1d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parity(data: &[Vec<u8>], parity_stripes: usize) -> Vec<Vec<u8>> {
        let mut p = vec![0_u8; data[0].len()];
        let mut q = vec![0_u8; data[0].len()];
        for (index, stripe) in data.iter().enumerate() {
            xor_assign(&mut p, stripe);
            multiply_xor_assign(&mut q, stripe, gf_pow2(index));
        }
        if parity_stripes == 1 {
            vec![p]
        } else {
            vec![p, q]
        }
    }

    fn recover(
        data: &[Vec<u8>],
        parity_stripes: usize,
        target: usize,
        unavailable: &[usize],
    ) -> Result<Vec<u8>> {
        let mut stripes = data.to_vec();
        stripes.extend(parity(data, parity_stripes));
        let mut output = vec![0_u8; data[0].len()];
        reconstruct_data(
            data.len(),
            parity_stripes,
            target,
            None,
            &mut output,
            |index, destination| {
                if unavailable.contains(&index) {
                    return Err(BtrfsError::MissingDevice {
                        device_id: u64::try_from(index).map_err(|_| BtrfsError::IntegerOverflow)?,
                    });
                }
                destination.copy_from_slice(&stripes[index]);
                Ok(())
            },
        )?;
        Ok(output)
    }

    #[test]
    fn raid5_recovers_each_data_stripe() {
        let data = vec![
            b"stripe-000001".to_vec(),
            b"stripe-000002".to_vec(),
            b"stripe-000003".to_vec(),
        ];
        for target in 0..data.len() {
            assert_eq!(
                recover(&data, 1, target, &[target]).expect("RAID5 recovery"),
                data[target]
            );
        }
    }

    #[test]
    fn raid6_recovers_data_with_any_second_failure() {
        let data = vec![
            b"stripe-000001".to_vec(),
            b"stripe-000002".to_vec(),
            b"stripe-000003".to_vec(),
            b"stripe-000004".to_vec(),
        ];
        let p_index = data.len();
        let q_index = p_index + 1;
        for target in 0..data.len() {
            for second in 0..data.len() + 2 {
                if second == target {
                    continue;
                }
                assert_eq!(
                    recover(&data, 2, target, &[target, second]).expect("RAID6 recovery"),
                    data[target],
                    "target {target}, second failure {second}"
                );
            }
            assert_eq!(
                recover(&data, 2, target, &[target, p_index]).expect("missing P"),
                data[target]
            );
            assert_eq!(
                recover(&data, 2, target, &[target, q_index]).expect("missing Q"),
                data[target]
            );
        }
    }

    #[test]
    fn raid5_rejects_two_failures() {
        let data = vec![b"stripe-000001".to_vec(), b"stripe-000002".to_vec()];
        assert!(matches!(
            recover(&data, 1, 0, &[0, 1]),
            Err(BtrfsError::Raid56RecoveryFailed {
                failures: 2,
                parity_stripes: 1
            })
        ));
    }
}
