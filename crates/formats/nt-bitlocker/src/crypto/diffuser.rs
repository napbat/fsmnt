/// Elephant diffuser rotation constants (verified against dislocker `diffuser.c`).
const RA: [u32; 4] = [9, 0, 13, 0];
const RB: [u32; 4] = [0, 10, 0, 25];

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn write_u32_le(data: &mut [u8], offset: usize, value: u32) {
    let b = value.to_le_bytes();
    data[offset] = b[0];
    data[offset + 1] = b[1];
    data[offset + 2] = b[2];
    data[offset + 3] = b[3];
}

/// Diffuser A decrypt: forward iteration, addition, 5 cycles.
///
/// References `(i-2)` and `(i-5)` neighbors with position-dependent rotation.
pub fn diffuser_a_decrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    for _ in 0..5 {
        for i in 0..n {
            let a = read_u32_le(data, ((i + n - 2) % n) * 4);
            let b = read_u32_le(data, ((i + n - 5) % n) * 4);
            let cur = read_u32_le(data, i * 4);
            write_u32_le(data, i * 4, cur.wrapping_add(a ^ b.rotate_left(RA[i % 4])));
        }
    }
}

/// Diffuser A encrypt: reverse iteration, subtraction, 5 cycles.
pub fn diffuser_a_encrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    for _ in 0..5 {
        for i in (0..n).rev() {
            let a = read_u32_le(data, ((i + n - 2) % n) * 4);
            let b = read_u32_le(data, ((i + n - 5) % n) * 4);
            let cur = read_u32_le(data, i * 4);
            write_u32_le(data, i * 4, cur.wrapping_sub(a ^ b.rotate_left(RA[i % 4])));
        }
    }
}

/// Diffuser B decrypt: forward iteration, addition, 3 cycles.
///
/// References `(i+2)` and `(i+5)` neighbors with position-dependent rotation.
pub fn diffuser_b_decrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    for _ in 0..3 {
        for i in 0..n {
            let a = read_u32_le(data, ((i + 2) % n) * 4);
            let b = read_u32_le(data, ((i + 5) % n) * 4);
            let cur = read_u32_le(data, i * 4);
            write_u32_le(data, i * 4, cur.wrapping_add(a ^ b.rotate_left(RB[i % 4])));
        }
    }
}

/// Diffuser B encrypt: reverse iteration, subtraction, 3 cycles.
pub fn diffuser_b_encrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    for _ in 0..3 {
        for i in (0..n).rev() {
            let a = read_u32_le(data, ((i + 2) % n) * 4);
            let b = read_u32_le(data, ((i + 5) % n) * 4);
            let cur = read_u32_le(data, i * 4);
            write_u32_le(data, i * 4, cur.wrapping_sub(a ^ b.rotate_left(RB[i % 4])));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffuser_a_round_trip() {
        let mut data = vec![0xABu8; 512];
        let original = data.clone();
        diffuser_a_decrypt(&mut data);
        assert_ne!(data, original);
        diffuser_a_encrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn diffuser_b_round_trip() {
        let mut data = vec![0xCDu8; 512];
        let original = data.clone();
        diffuser_b_decrypt(&mut data);
        assert_ne!(data, original);
        diffuser_b_encrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn full_diffuser_round_trip() {
        // Full decrypt pipeline (without AES-CBC): B decrypt → A decrypt
        // Full encrypt pipeline (without AES-CBC): A encrypt → B encrypt
        let mut data = vec![0xEFu8; 512];
        let original = data.clone();

        // "Decrypt"
        diffuser_b_decrypt(&mut data);
        diffuser_a_decrypt(&mut data);
        assert_ne!(data, original);

        // "Encrypt" (reverse order)
        diffuser_a_encrypt(&mut data);
        diffuser_b_encrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn diffuser_deterministic() {
        let mut d1 = vec![0x42u8; 512];
        let mut d2 = vec![0x42u8; 512];
        diffuser_a_decrypt(&mut d1);
        diffuser_a_decrypt(&mut d2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_input_different_output() {
        let mut d1 = vec![0x42u8; 512];
        let mut d2 = vec![0x43u8; 512];
        diffuser_a_decrypt(&mut d1);
        diffuser_a_decrypt(&mut d2);
        assert_ne!(d1, d2);
    }
}
