// Each block gets a unique 12-byte nonce by XOR-ing the archive's random base nonce
// with the block index (little-endian u64 across the first 8 bytes). This avoids
// storing a separate nonce per block while still guaranteeing uniqueness as long as
// the block count stays below 2^64. The index block uses u64::MAX as its number.
pub(crate) fn block_nonce(base: &[u8; 12], block_num: u64) -> [u8; 12] {
    let mut nonce = *base;
    let counter = block_num.to_le_bytes();
    for i in 0..8 {
        nonce[i] ^= counter[i];
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_counter_leaves_nonce_unchanged() {
        let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(block_nonce(&base, 0), base);
    }

    #[test]
    fn counter_one_flips_first_byte_only() {
        let base = [0u8; 12];
        let nonce = block_nonce(&base, 1);
        assert_eq!(nonce[0], 1);
        assert_eq!(&nonce[1..], &[0u8; 11]);
    }

    #[test]
    fn different_counters_produce_different_nonces() {
        let base = [0xAAu8; 12];
        assert_ne!(block_nonce(&base, 1), block_nonce(&base, 2));
        assert_ne!(block_nonce(&base, 0), block_nonce(&base, 1));
    }

    #[test]
    fn high_bytes_of_nonce_unchanged_by_counter() {
        let base = [0u8; 12];
        let nonce = block_nonce(&base, u64::MAX);
        assert_eq!(&nonce[8..], &[0u8; 4]);
    }

    #[test]
    fn index_sentinel_differs_from_block_zero() {
        let base = [0x55u8; 12];
        assert_ne!(block_nonce(&base, u64::MAX), block_nonce(&base, 0));
    }

    #[test]
    fn nonce_is_deterministic() {
        let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(block_nonce(&base, 42), block_nonce(&base, 42));
    }
}
