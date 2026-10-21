//! SHA-512 / SHA-256（FIPS 180-4），只用于 PBKDF2-HMAC 试校验。
//!
//! 为什么自带：本机离线 crate 目录里没有 `hmac` / `pbkdf2` / `sha1`，而
//! `sha2` 会把整个 family 拉进来；这里约 150 行、无第三方依赖、可离线
//! 构建，并且能用 NIST/RFC 已知向量逐条钉死正确性。SHA-512 用于 SQLCipher 4
//! 默认 PRF，SHA-256 只用于识别 SQLCipher 3 与其它候选 PRF 家族。

const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// 摘要家族：SQLCipher 的 PRF / HMAC 候选。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestKind {
    Sha512,
    Sha256,
}

impl DigestKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha512 => "SHA512",
            Self::Sha256 => "SHA256",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Self::Sha512 => 64,
            Self::Sha256 => 32,
        }
    }

    /// HMAC 单块用到的内部块大小（RFC 2104）。
    pub fn block_len(self) -> usize {
        match self {
            Self::Sha512 => 128,
            Self::Sha256 => 64,
        }
    }

    pub fn oneshot(self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(self);
        hasher.update(data);
        hasher.finish()
    }
}

const SHA512_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// 可增量喂入的摘要状态。
pub struct Hasher {
    kind: DigestKind,
    state: Vec<u64>,
    buffer: Vec<u8>,
    total_len: u64,
}

impl Hasher {
    pub fn new(kind: DigestKind) -> Self {
        let state = match kind {
            DigestKind::Sha512 => SHA512_IV.to_vec(),
            DigestKind::Sha256 => SHA256_IV.iter().map(|word| u64::from(*word)).collect(),
        };
        Self {
            kind,
            state,
            buffer: Vec::with_capacity(128),
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if !self.buffer.is_empty() {
            let take = (self.kind.block_len() - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == self.kind.block_len() {
                let block = std::mem::take(&mut self.buffer);
                self.compress(&block);
            }
        }
        let block_len = self.kind.block_len();
        let full = data.len() / block_len * block_len;
        // 先处理完整块，再把余数留到 buffer。
        for block in data[..full].chunks_exact(block_len) {
            self.compress(block);
        }
        self.buffer.extend_from_slice(&data[full..]);
    }

    pub fn finish(mut self) -> Vec<u8> {
        let block_len = self.kind.block_len();
        let bit_len = self.total_len.wrapping_mul(8);
        // SHA-512 / SHA-256 的长度域分别固定为 128 / 64 位（16 / 8 字节）。
        let length_field = match self.kind {
            DigestKind::Sha512 => 16,
            DigestKind::Sha256 => 8,
        };
        let mut tail = std::mem::take(&mut self.buffer);
        tail.push(0x80);
        let target = block_len - length_field;
        while tail.len() % block_len != target {
            tail.push(0);
        }
        if length_field == 16 {
            tail.extend_from_slice(&0_u64.to_be_bytes());
        }
        tail.extend_from_slice(&bit_len.to_be_bytes());
        for block in tail.chunks_exact(block_len) {
            self.compress(block);
        }
        let mut out = Vec::with_capacity(self.kind.output_len());
        match self.kind {
            DigestKind::Sha512 => {
                for word in &self.state {
                    out.extend_from_slice(&word.to_be_bytes());
                }
            }
            DigestKind::Sha256 => {
                for word in &self.state {
                    out.extend_from_slice(&(*word as u32).to_be_bytes());
                }
            }
        }
        out
    }

    /// 取出内部链接变量（用于 HMAC 预计算 ipad/opad 前缀状态）。
    pub fn into_state_words(&self) -> [u64; 8] {
        let mut words = [0_u64; 8];
        words.copy_from_slice(&self.state[..8]);
        words
    }

    /// 用已压缩的链接变量重新开始（吸收前缀块之后的状态）。
    ///
    /// `consumed` 是前缀已经计入的字节数（HMAC 的 ipad/opad 各 1 块），
    /// 它只影响 padding 里的长度域，不影响链接变量。
    pub fn from_state_words(kind: DigestKind, words: [u64; 8], consumed: u64) -> Self {
        Self {
            kind,
            state: words.to_vec(),
            buffer: Vec::with_capacity(128),
            total_len: consumed,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        match self.kind {
            DigestKind::Sha512 => {
                let mut w = [0_u64; 80];
                for (index, chunk) in block.chunks_exact(8).enumerate() {
                    let mut bytes = [0_u8; 8];
                    bytes.copy_from_slice(chunk);
                    w[index] = u64::from_be_bytes(bytes);
                }
                for index in 16..80 {
                    let s0 = w[index - 15].rotate_right(1)
                        ^ w[index - 15].rotate_right(8)
                        ^ (w[index - 15] >> 7);
                    let s1 = w[index - 2].rotate_right(19)
                        ^ w[index - 2].rotate_right(61)
                        ^ (w[index - 2] >> 6);
                    w[index] = w[index - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[index - 7])
                        .wrapping_add(s1);
                }
                let mut h = [0_u64; 8];
                h.copy_from_slice(&self.state[..8]);
                for index in 0..80 {
                    let s1 = h[4].rotate_right(14) ^ h[4].rotate_right(18) ^ h[4].rotate_right(41);
                    let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
                    let temp1 = h[7]
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(K512[index])
                        .wrapping_add(w[index]);
                    let s0 = h[0].rotate_right(28) ^ h[0].rotate_right(34) ^ h[0].rotate_right(39);
                    let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
                    let temp2 = s0.wrapping_add(maj);
                    h[7] = h[6];
                    h[6] = h[5];
                    h[5] = h[4];
                    h[4] = h[3].wrapping_add(temp1);
                    h[3] = h[2];
                    h[2] = h[1];
                    h[1] = h[0];
                    h[0] = temp1.wrapping_add(temp2);
                }
                for index in 0..8 {
                    self.state[index] = self.state[index].wrapping_add(h[index]);
                }
            }
            DigestKind::Sha256 => {
                let mut w = [0_u32; 64];
                for (index, chunk) in block.chunks_exact(4).enumerate() {
                    let mut bytes = [0_u8; 4];
                    bytes.copy_from_slice(chunk);
                    w[index] = u32::from_be_bytes(bytes);
                }
                for index in 16..64 {
                    let s0 = w[index - 15].rotate_right(7)
                        ^ w[index - 15].rotate_right(18)
                        ^ (w[index - 15] >> 3);
                    let s1 = w[index - 2].rotate_right(17)
                        ^ w[index - 2].rotate_right(19)
                        ^ (w[index - 2] >> 10);
                    w[index] = w[index - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[index - 7])
                        .wrapping_add(s1);
                }
                let mut h = [0_u32; 8];
                for index in 0..8 {
                    h[index] = self.state[index] as u32;
                }
                for index in 0..64 {
                    let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
                    let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
                    let temp1 = h[7]
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(K256[index])
                        .wrapping_add(w[index]);
                    let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
                    let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
                    let temp2 = s0.wrapping_add(maj);
                    h[7] = h[6];
                    h[6] = h[5];
                    h[5] = h[4];
                    h[4] = h[3].wrapping_add(temp1);
                    h[3] = h[2];
                    h[2] = h[1];
                    h[1] = h[0];
                    h[0] = temp1.wrapping_add(temp2);
                }
                for index in 0..8 {
                    self.state[index] = self.state[index].wrapping_add(u64::from(h[index]));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha512_matches_nist_vectors() {
        assert_eq!(
            hex(&DigestKind::Sha512.oneshot(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                .replace(char::is_whitespace, "")
        );
        // FIPS 180-4 / NIST CAVS: "abc"
        assert_eq!(
            hex(&DigestKind::Sha512.oneshot(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(char::is_whitespace, "")
        );
        // 896 bit = 112 字节，恰好触发 padding 的跨块分支。
        // 注意：`\` 行续接会吞掉换行但保留下一行缩进空格，因此这里显式拼接。
        let long = [
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        ]
        .concat()
        .into_bytes();
        assert_eq!(long.len(), 112);
        assert_eq!(
            hex(&DigestKind::Sha512.oneshot(&long)),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            hex(&DigestKind::Sha256.oneshot(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&DigestKind::Sha256.oneshot(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(&DigestKind::Sha256.oneshot(long)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn block_boundary_lengths_match_reference() {
        // 参考值由 Python hashlib.sha512 独立计算；覆盖整块、跨块 padding 两种分支。
        for (len, expect) in [
            (111_usize, "68cffa6d0d76f309"),
            (112, "d0865c524d1dddf7"),
            (128, "99b16f17aa0b969a"),
            (200, "cca3c0276046ef9f"),
        ] {
            let data: Vec<u8> = (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect();
            let digest = hex(&DigestKind::Sha512.oneshot(&data));
            assert!(
                digest.starts_with(expect),
                "len={len}: got {digest}, want prefix {expect}"
            );
        }
    }

    #[test]
    fn incremental_updates_equal_one_shot() {
        for kind in [DigestKind::Sha512, DigestKind::Sha256] {
            let data: Vec<u8> = (0..1000_u32).map(|value| (value % 251) as u8).collect();
            let mut hasher = Hasher::new(kind);
            for chunk in data.chunks(37) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finish(), kind.oneshot(&data), "{}", kind.name());
        }
    }
}
