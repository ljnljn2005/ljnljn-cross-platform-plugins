//! HMAC（RFC 2104）与 PBKDF2（RFC 8018 §5.2），覆盖 SQLCipher 4 需要的
//! `HMAC-SHA512` / `PBKDF2-HMAC-SHA512`，以及 SQLCipher 3 的 SHA1/SHA256 家族
//! 候选（此处只实现 SHA256，SHA1 不在本版本范围内，见 profile.rs 的限制说明）。
//!
//! 单块 HMAC 用预计算状态：PBKDF2 的 256000 次迭代里每个 block 的
//! ipad/opad 前缀是常量，预先算好就能省掉一半压缩。

use crate::sha512::{DigestKind, Hasher};

/// 预计算 HMAC 密钥状态。
#[derive(Clone, Copy, Debug)]
pub struct HmacKey {
    kind: DigestKind,
    ipad: [u64; 8],
    opad: [u64; 8],
}

impl HmacKey {
    pub fn new(kind: DigestKind, key: &[u8]) -> Self {
        let mut block = vec![0_u8; kind.block_len()];
        if key.len() > kind.block_len() {
            let digest = kind.oneshot(key);
            block[..digest.len()].copy_from_slice(&digest);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = Vec::with_capacity(kind.block_len());
        let mut opad = Vec::with_capacity(kind.block_len());
        for byte in &block {
            ipad.push(byte ^ 0x36);
            opad.push(byte ^ 0x5c);
        }
        let mut ipad_state = Hasher::new(kind);
        ipad_state.update(&ipad);
        let mut opad_state = Hasher::new(kind);
        opad_state.update(&opad);
        Self {
            kind,
            ipad: ipad_state.into_state_words(),
            opad: opad_state.into_state_words(),
        }
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let consumed = self.kind.block_len() as u64;
        let mut inner = Hasher::from_state_words(self.kind, self.ipad, consumed);
        inner.update(data);
        let inner_digest = inner.finish();
        // 外层 HMAC 已吸收 opad 块；随后喂入的是内层摘要。
        let mut outer = Hasher::from_state_words(self.kind, self.opad, consumed);
        outer.update(&inner_digest);
        outer.finish()
    }
}

/// `c` 函数：PRF(password) 在迭代次数上的原位更新（RFC 8018）。
pub fn pbkdf2_chains(prf: &HmacKey, start: &[u8], iterations: u32) -> Vec<u8> {
    let output_len = prf.kind.output_len();
    let mut block = prf.digest(start);
    let mut last = block.clone();
    for _ in 1..iterations {
        last = prf.digest(&last);
        for index in 0..output_len {
            block[index] ^= last[index];
        }
    }
    block
}

/// PBKDF2 的密钥派生，`length` 为期望输出字节数。
pub fn pbkdf2(
    kind: DigestKind,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Vec<u8> {
    let iterations = iterations.max(1);
    let prf = HmacKey::new(kind, password);
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut start = Vec::with_capacity(salt.len() + 4);
        start.extend_from_slice(salt);
        start.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&pbkdf2_chains(&prf, &start, iterations));
        counter += 1;
    }
    out.truncate(length);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// 把多段 hex 常量拼起来（显式 concat：`\` 行续接会吞换行但保留缩进空格）。
    fn expect(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn hmac_rfc4231_sha512_vector() {
        // RFC 4231 测试用例 1: key = 0x0b * 20, data = "Hi There"
        let key = [0x0b_u8; 20];
        let mac = HmacKey::new(DigestKind::Sha512, &key).digest(b"Hi There");
        assert_eq!(
            hex(&mac),
            expect(&[
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ])
        );
        // RFC 4231 测试用例 2: key = "Jefe", data = "what do ya want for nothing?"
        let mac = HmacKey::new(DigestKind::Sha512, b"Jefe").digest(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            expect(&[
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ])
        );
    }

    #[test]
    fn hmac_rfc4231_sha256_vector() {
        let key = [0x0b_u8; 20];
        let mac = HmacKey::new(DigestKind::Sha256, &key).digest(b"Hi There");
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn pbkdf2_sha512_reference_vectors() {
        // RFC 7914 §11 参考向量（独立复算：Python hashlib.pbkdf2_hmac）
        assert_eq!(
            hex(&pbkdf2(DigestKind::Sha512, b"passwd", b"salt", 1, 64)),
            expect(&[
                "c74319d99499fc3e9013acff597c23c5baf0a0bec5634c46b8352b793e324723",
                "d55caa76b2b25c43402dcfdc06cdcf66f95b7d0429420b39520006749c51a04e",
            ])
        );
        assert_eq!(
            hex(&pbkdf2(
                DigestKind::Sha512,
                b"Password",
                b"NaCl",
                80_000,
                64
            )),
            expect(&[
                "e6337d6fbeb645c794d4a9b5b75b7b30dac9ac50376a91df1f4460f6060d5add",
                "b2c1fd1f84409abacc67de7eb4056e6bb06c2d82c3ef4ccd1bded0f675ed97c6",
            ])
        );
    }

    #[test]
    fn pbkdf2_sha256_reference_vector() {
        assert_eq!(
            hex(&pbkdf2(DigestKind::Sha256, b"passwd", b"salt", 1, 64)),
            expect(&[
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ])
        );
    }

    #[test]
    fn pbkdf2_zero_iterations_is_clamped_to_one() {
        assert_eq!(
            pbkdf2(DigestKind::Sha512, b"passwd", b"salt", 0, 64),
            pbkdf2(DigestKind::Sha512, b"passwd", b"salt", 1, 64)
        );
    }

    #[test]
    fn pbkdf2_frozen_regression_vector() {
        // 冻结的回归向量（输入全部为测试常量，不是任何案件取值，也不是任何
        // 历史密钥）：16 字节顺序盐 + 多块输出（length 96 > 64 触发计数器）。
        // 由 RFC 8018 定义的算法唯一确定，并用 Python hashlib.pbkdf2_hmac 独立复算。
        let salt = (0_u8..16).collect::<Vec<_>>();
        assert_eq!(
            hex(&pbkdf2(
                DigestKind::Sha512,
                b"test-only-password",
                &salt,
                2,
                96
            )),
            expect(&[
                "39dc8a4e097f8d48a2cb7772c7392c96e6b2cfdc1847781b40315814961a03a8",
                "d3882c3dbe3b94dcf41adc3131264348c3f6d4e9bd7fa03b064bd80c79ffd6c6",
                "1b347f22e04ea78c46c63fa222c6a63997c838fa9152e6179a26d6034f81e2a6",
            ])
        );
    }
}
