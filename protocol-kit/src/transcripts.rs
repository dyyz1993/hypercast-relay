//! 签名 transcript 与邮箱派生 —— 从 crates/rendezvous 收拢(移动而非复制,
//! 2026-08-18)。这是四端(Rust/TS/Kotlin/Swift)共享逻辑的 Rust 唯一实现,
//! 由 `fixtures/protocol_fixtures.json` conformance 套件字节级锁定。
//!
//! 语义约定: 大端 u64; host/client 公钥以 SHA-256 摘要入册;
//! challenge/nonce 原样拼接。改动任何布局 = 先改协议文档,
//! 再四端同步, 再 `tools/gen_fixtures.py` 重新生成 fixtures。

use ring::digest;

const TICKET_REQUEST_MAGIC: &[u8; 4] = b"HCT1";
const HOST_REGISTRATION_MAGIC: &[u8; 4] = b"HHR1";
const CLIENT_HANDSHAKE_OFFER_MAGIC: &[u8; 4] = b"HCO1";
const SESSION_HANDSHAKE_MAGIC: &[u8; 4] = b"HCK1";
const P2P_OFFER_MAGIC: &[u8; 4] = b"HPO1";
const P2P_ANSWER_MAGIC: &[u8; 4] = b"HPA1";
const MAILBOX_ID_MAGIC: &[u8] = b"hypercast-rendezvous-mailbox/1";

fn sha256(value: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, value).as_ref().to_vec()
}

/// HCT1 —— 会话请求票据签名 transcript(客户端请求时签, 双方各签一份)。
#[must_use]
pub fn ticket_request_transcript(
    logical_session_id: &[u8; 16],
    expires_at_unix_ms: u64,
    request_nonce: &[u8; 32],
    host_public_key: &[u8],
    client_public_key: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(124);
    transcript.extend_from_slice(TICKET_REQUEST_MAGIC);
    transcript.extend_from_slice(logical_session_id);
    transcript.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    transcript.extend_from_slice(request_nonce);
    transcript.extend_from_slice(&sha256(host_public_key));
    transcript.extend_from_slice(&sha256(client_public_key));
    transcript
}

/// HHR1 —— Host mailbox 注册 transcript(Ed25519 签名对象)。
#[must_use]
pub fn host_registration_transcript(
    mailbox_id: &str,
    expires_at_unix_ms: u64,
    registration_nonce: &[u8; 32],
    host_public_key: &[u8],
) -> Vec<u8> {
    let mailbox_id = decode_hex::<32>(mailbox_id).expect("validated mailbox ID");
    let mut transcript = Vec::with_capacity(108);
    transcript.extend_from_slice(HOST_REGISTRATION_MAGIC);
    transcript.extend_from_slice(&mailbox_id);
    transcript.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    transcript.extend_from_slice(registration_nonce);
    transcript.extend_from_slice(&sha256(host_public_key));
    transcript
}

/// HCO1 —— 客户端握手 offer(临时 ECDH 公钥 + challenge)。
#[must_use]
pub fn client_handshake_offer_transcript(
    logical_session_id: &[u8; 16],
    host_public_key: &[u8],
    client_public_key: &[u8],
    client_ephemeral_public_key: &[u8],
    client_challenge: &[u8; 32],
    request_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(180);
    transcript.extend_from_slice(CLIENT_HANDSHAKE_OFFER_MAGIC);
    transcript.extend_from_slice(logical_session_id);
    transcript.extend_from_slice(&sha256(host_public_key));
    transcript.extend_from_slice(&sha256(client_public_key));
    transcript.extend_from_slice(&sha256(client_ephemeral_public_key));
    transcript.extend_from_slice(client_challenge);
    transcript.extend_from_slice(request_nonce);
    transcript
}

/// HCK1 —— 固定宽 transcript(4 + 16 + 6×32 字节), 会话密钥协商输入。
#[must_use]
pub fn session_handshake_transcript(
    logical_session_id: &[u8; 16],
    host_public_key: &[u8],
    client_public_key: &[u8],
    host_ephemeral_public_key: &[u8],
    client_ephemeral_public_key: &[u8],
    host_challenge: &[u8; 32],
    client_challenge: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(212);
    transcript.extend_from_slice(SESSION_HANDSHAKE_MAGIC);
    transcript.extend_from_slice(logical_session_id);
    for value in [
        host_public_key,
        client_public_key,
        host_ephemeral_public_key,
        client_ephemeral_public_key,
    ] {
        transcript.extend_from_slice(&sha256(value));
    }
    transcript.extend_from_slice(host_challenge);
    transcript.extend_from_slice(client_challenge);
    transcript
}

/// HPO1 —— P2P offer SDP 绑定(防 SDP 篡改)。
#[must_use]
pub fn p2p_offer_transcript(
    logical_session_id: &[u8; 16],
    offer_sdp: &[u8],
    host_public_key: &[u8],
    client_public_key: &[u8],
    request_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(148);
    transcript.extend_from_slice(P2P_OFFER_MAGIC);
    transcript.extend_from_slice(logical_session_id);
    for value in [offer_sdp, host_public_key, client_public_key] {
        transcript.extend_from_slice(&sha256(value));
    }
    transcript.extend_from_slice(request_nonce);
    transcript
}

/// HPA1 —— Host answer SDP 绑定(客户端必须验, 防 MITM)。
#[must_use]
pub fn p2p_answer_transcript(
    logical_session_id: &[u8; 16],
    offer_sdp: &[u8],
    answer_sdp: &[u8],
    host_public_key: &[u8],
    client_public_key: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(148);
    transcript.extend_from_slice(P2P_ANSWER_MAGIC);
    transcript.extend_from_slice(logical_session_id);
    for value in [offer_sdp, answer_sdp, host_public_key, client_public_key] {
        transcript.extend_from_slice(&sha256(value));
    }
    transcript
}

/// 邮箱派生: mailbox = SHA256("hypercast-rendezvous-mailbox/1" || token)。
/// (token 本身 = HMAC-SHA256(secret, "hypercast-rendezvous-auth/1"),
///  派生入口在各端 credentials 模块 —— 同一公式。)
#[must_use]
pub fn mailbox_id_for_token(token: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(MAILBOX_ID_MAGIC.len() + token.len());
    input.extend_from_slice(MAILBOX_ID_MAGIC);
    input.extend_from_slice(token);
    encode_hex(digest::digest(&digest::SHA256, &input).as_ref())
}

// —— hex 工具(kit 自备, 不反依赖 rendezvous) ——

#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 定长 hex 解码(小写, 严格长度)。非法输入返回 None, 供上层映射业务错误。
#[must_use]
pub fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[index] = (hi << 4) | lo;
    }
    Some(out)
}
