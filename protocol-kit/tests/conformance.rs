//! kit 自身 conformance —— 直接断言 `fixtures/`(权威语料单一来源)。
//! rendezvous/demo 与各端(经绑定)引用 kit 后, 四端一致性由此锁定。

use hypercast_protocol_kit::{
    client_handshake_offer_transcript, decode_hex, encode_hex, host_registration_transcript,
    mailbox_id_for_token, p2p_answer_transcript, p2p_offer_transcript,
    session_handshake_transcript, ticket_request_transcript,
};

fn unhex(value: &serde_json::Value) -> Vec<u8> {
    let s = value.as_str().expect("hex string in fixture");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
        .collect()
}

fn hex_str(value: &serde_json::Value) -> &str {
    value.as_str().expect("hex string in fixture")
}

#[test]
fn transcripts_and_mailbox_match_shared_fixtures() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/protocol_fixtures.json"
    );
    let root: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("shared fixtures present"))
            .expect("fixtures JSON");
    let inputs = &root["inputs"];
    let transcripts = &root["transcripts"];

    let session_id = decode_hex::<16>(hex_str(&inputs["session_id"])).unwrap();
    let nonce = decode_hex::<32>(hex_str(&inputs["nonce"])).unwrap();
    let host_key = unhex(&inputs["host_key"]);
    let client_key = unhex(&inputs["client_spki"]);
    let client_eph = unhex(&inputs["client_eph_spki"]);
    let host_eph = unhex(&inputs["host_eph_spki"]);
    let host_challenge = decode_hex::<32>(hex_str(&inputs["host_challenge"])).unwrap();
    let client_challenge = decode_hex::<32>(hex_str(&inputs["client_challenge"])).unwrap();
    let offer_sdp = hex_str(&inputs["offer_sdp"]).as_bytes().to_vec();
    let answer_sdp = hex_str(&inputs["answer_sdp"]).as_bytes().to_vec();
    let expires = inputs["expires_at_ms"].as_u64().unwrap();

    assert_eq!(
        encode_hex(&ticket_request_transcript(
            &session_id,
            expires,
            &nonce,
            &host_key,
            &client_key
        )),
        hex_str(&transcripts["hct1"])
    );
    assert_eq!(
        encode_hex(&client_handshake_offer_transcript(
            &session_id,
            &host_key,
            &client_key,
            &client_eph,
            &client_challenge,
            &nonce
        )),
        hex_str(&transcripts["hco1"])
    );
    assert_eq!(
        encode_hex(&p2p_offer_transcript(
            &session_id,
            &offer_sdp,
            &host_key,
            &client_key,
            &nonce
        )),
        hex_str(&transcripts["hpo1"])
    );
    assert_eq!(
        encode_hex(&p2p_answer_transcript(
            &session_id,
            &offer_sdp,
            &answer_sdp,
            &host_key,
            &client_key
        )),
        hex_str(&transcripts["hpa1"])
    );
    assert_eq!(
        encode_hex(&session_handshake_transcript(
            &session_id,
            &host_key,
            &client_key,
            &host_eph,
            &client_eph,
            &host_challenge,
            &client_challenge
        )),
        hex_str(&transcripts["hck1"])
    );

    // HHR1 与邮箱(Host/服务器侧公式)
    let token = decode_hex::<32>(hex_str(&root["mailbox"]["bearer_token_hex"])).unwrap();
    let mailbox_id = root["mailbox"]["mailbox_id"].as_str().unwrap();
    assert_eq!(mailbox_id_for_token(&token), mailbox_id);
    assert_eq!(
        host_registration_transcript(mailbox_id, expires, &nonce, &host_key).len(),
        108,
        "HHR1 固定宽 4+32+8+32+32"
    );

    // hex 工具自洽
    assert_eq!(
        encode_hex(&decode_hex::<4>("0a1f2b3c").unwrap()),
        "0a1f2b3c"
    );
    assert!(decode_hex::<4>("0a1f2b").is_none());
    assert!(decode_hex::<4>("zz").is_none());
}
