#!/usr/bin/env python3
"""
跨语言对拍 fixture 生成器 —— 客户端字节级一致性证据。

本脚本用 Python 独立实现(不经 CryptoKit/openssl): SHA-256/HMAC/HKDF(RFC 5869)、
P-256 标量乘法、transcript 拼接、输入二进制帧、音频帧(HMA1/HMC1/HMD1/HMR1/
HSD1/HSC1)、快捷键帧(HKS1)、质量二进制消息(0x15/0x0E)。生成的期望值写进
fixtures/*.json, 由各端 conformance 测试逐字节断言。

对应实现必须三端一致(web 端已冻结, 2026-08-24, 见 AGENTS.md §13):
  crates/rendezvous + demo/events  ·  android  ·  ios HypercastKit

修改任何 transcript/帧布局时: 先改 docs/protocol/ 文档, 再三端同步, 再重新生成本 fixture。
音频/快捷键帧的自检断言内嵌 Rust golden 向量(crates/events + crates/transport),
生成器跑通即证明 Python 实现与 Rust 契约一致。
"""

import hashlib
import hmac
import json
import struct
from pathlib import Path

# 仓库级唯一权威位置: crates/protocol-kit/fixtures/
# 三端(Rust/Kotlin/Swift)的 conformance 测试都读本目录下的同一份文件。
OUT_DIR = Path(__file__).resolve().parent.parent / "fixtures"
OUT_CRYPTO = OUT_DIR / "protocol_fixtures.json"
OUT_PROTO = OUT_DIR / "proto_fixtures.json"
OUT_AUDIO = OUT_DIR / "audio_fixtures.json"

SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def u64be(v: int) -> bytes:
    return struct.pack(">Q", v)


def f32le(v: float) -> bytes:
    return struct.pack("<f", v)


# ---- P-256(纯 Python 标量乘法, 与 CryptoKit/openssl 无关的第三方实现) ----

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        slope = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        slope = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def _mul(k: int, p):
    r = None
    assert 0 < k < N, "scalar out of range"
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def spki_of(point) -> bytes:
    x, y = point
    return SPKI_PREFIX + b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---- 固定输入(全部确定性, 刻意用连续字节以暴露拼接顺序错误) ----

secret = bytes(range(0x00, 0x20))            # 32B 配对密钥
session_id = bytes(range(0xA0, 0xB0))        # 16B
nonce = bytes(range(0xB0, 0xD0))             # 32B
client_challenge = bytes(range(0xD0, 0xF0))  # 32B
host_challenge = bytes(range(0xE0, 0x100))   # 32B
host_key = bytes(range(0x11, 0x31))          # 32B Ed25519 公钥(合成)
offer_id = bytes(range(0x51, 0x61))          # 16B


def synth_spki(x_start: int) -> bytes:
    return (SPKI_PREFIX + b"\x04"
            + bytes(range(x_start, x_start + 0x20))
            + bytes(range(x_start + 0x20, x_start + 0x40)))


client_spki = synth_spki(0x41)     # 91B 签名身份(合成, 只参与 SHA-256)
client_eph_spki = synth_spki(0x31)
host_eph_spki = synth_spki(0x71)
offer_sdp = b"v=0\r\no=hypercast 1 1 IN IP4 192.168.1.10\r\ns=-\r\nt=0 0\r\n"
answer_sdp = b"v=0\r\no=hypercast 2 1 IN IP4 192.168.1.10\r\ns=-\r\nt=0 0\r\n"
expires_at_ms = 1765000000000

# ---- 邮箱 / HPC1 ----

token = hmac256(secret, b"hypercast-rendezvous-auth/1")
mailbox_id = sha256(b"hypercast-rendezvous-mailbox/1" + token)
hpc1_proof = hmac256(secret, b"HPC1" + offer_id + sha256(client_spki))

# ---- transcripts(与 web/src/crypto/protocol.ts 布局一致) ----

hct1 = (b"HCT1" + session_id + u64be(expires_at_ms) + nonce
        + sha256(host_key) + sha256(client_spki))
hco1 = (b"HCO1" + session_id
        + sha256(host_key) + sha256(client_spki) + sha256(client_eph_spki)
        + client_challenge + nonce)
hpo1 = (b"HPO1" + session_id + sha256(offer_sdp)
        + sha256(host_key) + sha256(client_spki) + nonce)
hpa1 = (b"HPA1" + session_id + sha256(offer_sdp) + sha256(answer_sdp)
        + sha256(host_key) + sha256(client_spki))
hck1 = (b"HCK1" + session_id
        + sha256(host_key) + sha256(client_spki)
        + sha256(host_eph_spki) + sha256(client_eph_spki)
        + host_challenge + client_challenge)

# ---- ECDH + HKDF(真实 P-256 点, 固定标量) ----

client_priv = bytes(range(0x01, 0x21))   # 标量 < N ✅
host_eph_priv = bytes(range(0x21, 0x41))
G = (GX, GY)
client_pub = _mul(int.from_bytes(client_priv, "big"), G)
host_eph_pub = _mul(int.from_bytes(host_eph_priv, "big"), G)
shared_x = _mul(int.from_bytes(client_priv, "big"), host_eph_pub)[0].to_bytes(32, "big")

client_spki_real = spki_of(client_pub)
host_eph_spki_real = spki_of(host_eph_pub)
hck1_ecdh = (b"HCK1" + session_id
             + sha256(host_key) + sha256(client_spki)
             + sha256(host_eph_spki_real) + sha256(client_spki_real)
             + host_challenge + client_challenge)
info = b"hypercast-session-keys/1" + sha256(hck1_ecdh)
hkdf72 = hkdf_sha256(shared_x, secret, info, 72)

crypto_fixtures = {
    "inputs": {
        "secret": secret.hex(),
        "session_id": session_id.hex(),
        "nonce": nonce.hex(),
        "client_challenge": client_challenge.hex(),
        "host_challenge": host_challenge.hex(),
        "host_key": host_key.hex(),
        "offer_id": offer_id.hex(),
        "client_spki": client_spki.hex(),
        "client_eph_spki": client_eph_spki.hex(),
        "host_eph_spki": host_eph_spki.hex(),
        "offer_sdp": offer_sdp.decode(),
        "answer_sdp": answer_sdp.decode(),
        "expires_at_ms": expires_at_ms,
    },
    "mailbox": {
        "mailbox_id": mailbox_id.hex(),
        "bearer_token_hex": token.hex(),
    },
    "hpc1": {"proof": hpc1_proof.hex()},
    "transcripts": {
        "hct1": hct1.hex(),
        "hco1": hco1.hex(),
        "hpo1": hpo1.hex(),
        "hpa1": hpa1.hex(),
        "hck1": hck1.hex(),
    },
    "ecdh_hkdf": {
        "client_priv": client_priv.hex(),
        "client_spki_real": client_spki_real.hex(),
        "host_eph_priv": host_eph_priv.hex(),
        "host_eph_spki_real": host_eph_spki_real.hex(),
        "shared_x": shared_x.hex(),
        "hck1": hck1_ecdh.hex(),
        "hkdf72": hkdf72.hex(),
    },
}

# ---- 输入二进制帧 / JSON 消息(little-endian f32, 与 host_webrtc.rs 对齐) ----

pointer = dict(action=1, button=2, x=123.5, y=-45.25, dx=0.0, dy=0.0,
               vw=1920.0, vh=1080.0)
pointer_hex = (bytes([0x01, pointer["action"], 0x02, 0x00])
               + f32le(pointer["x"]) + f32le(pointer["y"])
               + f32le(pointer["dx"]) + f32le(pointer["dy"])
               + f32le(pointer["vw"]) + f32le(pointer["vh"])).hex()

pointer_delta = dict(action=3, button=-1, x=0.0, y=0.0, dx=3.5, dy=-1.25,
                     vw=0.0, vh=0.0)
pointer_delta_hex = (bytes([0x01, pointer_delta["action"], 0xFF, 0xFF])
                     + f32le(pointer_delta["x"]) + f32le(pointer_delta["y"])
                     + f32le(pointer_delta["dx"]) + f32le(pointer_delta["dy"])
                     + f32le(pointer_delta["vw"]) + f32le(pointer_delta["vh"])).hex()

wheel = dict(x=100.5, y=60.0, delta_x=-2.5, delta_y=8.0, vw=1920.0, vh=1080.0)
wheel_hex = (bytes([0x02])
             + f32le(wheel["x"]) + f32le(wheel["y"])
             + f32le(wheel["delta_x"]) + f32le(wheel["delta_y"])
             + f32le(wheel["vw"]) + f32le(wheel["vh"])).hex()


def widget_layout_fixtures() -> dict:
    """WidgetLayout JSON schema 2 对拍(客户端配置 schema 升格第四共享协议):
    Android WidgetLayoutCodec ↔ iOS HypercastInput.WidgetLayoutCodec。
    样例语义与 Android 单测同源: 正常布局 / 损坏回落 / v1 迁移 / 越界钳制。"""
    normal = {
        "schema": 2,
        "video_offset_y": 36,
        "widgets": [
            {"kind": "VOICE_BAR", "x": 0.5, "y": 0.92, "scale": 1.0, "visible": True, "alpha": 0.6},
            {"kind": "ROUTE_CHIP", "x": 0.12, "y": 0.08, "scale": 0.85, "visible": False, "alpha": 1.0},
            {"kind": "SCROLL_PAD", "x": 0.9, "y": 0.4, "scale": 1.15, "visible": True, "alpha": 0.8},
        ],
    }
    legacy_v1 = {
        "schema": 1,
        "widgets": [{"kind": "QUICK_BAR", "x": 0.3, "y": 0.7, "size": "LARGE"}],
    }
    corrupted = {
        "schema": 2,
        "video_offset_y": -80,
        "widgets": [
            {"kind": "VOICE_BAR", "x": 1.7, "y": -0.3, "scale": 9.0, "visible": True, "alpha": 5.0},
            {"kind": "MYSTERY_BAR", "x": 0.5, "y": 0.5, "scale": 1.0, "visible": True, "alpha": 1.0},
            {"kind": "ROUTE_CHIP", "x": 0.2, "y": 0.2, "scale": 0.8, "visible": True, "alpha": 0.9},
            {"kind": "ROUTE_CHIP", "x": 0.4, "y": 0.4, "scale": 1.2, "visible": False, "alpha": 0.7},
        ],
    }
    expected = {
        # decode(正常): 原样还原
        "normal_decoded": {
            "video_offset_y": 36,
            "anchors": [
                {"kind": "VOICE_BAR", "x": 0.5, "y": 0.92, "scale": 1.0, "visible": True, "alpha": 0.6},
                {"kind": "ROUTE_CHIP", "x": 0.12, "y": 0.08, "scale": 0.85, "visible": False, "alpha": 1.0},
                {"kind": "SCROLL_PAD", "x": 0.9, "y": 0.4, "scale": 1.15, "visible": True, "alpha": 0.8},
            ],
        },
        # decode(v1): size 三档 → 连续 scale, 其余默认
        "legacy_v1_decoded": {
            "video_offset_y": 0,
            "anchors": [
                {"kind": "QUICK_BAR", "x": 0.3, "y": 0.7, "scale": 1.15, "visible": True, "alpha": 1.0},
            ],
        },
        # decode(损坏): 越界坐标/scale/alpha 钳制, 未知 kind 丢弃, 重复 kind 取首个
        "corrupted_decoded": {
            "video_offset_y": -80,
            "anchors": [
                {"kind": "VOICE_BAR", "x": 1.0, "y": 0.0, "scale": 1.5, "visible": True, "alpha": 1.0},
                {"kind": "ROUTE_CHIP", "x": 0.2, "y": 0.2, "scale": 0.8, "visible": True, "alpha": 0.9},
            ],
        },
    }
    return {
        "schema_version": 2,
        "inputs": {"normal": normal, "legacy_v1": legacy_v1, "corrupted": corrupted},
        "expected": expected,
    }

def cj(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


# ---- 音频/快捷键/质量二进制帧(布局见 docs/protocol/audio-stream-v1.md 等) ----
# 大端辅助(音频帧全 BE; PCM16 样本为帧内唯一 LE 处)

def u8(v: int) -> bytes:
    return bytes([v])


def u16be(v: int) -> bytes:
    return struct.pack(">H", v)


def u32be(v: int) -> bytes:
    return struct.pack(">I", v)


def u64be_(v: int) -> bytes:
    return struct.pack(">Q", v)


MIC_SESSION = bytes([0x11]) * 16          # 对齐 Rust golden SESSION
MIC_LEASE = bytes([0x22]) * 16            # 对齐 Rust golden lease_id
AUDIO_PAYLOAD = bytes([0xAA, 0xBB, 0xCC])  # 对齐 Rust golden payload
PCM16_MONO_960 = struct.pack("<960h", *[((i * 7) % 1000) - 500 for i in range(960)])


def hma1(session_id: bytes, sequence: int, ts_us: int, codec: int, eos: bool,
         payload: bytes, sample_rate: int = 48000, channels: int = 1) -> bytes:
    return (b"HMA1" + u8(1) + session_id + u64be_(sequence) + u64be_(ts_us)
            + u32be(sample_rate) + u8(channels) + u8(codec) + u8(1 if eos else 0)
            + u32be(len(payload)) + payload)


def hmc1(kind: int, session_id: bytes, body: bytes = b"") -> bytes:
    return b"HMC1" + u8(1) + u8(kind) + session_id + body


def hmd1(route_state: int, demand_active: bool, lease_id: bytes, epoch: int,
         running: int, err: str = "") -> bytes:
    err_b = err.encode()
    return (b"HMD1" + u8(1) + u8(route_state) + u8(1 if demand_active else 0)
            + u8(0) + lease_id + u64be_(epoch) + u32be(running)
            + u16be(len(err_b)) + err_b)


def hmr1(enabled: bool, revision: int) -> bytes:
    return b"HMR1" + u8(1) + u8(1 if enabled else 0) + b"\x00\x00" + u64be_(revision)


def hsd1(sequence: int, ts_us: int, codec: int, eos: bool, payload: bytes,
         sample_rate: int = 48000, channels: int = 2) -> bytes:
    return (b"HSD1" + u8(1) + u8(1 if eos else 0) + u8(codec) + u8(channels)
            + u32be(sample_rate) + u64be_(sequence) + u64be_(ts_us)
            + u32be(len(payload)) + payload)


def hsc1(enabled: bool, codec: int, revision: int) -> bytes:
    return b"HSC1" + u8(1) + u8(1 if enabled else 0) + u8(codec) + u8(0) + u64be_(revision)


def hks1(slot_id: int, events: list) -> bytes:
    out = b"HKS1" + u8(1) + u8(slot_id) + u8(len(events)) + u8(0)
    for key_code, flags, key_down, delay_ms in events:
        out += u16be(key_code) + u64be_(flags) + u8(1 if key_down else 0) + u16be(delay_ms)
    return out


# 修饰键位(见 docs/protocol/shortcut-frame-v1.md, 与 CGEventFlags 一致)
MOD_SHIFT = 0x0002_0000
MOD_CONTROL = 0x0004_0000
MOD_OPTION = 0x0008_0000
MOD_COMMAND = 0x0010_0000
MOD_FN = 0x0080_0000

hma1_opus = hma1(MIC_SESSION, 9, 123456, codec=1, eos=True, payload=AUDIO_PAYLOAD)
hma1_pcm16 = hma1(MIC_SESSION, 4, 987654, codec=2, eos=False, payload=PCM16_MONO_960)
hmc1_start = hmc1(1, MIC_SESSION, u32be(48000) + u8(1) + u16be(20) + u8(1))
hmc1_start_pcm16 = hmc1(1, MIC_SESSION, u32be(48000) + u8(1) + u16be(20) + u8(2))
hmc1_ready = hmc1(2, MIC_SESSION)
hmc1_stop = hmc1(3, MIC_SESSION, u64be_(9))
hmc1_cancel = hmc1(5, MIC_SESSION, u8(3))
HMC1_ERROR_MSG = b"encoder failed"
hmc1_error = hmc1(6, MIC_SESSION, u16be(0x0201) + u16be(len(HMC1_ERROR_MSG)) + HMC1_ERROR_MSG)
hmd1_ready = hmd1(route_state=1, demand_active=True, lease_id=MIC_LEASE, epoch=9, running=2)
hmr1_golden = hmr1(enabled=False, revision=7)
hsd1_opus = hsd1(0x0A0B, 424242, codec=1, eos=False, payload=AUDIO_PAYLOAD * 2)
hsd1_eos_tail = hsd1(0x0A0C, 424262, codec=1, eos=True, payload=b"")
hsc1_pcm16 = hsc1(enabled=True, codec=2, revision=5)
hsc1_legacy = hsc1(enabled=True, codec=0, revision=6)
hks1_single = hks1(7, [(0x35, 0, True, 0)])                       # esc down
hks1_chord = hks1(3, [                                            # ⌘⌥ return down 全和弦
    (0x3B, MOD_CONTROL, True, 0),                                 # control down, 累积 flags
    (0x3D, MOD_CONTROL | MOD_OPTION, True, 0),                    # option down
    (0x36, MOD_CONTROL | MOD_OPTION | MOD_COMMAND, True, 0),      # command down
    (0x24, MOD_CONTROL | MOD_OPTION | MOD_COMMAND, True, 90),     # return down, 全量 flags
])
quality_pref_0x15 = u32be(6) + bytes([0x15, 0x02]) + u32be(90)    # HD + 90fps
quality_applied_0x0e = (u64be_(3) + u32be(60) + u64be_(8_000_000)
                        + u8(1) + u8(2))                          # Balanced / NetworkDowngrade

audio_fixtures = {
    "inputs": {
        "mic_session": MIC_SESSION.hex(),
        "mic_lease": MIC_LEASE.hex(),
        "payload_3b": AUDIO_PAYLOAD.hex(),
        "pcm16_mono_960_len": len(PCM16_MONO_960),
    },
    "hma1": {
        "opus_eos": {"sequence": 9, "capture_ts_us": 123456, "codec": 1,
                     "end_of_stream": True, "hex": hma1_opus.hex()},
        "pcm16_mid": {"sequence": 4, "capture_ts_us": 987654, "codec": 2,
                      "end_of_stream": False,
                      "payload_head_hex": PCM16_MONO_960[:16].hex(),
                      "hex": hma1_pcm16.hex()},
    },
    "hmc1": {
        "start_opus_48k_mono_20ms": {"hex": hmc1_start.hex()},
        "start_pcm16_48k_mono_20ms": {"hex": hmc1_start_pcm16.hex()},
        "ready": {"hex": hmc1_ready.hex()},
        "stop_final_seq_9": {"hex": hmc1_stop.hex()},
        "cancel_permission_denied": {"hex": hmc1_cancel.hex()},
        "error": {"code": 0x0201, "message": "encoder failed", "hex": hmc1_error.hex()},
    },
    "hmd1": {
        "ready_demand": {"hex": hmd1_ready.hex()},
    },
    "hmr1": {
        "disabled_rev7": {"hex": hmr1_golden.hex()},
    },
    "hsd1": {
        "opus_stereo": {"sequence": 0x0A0B, "capture_ts_us": 424242, "codec": 1,
                        "end_of_stream": False, "hex": hsd1_opus.hex()},
        "opus_eos_empty_tail": {"sequence": 0x0A0C, "capture_ts_us": 424262,
                                "codec": 1, "end_of_stream": True,
                                "payload_len": 0, "hex": hsd1_eos_tail.hex()},
    },
    "hsc1": {
        "enable_pcm16_rev5": {"hex": hsc1_pcm16.hex()},
        "enable_legacy_rev6": {"hex": hsc1_legacy.hex()},
    },
}

# ---- LAN 发现(对齐 Android LanHostDiscovery.kt / host crates/demo/src/lan_discovery.rs) ----

LAN_FINGERPRINT = bytes(range(0x00, 0x20)).hex()            # 64 hex
LAN_INSTANCE_ID = "host-" + LAN_FINGERPRINT[:24]
lan_announcement_valid = f"HYPERCAST_HOST/1 {LAN_INSTANCE_ID} 9002 9003 Studio Mac"
lan_announcement_spaces = f"HYPERCAST_HOST/1 {LAN_INSTANCE_ID} 9002 9003 My Home Mac Pro"
lan_transcript = b"HLP1" + nonce                            # nonce = bytes(0xB0..0xCF)

LAN_ED25519_PRIV = bytes(range(0x21, 0x41))                 # 确定性私钥(fixture 稳定)
LAN_ED25519_PUB = None
LAN_PROOF_SIGNATURE = None
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _lan_key = Ed25519PrivateKey.from_private_bytes(LAN_ED25519_PRIV)
    LAN_ED25519_PUB = _lan_key.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    LAN_PROOF_SIGNATURE = _lan_key.sign(lan_transcript)
except Exception:  # 无 cryptography 库时签名向量留空, 各端只测字段校验分支
    pass

# ---- LAN P2P 信令 transcript(对齐 Android LanP2pTranscripts / host lan_p2p_signaling.rs) ----

LANP2_SESSION = bytes([1]) * 16
LANP2_NONCE = bytes([2]) * 32
LANP2_HOST_KEY = bytes([3]) * 32
LANP2_CLIENT_SPKI = bytes([4]) * 91          # 客户端身份为 91B SPKI(P-256)


def lan_p2p_offer_transcript(session, offer_sdp, host_key, client_spki, nonce,
                             realtime_offer_sdp=None):
    if realtime_offer_sdp is None:
        out = b"HLO1" + session + sha256(offer_sdp)
    else:
        out = b"HLO2" + session + sha256(offer_sdp) + sha256(realtime_offer_sdp)
    return out + sha256(host_key) + sha256(client_spki) + nonce


def lan_p2p_answer_transcript(session, offer_sdp, answer_sdp, host_key, client_spki,
                              nonce, realtime_offer_sdp=None, realtime_answer_sdp=None):
    assert (realtime_offer_sdp is None) == (realtime_answer_sdp is None)
    if realtime_offer_sdp is None:
        out = b"HLA1" + session + sha256(offer_sdp) + sha256(answer_sdp)
    else:
        out = (b"HLA2" + session + sha256(offer_sdp) + sha256(answer_sdp)
               + sha256(realtime_offer_sdp) + sha256(realtime_answer_sdp))
    return out + sha256(host_key) + sha256(client_spki) + nonce


lanp2_offer_v1 = lan_p2p_offer_transcript(LANP2_SESSION, b"offer", LANP2_HOST_KEY,
                                          LANP2_CLIENT_SPKI, LANP2_NONCE)
lanp2_offer_v2 = lan_p2p_offer_transcript(LANP2_SESSION, b"main-offer", LANP2_HOST_KEY,
                                          LANP2_CLIENT_SPKI, LANP2_NONCE,
                                          realtime_offer_sdp=b"input-offer")
lanp2_answer_v1 = lan_p2p_answer_transcript(LANP2_SESSION, b"offer", b"answer",
                                            LANP2_HOST_KEY, LANP2_CLIENT_SPKI, LANP2_NONCE)
lanp2_answer_v2 = lan_p2p_answer_transcript(LANP2_SESSION, b"main-offer", b"main-answer",
                                            LANP2_HOST_KEY, LANP2_CLIENT_SPKI, LANP2_NONCE,
                                            realtime_offer_sdp=b"input-offer",
                                            realtime_answer_sdp=b"input-answer")
# host 答案签名(Ed25519, 与 lan_discovery 同一确定性密钥)。
# 签名向量必须自洽: 进 transcript 的 host_key 与签名私钥是同一身份。
LANP2_ANSWER_SIGNATURE = None
LANP2_HOST_PUB = None
LANP2_ANSWER_SIGNED_TRANSCRIPT = None
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _lanp2_key = Ed25519PrivateKey.from_private_bytes(LAN_ED25519_PRIV)
    LANP2_HOST_PUB = _lanp2_key.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw)
    LANP2_ANSWER_SIGNED_TRANSCRIPT = lan_p2p_answer_transcript(
        LANP2_SESSION, b"offer", b"answer", LANP2_HOST_PUB, LANP2_CLIENT_SPKI, LANP2_NONCE)
    LANP2_ANSWER_SIGNATURE = _lanp2_key.sign(LANP2_ANSWER_SIGNED_TRANSCRIPT)
except Exception:
    pass

hvm1_set_active = (b"HVM1" + u8(1) + u8(1) + u8(1) + u8(0)
                   + u64be_(5) + u64be_(1) + u64be_(0) + u64be_(0))

widget_layout_fixtures_dict = widget_layout_fixtures()

proto_fixtures = {
    "widget_layout": widget_layout_fixtures_dict,
    "pointer": {**pointer, "hex": pointer_hex},
    "pointer_delta": {**pointer_delta, "hex": pointer_delta_hex},
    "wheel": {**wheel, "hex": wheel_hex},
    "text_json": {"text": "hello hypercast",
                  "json": cj({"type": "text", "text": "hello hypercast"})},
    "key_json": {"code": "KeyA",
                 "json": cj({"type": "key", "code": "KeyA"})},
    "quality_json": {"preset": "hd", "bitrate": 8000000,
                     "json": cj({"type": "quality", "preset": "hd",
                                 "bitrate": 8000000})},
    "clipboard_json": {"dir": "host", "text": "copied text",
                       "json": cj({"type": "clipboard", "dir": "host",
                                   "text": "copied text"})},
    "display_json": {"id": 4294961,
                     "json": cj({"type": "display", "id": 4294961})},
    "hks1": {
        "single_esc_down": {"slot": 7, "hex": hks1_single.hex()},
        "chord_ctrl_opt_cmd_return": {"slot": 3, "hex": hks1_chord.hex()},
    },
    "quality_binary": {
        "preference_0x15": {"preset_code": 2, "requested_fps": 90,
                            "hex": quality_pref_0x15.hex()},
        "applied_0x0e": {"report_revision": 3, "fps": 60, "bitrate_bps": 8000000,
                         "tier": 1, "reason": 2, "hex": quality_applied_0x0e.hex()},
        "ceilings": {"auto": 20000000, "clear": 2000000, "hd": 8000000,
                     "original": 20000000},
        "fps_tiers": [30, 60, 90, 144],
    },
    "hvm1": {
        "set_active": {"revision": 5, "command_id": 1, "hex": hvm1_set_active.hex()},
    },
    "lan_p2p": {
        "inputs": {
            "session_hex": LANP2_SESSION.hex(), "nonce_hex": LANP2_NONCE.hex(),
            "host_key_hex": LANP2_HOST_KEY.hex(),
            "client_spki_hex": LANP2_CLIENT_SPKI.hex(),
        },
        "offer_transcript_v1": {"offer_sdp": "offer", "hex": lanp2_offer_v1.hex()},
        "offer_transcript_v2": {"offer_sdp": "main-offer",
                                "realtime_input_offer_sdp": "input-offer",
                                "hex": lanp2_offer_v2.hex()},
        "answer_transcript_v1": {"offer_sdp": "offer", "answer_sdp": "answer",
                                 "hex": lanp2_answer_v1.hex()},
        "answer_transcript_v2": {"offer_sdp": "main-offer", "answer_sdp": "main-answer",
                                 "realtime_input_offer_sdp": "input-offer",
                                 "realtime_input_answer_sdp": "input-answer",
                                 "hex": lanp2_answer_v2.hex()},
        "answer_signature_v1": {
            "host_public_key_raw_hex": LANP2_HOST_PUB.hex() if LANP2_HOST_PUB else "",
            "transcript_hex": (LANP2_ANSWER_SIGNED_TRANSCRIPT.hex()
                               if LANP2_ANSWER_SIGNED_TRANSCRIPT else ""),
            "signature_hex": LANP2_ANSWER_SIGNATURE.hex() if LANP2_ANSWER_SIGNATURE else "",
        },
    },
    "lan_discovery": {
        "probe_hex": b"HYPERCAST_DISCOVER/1".hex(),
        "announcement_valid": {
            "text": lan_announcement_valid,
            "instance_id": LAN_INSTANCE_ID, "video_port": 9002, "api_port": 9003,
            "display_name": "Studio Mac", "source_host": "192.168.1.10",
        },
        "announcement_name_with_spaces": {"text": lan_announcement_spaces,
                                          "display_name": "My Home Mac Pro"},
        "promotion": {"fingerprint": LAN_FINGERPRINT,
                      "fingerprint_sha256_prefixed": "sha256:" + LAN_FINGERPRINT,
                      "expected_instance_id": LAN_INSTANCE_ID},
        "hlp1_transcript": {"nonce_hex": nonce.hex(), "hex": lan_transcript.hex()},
        "identity_proof": {
            "host_public_key_raw_hex": LAN_ED25519_PUB.hex() if LAN_ED25519_PUB else "",
            "signature_hex": LAN_PROOF_SIGNATURE.hex() if LAN_PROOF_SIGNATURE else "",
            "protocol": "hypercast-lan-host-proof/1",
        },
    },
}


def selfcheck_against_rust_goldens() -> None:
    """断言 Python 实现与 crates/events + crates/transport 的 golden 字面量逐字节一致。

    来源: crates/events/src/virtual_microphone.rs(golden_bytes_match_the_kotlin_contract /
    host_microphone_status_round_trips_with_a_stable_golden_vector /
    route_command_matches_the_kotlin_golden_vector)、crates/transport/src/channel.rs
    (encodes_exact_golden_bytes)。改 Rust 契约而不改这里, 生成器直接抛错。
    """
    assert hmc1_ready == b"HMC1\x01\x02" + MIC_SESSION, "HMC1 Ready golden mismatch"
    assert hma1_opus == (b"HMA1\x01" + MIC_SESSION + u64be_(9) + u64be_(123456)
                         + u32be(48000) + bytes([1, 1, 1]) + u32be(3) + AUDIO_PAYLOAD), \
        "HMA1 golden mismatch"
    assert hmd1_ready == (b"HMD1\x01\x01\x01\x00" + MIC_LEASE + u64be_(9)
                          + u32be(2) + u16be(0)), "HMD1 golden mismatch"
    assert hmr1_golden == b"HMR1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07", \
        "HMR1 golden mismatch"
    envelope = (b"HCS1\x01\x03" + u16be(0x0003) + bytes(range(0x00, 0x10))
                + u64be_(0x0102030405060708) + u64be_(0x1112131415161718)
                + u32be(2) + b"ok")
    assert envelope == bytes([
        0x48, 0x43, 0x53, 0x31, 0x01, 0x03, 0x00, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x00, 0x00, 0x00, 0x02, 0x6F, 0x6B]), "HCS1 envelope golden mismatch"


def main() -> None:
    selfcheck_against_rust_goldens()
    with open(OUT_CRYPTO, "w") as f:
        json.dump(crypto_fixtures, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(OUT_PROTO, "w") as f:
        json.dump(proto_fixtures, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(OUT_AUDIO, "w") as f:
        json.dump(audio_fixtures, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {OUT_CRYPTO}, {OUT_PROTO} and {OUT_AUDIO}")


if __name__ == "__main__":
    main()
