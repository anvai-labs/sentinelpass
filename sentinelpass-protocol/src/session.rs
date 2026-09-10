//! Directional session keys, AAD-bound frames, replay protection, and
//! deadlines for IPC connections (WBS-509/510/511, TD-ROB-16).
//!
//! Wire design (v1):
//!
//! * Handshake — the CLIENT sends the first frame (the same 4-byte
//!   length-prefixed framing as everything else): a JSON
//!   `SessionHello { v: 1, cr: <hex 32B client random> }`. The server
//!   replies `SessionAccept { v: 1, sr: <hex 32B server random> }`.
//! * Key schedule (WBS-509) — HKDF-SHA256 with the daemon auth token as
//!   IKM and `client_random || server_random` as salt yields two
//!   DIRECTIONAL 32-byte keys (`c2s`, `s2c`); the client encrypts with
//!   `c2s`, the server with `s2c`, so a frame replayed into the opposite
//!   direction (reflection) fails authentication.
//! * Frames (WBS-510) — nonce `4 zero bytes || u64 BE counter` and AAD
//!   `SPIS || proto(u16 LE) || direction(u8) || counter(u64 LE)`: the
//!   ciphertext is bound to the protocol, the direction, and the counter.
//! * Replay (WBS-511) — each direction's counter must be STRICTLY
//!   increasing; a duplicate or lower counter is refused before delivery.
//! * Deadlines — every frame read is bounded by [`SESSION_READ_DEADLINE`]
//!   (stalled peers cannot wedge the other side); frame bounds stay at
//!   [`MAX_MESSAGE_SIZE`].
//!
//! Compatibility: legacy (pre-session) clients speaking plaintext
//! envelopes are accepted in PLAIN mode when the server negotiates (the
//! first frame is not a SessionHello); plain mode is the ADR-007 migration
//! window and is removed in 1.0. New clients ALWAYS negotiate.

use crate::transport::{TransportError, TransportResult, MAX_MESSAGE_SIZE};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Session protocol version.
pub const SESSION_PROTO_VERSION: u16 = 1;
/// Bound on every frame read (deadlines, WBS-511).
pub const SESSION_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// Magic prefix of the session AAD ("SPIS" = SentinelPass IPC Session).
const AAD_MAGIC: &[u8; 4] = b"SPIS";

/// Handshake frame (client → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHello {
    /// Protocol version; must equal [`SESSION_PROTO_VERSION`].
    pub v: u16,
    /// 32-byte client random, hex.
    pub cr: String,
}

/// Handshake frame (server → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAccept {
    pub v: u16,
    /// 32-byte server random, hex.
    pub sr: String,
}

/// Which direction frames flow in. Directional keys (WBS-509): the client
/// encrypts with `c2s`, the server with `s2c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub fn opposite(self) -> Direction {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Direction::ClientToServer => 1,
            Direction::ServerToClient => 2,
        }
    }

    fn info(self) -> &'static str {
        match self {
            Direction::ClientToServer => "sentinelpass-ipc v1 client-to-server",
            Direction::ServerToClient => "sentinelpass-ipc v1 server-to-client",
        }
    }
}

/// One direction's crypto state: directional key + strictly-increasing
/// counter (the core of replay protection, WBS-511).
struct DirectionState {
    key: [u8; 32],
    direction: Direction,
    /// Send: last counter SENT. Receive: last counter ACCEPTED.
    counter: u64,
}

impl DirectionState {
    fn new(key: [u8; 32], direction: Direction) -> Self {
        Self {
            key,
            direction,
            counter: 0,
        }
    }

    fn next_counter(&mut self) -> TransportResult<u64> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| TransportError::Other("session counter exhausted".to_string()))?;
        Ok(self.counter)
    }

    fn accept_counter(&mut self, counter: u64) -> TransportResult<()> {
        if counter <= self.counter {
            return Err(TransportError::Other(format!(
                "rejected frame: counter {counter} is not newer than {} (replay or reorder)",
                self.counter
            )));
        }
        self.counter = counter;
        Ok(())
    }
}

/// AAD for one frame (WBS-510): binds the ciphertext to the protocol, the
/// SENDER's direction, and the counter.
fn frame_aad(direction: Direction, proto: u16, counter: u64) -> [u8; 15] {
    let mut aad = [0u8; 15];
    aad[..4].copy_from_slice(AAD_MAGIC);
    aad[4..6].copy_from_slice(&proto.to_le_bytes());
    aad[6] = direction.tag();
    aad[7..15].copy_from_slice(&counter.to_le_bytes());
    aad
}

fn counter_nonce(counter: u64) -> [u8; 12] {
    // Deterministic per-direction counter nonce: 4 zero bytes || u64 BE.
    // Unique per (key, counter); keys are directional and session-bound, so
    // no nonce reuse occurs.
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Derive the two directional keys (WBS-509). `token` is the daemon auth
/// token (32 random bytes, hex); the session randoms bind the keys to one
/// specific session.
pub fn derive_directional_keys(
    token: &str,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> TransportResult<([u8; 32], [u8; 32])> {
    // Production tokens are 32 random bytes hex-encoded. Non-hex tokens
    // (embedders, tests) are normalized through SHA-256 so the schedule
    // always has exactly 32 bytes of key material.
    let token_bytes = match hex::decode(token.trim()) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => Sha256::digest(token.trim().as_bytes()).to_vec(),
    };

    let salt = [client_random.as_slice(), server_random.as_slice()].concat();
    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &token_bytes);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(Direction::ClientToServer.info().as_bytes(), &mut c2s)
        .map_err(|e| TransportError::Other(format!("hkdf expand failed: {e}")))?;
    hk.expand(Direction::ServerToClient.info().as_bytes(), &mut s2c)
        .map_err(|e| TransportError::Other(format!("hkdf expand failed: {e}")))?;
    Ok((c2s, s2c))
}

/// Session crypto for ONE connection endpoint: seals in the endpoint's
/// send direction, opens in the peer's.
pub struct SessionCrypto {
    send: DirectionState,
    recv: DirectionState,
}

impl SessionCrypto {
    /// Client endpoint (sends c2s, receives s2c).
    pub fn client(c2s: [u8; 32], s2c: [u8; 32]) -> Self {
        Self {
            send: DirectionState::new(c2s, Direction::ClientToServer),
            recv: DirectionState::new(s2c, Direction::ServerToClient),
        }
    }

    /// Server endpoint (sends s2c, receives c2s).
    pub fn server(c2s: [u8; 32], s2c: [u8; 32]) -> Self {
        Self {
            send: DirectionState::new(s2c, Direction::ServerToClient),
            recv: DirectionState::new(c2s, Direction::ClientToServer),
        }
    }

    /// Seal one frame: counter nonce + AAD binding direction/protocol/
    /// counter (WBS-509/510).
    pub fn seal(&mut self, plaintext: &[u8]) -> TransportResult<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::Aes256Gcm;

        let counter = self.send.next_counter()?;
        let cipher = Aes256Gcm::new_from_slice(&self.send.key)
            .map_err(|e| TransportError::Other(format!("session cipher init: {e}")))?;
        let nonce = counter_nonce(counter);
        let aad = frame_aad(self.send.direction, SESSION_PROTO_VERSION, counter);

        let mut frame = nonce.to_vec();
        frame.extend_from_slice(
            &cipher
                .encrypt(
                    (&nonce).into(),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| TransportError::Other("session seal failed".to_string()))?,
        );
        Ok(frame)
    }

    /// Open one frame: enforces the strictly-increasing counter (replay,
    /// WBS-511) and the AAD binding to OUR receive direction (reflection,
    /// WBS-510) before returning the plaintext.
    pub fn open(&mut self, frame: &[u8]) -> TransportResult<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::Aes256Gcm;

        if frame.len() <= 12 || frame.len() > MAX_MESSAGE_SIZE + 16 {
            return Err(TransportError::Other(format!(
                "session frame out of bounds: {} bytes",
                frame.len()
            )));
        }
        let (nonce_bytes, ciphertext) = frame.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        let counter = u64::from_be_bytes(nonce[4..12].try_into().expect("8 bytes"));
        self.recv.accept_counter(counter)?;

        let cipher = Aes256Gcm::new_from_slice(&self.recv.key)
            .map_err(|e| TransportError::Other(format!("session cipher init: {e}")))?;
        // AAD uses the SENDER's (= our receive) direction: a reflected
        // frame carries the wrong tag and fails authentication.
        let aad = frame_aad(self.recv.direction, SESSION_PROTO_VERSION, counter);
        cipher
            .decrypt(
                (&nonce).into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                TransportError::Other(
                    "session frame failed authentication (wrong key, direction, or tampered)"
                        .to_string(),
                )
            })
    }
}

/// True when the first plaintext frame is a SessionHello (server-side
/// negotiation detection). A plaintext envelope frame is NOT a hello.
pub fn is_session_hello(first_frame: &[u8]) -> bool {
    serde_json::from_slice::<SessionHello>(first_frame)
        .map(|hello| hello.v == SESSION_PROTO_VERSION && hello.cr.len() == 64)
        .unwrap_or(false)
}

pub fn parse_hello(frame: &[u8]) -> TransportResult<SessionHello> {
    let hello: SessionHello = serde_json::from_slice(frame)
        .map_err(|e| TransportError::Other(format!("invalid SessionHello: {e}")))?;
    if hello.v != SESSION_PROTO_VERSION {
        return Err(TransportError::Other(format!(
            "unsupported session protocol {}",
            hello.v
        )));
    }
    if hello.cr.len() != 64 {
        return Err(TransportError::Other(
            "SessionHello client random must be 32 hex bytes".to_string(),
        ));
    }
    Ok(hello)
}

pub fn parse_accept(frame: &[u8]) -> TransportResult<SessionAccept> {
    let accept: SessionAccept = serde_json::from_slice(frame)
        .map_err(|e| TransportError::Other(format!("invalid SessionAccept: {e}")))?;
    if accept.v != SESSION_PROTO_VERSION {
        return Err(TransportError::Other(format!(
            "unsupported session protocol {}",
            accept.v
        )));
    }
    if accept.sr.len() != 64 {
        return Err(TransportError::Other(
            "SessionAccept server random must be 32 hex bytes".to_string(),
        ));
    }
    Ok(accept)
}

/// Fresh client hello + its random (kept by the client for key derivation).
pub fn new_hello() -> (SessionHello, [u8; 32]) {
    let mut cr = [0u8; 32];
    OsRng.fill_bytes(&mut cr);
    (
        SessionHello {
            v: SESSION_PROTO_VERSION,
            cr: hex::encode(cr),
        },
        cr,
    )
}

/// Fresh server accept + its random.
pub fn new_accept() -> (SessionAccept, [u8; 32]) {
    let mut sr = [0u8; 32];
    OsRng.fill_bytes(&mut sr);
    (
        SessionAccept {
            v: SESSION_PROTO_VERSION,
            sr: hex::encode(sr),
        },
        sr,
    )
}

pub fn client_random_of(hello: &SessionHello) -> TransportResult<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(&hello.cr, &mut out)
        .map_err(|e| TransportError::Other(format!("invalid client random: {e}")))?;
    Ok(out)
}

pub fn server_random_of(accept: &SessionAccept) -> TransportResult<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(&accept.sr, &mut out)
        .map_err(|e| TransportError::Other(format!("invalid server random: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn directional_keys_differ_and_bind_to_session_and_token() {
        let (_hello, cr) = new_hello();
        let (_accept, sr) = new_accept();
        let (c2s, s2c) = derive_directional_keys(TOKEN, &cr, &sr).unwrap();
        assert_ne!(c2s, s2c, "directions must derive different keys");

        // Different session randoms → different keys.
        let (hello2, cr2) = new_hello();
        let (_, sr2) = new_accept();
        let (c2s2, _) = derive_directional_keys(TOKEN, &cr2, &sr2).unwrap();
        assert_ne!(c2s, c2s2, "keys must be session-specific");
        let _ = hello2;

        // Wrong token → different keys.
        let (c2s3, _) = derive_directional_keys(
            "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            &cr,
            &sr,
        )
        .unwrap();
        assert_ne!(c2s, c2s3);
    }

    /// Positive: both directions round-trip. Negative: replay, reflection,
    /// tamper, and reorder are all refused (WBS-510/511).
    #[test]
    fn seal_open_round_trip_and_replay_reflection_rejected() {
        let (_, cr) = new_hello();
        let (_, sr) = new_accept();
        let (c2s, s2c) = derive_directional_keys(TOKEN, &cr, &sr).unwrap();
        let mut client = SessionCrypto::client(c2s, s2c);
        let mut server = SessionCrypto::server(c2s, s2c);

        let plaintext = br#"{"token":"t","message":"CheckVault"}"#;

        // Bidirectional round trips.
        let frame = client.seal(plaintext).unwrap();
        assert_eq!(server.open(&frame).unwrap().as_slice(), &plaintext[..]);
        let reply = server.seal(b"ok").unwrap();
        assert_eq!(client.open(&reply).unwrap(), b"ok");

        // Replay: the SAME frame delivered AGAIN is refused (counter not
        // newer), while the next legitimate frame is accepted.
        let frame2 = client.seal(b"second").unwrap();
        assert_eq!(server.open(&frame2).unwrap(), b"second");
        assert!(
            server.open(&frame2).is_err(),
            "replayed frame must be refused"
        );

        // Reflection: a c2s frame fed to the CLIENT endpoint (its own
        // receive direction is s2c) fails authentication.
        let frame3 = client.seal(b"third").unwrap();
        assert!(
            client.open(&frame3).is_err(),
            "reflected frame must be refused"
        );

        // Reorder: once c5 is accepted, the older c4 is refused (strictly
        // increasing per direction; gaps are allowed, regressions are not).
        let frame4 = client.seal(b"fourth").unwrap();
        let frame5 = client.seal(b"fifth").unwrap();
        assert_eq!(server.open(&frame5).unwrap(), b"fifth");
        assert!(server.open(&frame4).is_err(), "older frame must be refused");

        // Tamper: one flipped bit breaks authentication.
        let mut frame6 = client.seal(b"sixth").unwrap();
        let last = frame6.len() - 1;
        frame6[last] ^= 1;
        assert!(server.open(&frame6).is_err());
    }

    #[test]
    fn hello_detection_and_rejects() {
        let (hello, _) = new_hello();
        let bytes = serde_json::to_vec(&hello).unwrap();
        assert!(is_session_hello(&bytes));

        // A plaintext envelope frame is NOT a hello (legacy detection).
        let envelope = br#"{"token":"t","message":"CheckVault"}"#;
        assert!(!is_session_hello(envelope));

        // Wrong version refused by parse_hello.
        let bad = serde_json::json!({ "v": 99, "cr": hex::encode([0u8; 32]) });
        assert!(parse_hello(serde_json::to_vec(&bad).unwrap().as_slice()).is_err());

        // Short client random refused.
        let bad = serde_json::json!({ "v": 1, "cr": "aabb" });
        assert!(parse_hello(serde_json::to_vec(&bad).unwrap().as_slice()).is_err());
    }
}
