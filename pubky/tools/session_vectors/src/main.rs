use std::str::FromStr;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem, OpModeS, Serializable};
use pubky::deep_links::{
    DeepLinkScheme, GrantApprovalFormat, GrantRelayChannel, SigninGrantDeepLink, SigninGrantParams,
};
use pubky_common::auth::grant::GrantClaims;
use pubky_common::auth::grant_session_responses::{GrantSessionInfo, GrantSessionResponse};
use pubky_common::auth::jws::{sign_jws, ClientId, GrantId, GRANT_JWS_TYP};
use pubky_common::capabilities::{Capabilities, Capability};
use pubky_common::crypto::{encrypt, hash, Hasher, Keypair};
use pubky_common::encryption_keys::ScopedEncryptionKeyBundle;
use pubky_common::storage_path::StoragePath;
use serde_json::json;

const REV: &str = "131370c0a19c343c5c3aa4b7414f77b01b5066ac";
const RELAY: &str = "https://httprelay.pubky.app/inbox";
const CLIENT_ID: &str = "pubky-browser";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn grant(user: &Keypair, client: &Keypair, caps: &str) -> (GrantClaims, String) {
    let claims = GrantClaims {
        iss: user.public_key(),
        client_id: ClientId::new(CLIENT_ID).unwrap(),
        caps: Capabilities::from_str(caps).unwrap().to_vec(),
        cnf: client.public_key(),
        jti: GrantId::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        iat: 1_760_000_000,
        exp: 1_830_000_000,
    };
    let jws = sign_jws(user, GRANT_JWS_TYP, &claims);
    (claims, jws)
}

fn main() {
    let user = Keypair::from_secret(&[7; 32]);
    let client = Keypair::from_secret(&[9; 32]);
    let homeserver = Keypair::from_secret(&[3; 32]);
    let secret = [1u8; 32];

    // BLAKE3 and relay channel IDs.
    let blake3_cases: Vec<_> = [&b""[..], &b"abc"[..], &secret[..], &[0x42u8; 1500][..]]
        .iter()
        .map(|input| json!({ "input_hex": hex(input), "hash_hex": hex(hash(input).as_bytes()) }))
        .collect();
    let (hpke_sk, hpke_pk) = X25519HkdfSha256::derive_keypair(&[5u8; 32]);
    let epk: [u8; 32] = hpke_pk.to_bytes().into();
    let mut hasher = Hasher::new();
    hasher.update(b"pubky-grant-relay-channel-v1\0");
    hasher.update(&epk);
    let hpke_channel = URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes());
    let shared_channel = URL_SAFE_NO_PAD.encode(hash(&secret).as_bytes());

    // Deep links.
    let caps_bare = Capabilities::from_str("/pub/:rw").unwrap();
    let bare_params = SigninGrantParams::new(
        caps_bare.clone(),
        url::Url::parse(RELAY).unwrap(),
        secret,
        ClientId::new(CLIENT_ID).unwrap(),
        client.public_key(),
    );
    let bare_link = SigninGrantDeepLink::new(DeepLinkScheme::PubkyAuth, bare_params).to_string();
    let caps_signed = Capabilities::from_str("/pub/notes/:rw,/priv/notes/:rwe").unwrap();
    let mut signed_params = SigninGrantParams::new(
        caps_signed.clone(),
        url::Url::parse(RELAY).unwrap(),
        secret,
        ClientId::new(CLIENT_ID).unwrap(),
        client.public_key(),
    );
    signed_params.approval_format = GrantApprovalFormat::SignedApprovalV1;
    signed_params.relay_channel = GrantRelayChannel::Hpke { ephemeral_public_key: epk };
    let signed_link = SigninGrantDeepLink::new(DeepLinkScheme::PubkyAuth, signed_params).to_string();

    // Bare grant delivered over the shared-secret channel.
    let (bare_claims, bare_jws) = grant(&user, &client, &caps_bare.to_string());
    let bare_message = encrypt(bare_jws.as_bytes(), &secret);

    // Signed approval with an encryption key, delivered over HPKE.
    let (signed_claims, signed_grant_jws) = grant(&user, &client, &caps_signed.to_string());
    let key_scopes: Vec<StoragePath> = signed_claims
        .caps
        .iter()
        .filter(|cap| cap.grants_encryption_keys())
        .map(|cap| cap.scope().clone())
        .collect();
    let bundle = ScopedEncryptionKeyBundle::from_identity_secret(&user.secret(), key_scopes.iter());
    let envelope = json!({ "version": "v1", "grant": signed_grant_jws, "encryption_keys": bundle });
    let approval_jws = sign_jws(&user, "pubky-grant-approval", &envelope);
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &hpke_pk,
        b"pubky-grant-approval-hpke-v1",
        approval_jws.as_bytes(),
        b"",
    )
    .unwrap();
    let mut wire = b"pubky-hpke-v1\0".to_vec();
    wire.extend_from_slice(&encapped.to_bytes());
    wire.extend_from_slice(&ciphertext);

    // Proof of possession and the exchange body, with a fixed nonce and time.
    #[derive(serde::Serialize)]
    struct PopProofClaims {
        aud: pubky_common::crypto::PublicKey,
        gid: GrantId,
        nonce: String,
        iat: u64,
    }
    let pop = sign_jws(
        &client,
        "pubky-pop",
        &PopProofClaims {
            aud: homeserver.public_key(),
            gid: GrantId::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            nonce: "bm9uY2Utbm9uY2Utbm9uYw".into(),
            iat: 1_760_000_123,
        },
    );
    let exchange_body = json!({ "grant": bare_jws, "pop": pop }).to_string();

    // Session response.
    let response = GrantSessionResponse {
        token: "bearer-token-for-tests".into(),
        session: GrantSessionInfo {
            homeserver: homeserver.public_key(),
            pubky: user.public_key(),
            client_id: ClientId::new(CLIENT_ID).unwrap(),
            capabilities: Capabilities::from_str("/pub/:rw").unwrap().to_vec(),
            grant_id: GrantId::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            token_expires_at: 1_760_003_600,
            grant_expires_at: 1_830_000_000,
            created_at: 1_760_000_000,
        },
    };

    // Scope coverage, per the SDK.
    let pairs = [
        ("/pub/app/:r", "/pub/app/file"),
        ("/pub/app/:r", "/pub/app/"),
        ("/pub/app/:r", "/pub/app/deep/nested/file"),
        ("/pub/app/:r", "/pub/app-evil/file"),
        ("/pub/app/:r", "/pub/ap"),
        ("/pub/app:r", "/pub/app"),
        ("/pub/app:r", "/pub/app/inside"),
        ("/pub/app:r", "/pub/appended"),
        ("/:rw", "/pub/anything"),
        ("/:rw", "/"),
        ("/pub/:rw", "/priv/secret"),
    ];
    let covers: Vec<_> = pairs
        .iter()
        .map(|(cap, path)| {
            let c = Capability::from_str(cap).unwrap();
            let p = StoragePath::new(path).unwrap();
            json!({ "capability": cap, "path": path, "covers": c.scope_covers_path(&p) })
        })
        .collect();
    let canonical_caps: Vec<_> = ["/pub/:rw", "/pub/notes/:rw,/priv/notes/:rwe", "/pub/a/:r,/pub/b:w"]
        .iter()
        .map(|s| json!({ "input": s, "canonical": Capabilities::from_str(s).unwrap().to_string() }))
        .collect();

    let out = json!({
        "pubky_core_rev": REV,
        "keys": {
            "user_secret_hex": hex(&user.secret()),
            "user_public_z32": user.public_key().z32(),
            "user_public_hex": hex(user.public_key().as_bytes()),
            "client_secret_hex": hex(&client.secret()),
            "client_public_z32": client.public_key().z32(),
            "homeserver_public_z32": homeserver.public_key().z32(),
        },
        "blake3": blake3_cases,
        "relay": {
            "inbox": RELAY,
            "shared_secret_b64url": URL_SAFE_NO_PAD.encode(secret),
            "shared_channel_id": shared_channel,
            "hpke_recipient_secret_b64url": URL_SAFE_NO_PAD.encode(hpke_sk.to_bytes()),
            "hpke_recipient_public_b64url": URL_SAFE_NO_PAD.encode(epk),
            "hpke_channel_id": hpke_channel,
        },
        "links": { "bare": bare_link, "signed": signed_link },
        "bare_grant": {
            "caps": caps_bare.to_string(),
            "claims": serde_json::to_value(&bare_claims).unwrap(),
            "jws": bare_jws,
            "relay_message_b64": STANDARD.encode(&bare_message),
        },
        "signed_approval": {
            "caps": caps_signed.to_string(),
            "claims": serde_json::to_value(&signed_claims).unwrap(),
            "grant_jws": signed_grant_jws,
            "approval_jws": approval_jws,
            "relay_message_b64": STANDARD.encode(&wire),
        },
        "pop": {
            "nonce": "bm9uY2Utbm9uY2Utbm9uYw",
            "iat": 1_760_000_123,
            "jws": pop,
            "exchange_body": exchange_body,
        },
        "session_response": serde_json::to_value(&response).unwrap(),
        "covers": covers,
        "canonical_caps": canonical_caps,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
