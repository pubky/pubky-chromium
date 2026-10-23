// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Test-only signed responses, generated at runtime so their TTL stays fresh.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use pkarr::{dns::rdata::SVCB, dns::Name, Keypair, SignedPacket};
use pkresolve::service_protocol::{ResolveBundle, BUNDLE_SCHEMA};
use pkresolve::{derive_resolution, HttpProtocol, ResolutionRequest};

#[cxx::bridge(namespace = "pubky::prototype::test")]
mod ffi {
    struct SignedBundleFixture {
        service: String,
        bundle: String,
        public_key: [u8; 32],
    }

    extern "Rust" {
        fn make_signed_bundle(ttl_seconds: u32, observed_age_seconds: u32) -> SignedBundleFixture;
        fn make_tampered_bundle() -> SignedBundleFixture;
        fn make_delegated_bundle() -> SignedBundleFixture;
    }
}

fn make_signed_bundle(ttl_seconds: u32, observed_age_seconds: u32) -> ffi::SignedBundleFixture {
    make_bundle(ttl_seconds, observed_age_seconds, None)
}

fn make_tampered_bundle() -> ffi::SignedBundleFixture {
    let mut fixture = make_signed_bundle(60, 10);
    let mut bundle: ResolveBundle =
        serde_json::from_str(&fixture.bundle).expect("valid fixture bundle");
    let mut packet = STANDARD.decode(&bundle.packets[0]).expect("valid base64");
    // Native layout starts with observation time (8 bytes) and key (32 bytes).
    // Corrupt the signature while keeping the DNS packet and summary valid.
    packet[40] ^= 1;
    bundle.packets[0] = STANDARD.encode(packet);
    fixture.bundle = serde_json::to_string(&bundle).expect("serializable bundle");
    fixture
}

fn make_delegated_bundle() -> ffi::SignedBundleFixture {
    make_bundle(60, 10, Some(Keypair::from_secret_key(&[8; 32])))
}

fn make_bundle(
    ttl_seconds: u32,
    observed_age_seconds: u32,
    delegate: Option<Keypair>,
) -> ffi::SignedBundleFixture {
    // Public, deterministic test keys. Each resolver owns a separate cache.
    let key = Keypair::from_secret_key(&[7; 32]);
    let routing_key = delegate.as_ref().unwrap_or(&key);
    let root = Name::new_unchecked(".");
    let mut service = SVCB::new(7, root.clone());
    service.set_port(8443);
    service.set_alpn(&["h2".try_into().expect("valid test ALPN")]);
    service.set_no_default_alpn();
    let mut packet = SignedPacket::builder()
        .https(root.clone(), service, ttl_seconds)
        .address(root, "203.0.113.10".parse().expect("valid test IP"), ttl_seconds)
        .sign(routing_key)
        .expect("valid signed test packet");
    let observed = SystemTime::now() - Duration::from_secs(u64::from(observed_age_seconds));
    packet.set_last_seen(&observed.into());
    let mut packets = vec![STANDARD.encode(packet.serialize())];
    let mut provider = HashMap::from([(routing_key.public_key(), Arc::new(packet))]);
    if let Some(delegate) = &delegate {
        let mut alias = SignedPacket::builder()
            .https(
                Name::new_unchecked("."),
                SVCB::new(0, Name::new(&delegate.to_z32()).expect("valid alias target")),
                ttl_seconds,
            )
            .sign(&key)
            .expect("valid alias packet");
        alias.set_last_seen(&observed.into());
        packets.push(STANDARD.encode(alias.serialize()));
        provider.insert(key.public_key(), Arc::new(alias));
    }
    let request = ResolutionRequest::new(
        key.to_z32().parse().expect("valid service"),
        443,
        vec![HttpProtocol::Http2],
    )
    .expect("valid request");
    let bundle = ResolveBundle {
        schema: BUNDLE_SCHEMA,
        packets,
        resolution: derive_resolution(&request, &provider).expect("test packet resolves").into(),
    };
    ffi::SignedBundleFixture {
        service: key.to_z32(),
        public_key: *routing_key.public_key().as_bytes(),
        bundle: serde_json::to_string(&bundle).expect("serializable bundle"),
    }
}
