#![no_main]
use libfuzzer_sys::fuzz_target;
use stackforge_core::layer::tls::{is_tls_payload, TlsLayer};
use stackforge_core::layer::tls::{ClientHello, ServerHello, Handshake, Certificate};
use stackforge_core::layer::tls::{Sslv2ClientHello, Sslv2ServerHello, Sslv2ClientMasterKey};
use stackforge_core::layer::LayerIndex;
use stackforge_core::layer::LayerKind;

fuzz_target!(|data: &[u8]| {
    // TLS detection heuristic
    let _ = is_tls_payload(data);

    // TLS record layer field accessors
    if data.len() >= 5 {
        let tls = TlsLayer {
            index: LayerIndex::new(LayerKind::Tls, 0, data.len()),
        };
        let _ = tls.content_type(data);
        let _ = tls.version(data);
        let _ = tls.length(data);
        let _ = tls.fragment(data);
    }

    // TLS handshake parsing — complex nested structures
    let _ = Handshake::parse(data);
    let _ = ClientHello::parse(data);
    let _ = ServerHello::parse(data);
    let _ = Certificate::parse(data);

    // SSLv2 handshake parsing
    let _ = Sslv2ClientHello::parse(data);
    let _ = Sslv2ServerHello::parse(data);
    let _ = Sslv2ClientMasterKey::parse(data);
});
