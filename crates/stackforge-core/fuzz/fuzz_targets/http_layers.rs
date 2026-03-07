#![no_main]
use libfuzzer_sys::fuzz_target;
use stackforge_core::layer::http::detection;
use stackforge_core::layer::http::request::HttpRequest;
use stackforge_core::layer::http::response::HttpResponse;
use stackforge_core::layer::http2::frames::{Http2Frame, parse_all_frames, parse_settings};
use stackforge_core::layer::http2::hpack::HpackDecoder;

fuzz_target!(|data: &[u8]| {
    // HTTP/1.x detection and parsing
    let _ = detection::is_http(data);
    let _ = HttpRequest::parse(data);
    let _ = HttpResponse::parse(data);

    // HTTP/2 frame parsing
    let _ = Http2Frame::parse_at(data, 0);
    let _ = parse_all_frames(data);
    let _ = parse_settings(data);

    // HPACK Huffman + header decoding — complex state machine, high-value target
    let mut decoder = HpackDecoder::new();
    let _ = decoder.decode(data);
});
