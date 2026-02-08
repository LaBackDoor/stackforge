//! SSH compatibility tests with Scapy.
//!
//! Note: SSH compat testing is limited since SSH binary packets require
//! encryption context. We test version exchange which is plaintext.

use super::scapy_build;
use stackforge_core::SshBuilder;

#[test]
fn test_ssh_version_exchange_format() {
    // Verify that our version exchange format matches the SSH protocol spec
    let builder = SshBuilder::version_exchange("OpenSSH_9.2p1");
    let bytes = builder.build();

    // Should match "SSH-2.0-OpenSSH_9.2p1\r\n"
    assert!(bytes.starts_with(b"SSH-2.0-"));
    assert!(bytes.ends_with(b"\r\n"));
    assert_eq!(bytes, b"SSH-2.0-OpenSSH_9.2p1\r\n");
}

#[test]
fn test_ssh_version_exchange_vs_scapy() {
    // Build SSH version exchange with Scapy
    // scapy_build expects a single expression, so we use __import__ inline
    let scapy_bytes = scapy_build(
        r#"__import__("scapy.layers.ssh", fromlist=["SSHVersionExchange"]).SSHVersionExchange(lines=[b"SSH-2.0-OpenSSH_9.2p1"])"#,
    );

    // Our version exchange
    let sf_bytes = SshBuilder::version_exchange("OpenSSH_9.2p1").build();

    // Both should produce SSH-2.0-OpenSSH_9.2p1\r\n
    assert_eq!(
        sf_bytes,
        scapy_bytes,
        "Stackforge: {:?}\nScapy: {:?}",
        String::from_utf8_lossy(&sf_bytes),
        String::from_utf8_lossy(&scapy_bytes),
    );
}
