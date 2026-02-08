//! SSH layer builder.
//!
//! Provides a minimal builder for SSH version exchange messages.
//! Full SSH binary packet construction is not supported since SSH
//! requires encryption context for most operations.

/// Builder for SSH layer data.
///
/// Currently supports building SSH version exchange messages.
/// Binary SSH packets require encryption and are not constructable.
#[derive(Debug, Clone)]
pub struct SshBuilder {
    /// Version string (e.g., "OpenSSH_9.2p1")
    version: String,
}

impl Default for SshBuilder {
    fn default() -> Self {
        Self {
            version: "stackforge".to_string(),
        }
    }
}

impl SshBuilder {
    /// Create a new SSH builder with default version string.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an SSH version exchange message.
    ///
    /// Generates `SSH-2.0-{version}\r\n`.
    pub fn version_exchange(version: &str) -> Self {
        Self {
            version: version.to_string(),
        }
    }

    /// Set the version string.
    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    /// Get the header size (the full version exchange message length).
    pub fn header_size(&self) -> usize {
        // "SSH-2.0-" + version + "\r\n"
        8 + self.version.len() + 2
    }

    /// Build the SSH version exchange into bytes.
    pub fn build(&self) -> Vec<u8> {
        format!("SSH-2.0-{}\r\n", self.version).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exchange_build() {
        let builder = SshBuilder::version_exchange("OpenSSH_9.2p1");
        let bytes = builder.build();
        assert_eq!(bytes, b"SSH-2.0-OpenSSH_9.2p1\r\n");
    }

    #[test]
    fn test_default_version() {
        let builder = SshBuilder::new();
        let bytes = builder.build();
        assert_eq!(bytes, b"SSH-2.0-stackforge\r\n");
    }

    #[test]
    fn test_header_size() {
        let builder = SshBuilder::version_exchange("test");
        assert_eq!(builder.header_size(), builder.build().len());
    }
}
