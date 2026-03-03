//! POP3 packet builder.
//!
//! Provides a fluent API for constructing POP3 command and reply payloads.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::pop3::builder::Pop3Builder;
//!
//! // Build a USER command
//! let pkt = Pop3Builder::new().user("alice").build();
//! assert_eq!(pkt, b"USER alice\r\n");
//!
//! // Build a +OK response
//! let pkt = Pop3Builder::new().ok("POP3 server ready").build();
//! assert_eq!(pkt, b"+OK POP3 server ready\r\n");
//! ```

/// Builder for POP3 messages (commands and replies).
#[must_use]
#[derive(Debug, Clone)]
pub struct Pop3Builder {
    /// If true, build a +OK reply; if false, -ERR; if None, build a command.
    is_reply: Option<bool>,
    command: Option<String>,
    text: String,
    /// Additional lines for multi-line responses (terminated by "." line).
    body_lines: Vec<String>,
}

impl Default for Pop3Builder {
    fn default() -> Self {
        Self {
            is_reply: None,
            command: Some("NOOP".to_string()),
            text: String::new(),
            body_lines: Vec::new(),
        }
    }
}

impl Pop3Builder {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Reply builders (server-side)
    // ========================================================================

    /// Build a +OK response.
    pub fn ok(mut self, text: impl Into<String>) -> Self {
        self.is_reply = Some(true);
        self.command = None;
        self.text = text.into();
        self.body_lines.clear();
        self
    }

    /// Build a -ERR response.
    pub fn err(mut self, text: impl Into<String>) -> Self {
        self.is_reply = Some(false);
        self.command = None;
        self.text = text.into();
        self.body_lines.clear();
        self
    }

    /// Build a +OK response with a multi-line body.
    ///
    /// The body is terminated by a `.\r\n` line automatically.
    pub fn ok_multiline(mut self, header: impl Into<String>, lines: Vec<String>) -> Self {
        self.is_reply = Some(true);
        self.command = None;
        self.text = header.into();
        self.body_lines = lines;
        self
    }

    /// +OK POP3 server ready (server greeting).
    pub fn server_ready(self) -> Self {
        self.ok("POP3 server ready")
    }

    /// +OK after successful USER.
    pub fn user_accepted(self) -> Self {
        self.ok("Password required")
    }

    /// +OK after successful PASS.
    pub fn logged_in(self) -> Self {
        self.ok("logged in")
    }

    /// +OK nmsgs octets (STAT response).
    pub fn stat_reply(self, num_msgs: u32, total_size: u64) -> Self {
        let text = format!("{num_msgs} {total_size}");
        self.ok(text)
    }

    /// +OK with message list (LIST response, multi-line).
    pub fn list_reply(self, messages: Vec<(u32, u64)>) -> Self {
        let header = format!("{} messages", messages.len());
        let lines = messages
            .into_iter()
            .map(|(num, size)| format!("{num} {size}"))
            .collect();
        self.ok_multiline(header, lines)
    }

    /// -ERR Unknown command.
    pub fn unknown_command(self) -> Self {
        self.err("Unknown command")
    }

    /// -ERR Permission denied.
    pub fn permission_denied(self) -> Self {
        self.err("Permission denied")
    }

    // ========================================================================
    // Command builders (client-side)
    // ========================================================================

    fn command(mut self, verb: impl Into<String>, args: impl Into<String>) -> Self {
        self.command = Some(verb.into().to_ascii_uppercase());
        self.is_reply = None;
        self.text = args.into();
        self.body_lines.clear();
        self
    }

    /// USER <username>
    pub fn user(self, username: impl Into<String>) -> Self {
        self.command("USER", username)
    }

    /// PASS <password>
    pub fn pass(self, password: impl Into<String>) -> Self {
        self.command("PASS", password)
    }

    /// QUIT
    pub fn quit(self) -> Self {
        self.command("QUIT", "")
    }

    /// STAT
    pub fn stat(self) -> Self {
        self.command("STAT", "")
    }

    /// LIST [msg]
    pub fn list(self, msg: Option<u32>) -> Self {
        let args = msg.map(|n| n.to_string()).unwrap_or_default();
        self.command("LIST", args)
    }

    /// RETR <msg>
    pub fn retr(self, msg: u32) -> Self {
        self.command("RETR", msg.to_string())
    }

    /// DELE <msg>
    pub fn dele(self, msg: u32) -> Self {
        self.command("DELE", msg.to_string())
    }

    /// NOOP
    pub fn noop(self) -> Self {
        self.command("NOOP", "")
    }

    /// RSET
    pub fn rset(self) -> Self {
        self.command("RSET", "")
    }

    /// TOP <msg> <n> (retrieve header + first n body lines)
    pub fn top(self, msg: u32, lines: u32) -> Self {
        let args = format!("{msg} {lines}");
        self.command("TOP", args)
    }

    /// UIDL [msg]
    pub fn uidl(self, msg: Option<u32>) -> Self {
        let args = msg.map(|n| n.to_string()).unwrap_or_default();
        self.command("UIDL", args)
    }

    /// APOP <name> <digest>
    pub fn apop(self, name: impl Into<String>, digest: impl Into<String>) -> Self {
        let args = format!("{} {}", name.into(), digest.into());
        self.command("APOP", args)
    }

    /// CAPA (list capabilities, RFC 2449)
    pub fn capa(self) -> Self {
        self.command("CAPA", "")
    }

    /// AUTH [mechanism]
    pub fn auth(self, mechanism: impl Into<String>) -> Self {
        self.command("AUTH", mechanism)
    }

    /// STLS (start TLS, RFC 2595)
    pub fn stls(self) -> Self {
        self.command("STLS", "")
    }

    // ========================================================================
    // Build
    // ========================================================================

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        match self.is_reply {
            Some(true) => self.build_ok(),
            Some(false) => self.build_err(),
            None => self.build_command(),
        }
    }

    fn build_ok(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.text.is_empty() {
            out.extend_from_slice(b"+OK\r\n");
        } else {
            out.extend_from_slice(format!("+OK {}\r\n", self.text).as_bytes());
        }
        if !self.body_lines.is_empty() {
            for line in &self.body_lines {
                // Byte-stuff lines starting with "."
                if line.starts_with('.') {
                    out.extend_from_slice(format!(".{line}\r\n").as_bytes());
                } else {
                    out.extend_from_slice(format!("{line}\r\n").as_bytes());
                }
            }
            out.extend_from_slice(b".\r\n"); // terminator
        }
        out
    }

    fn build_err(&self) -> Vec<u8> {
        if self.text.is_empty() {
            b"-ERR\r\n".to_vec()
        } else {
            format!("-ERR {}\r\n", self.text).into_bytes()
        }
    }

    fn build_command(&self) -> Vec<u8> {
        let verb = self.command.as_deref().unwrap_or("NOOP");
        let args = &self.text;
        let line = if args.is_empty() {
            format!("{verb}\r\n")
        } else {
            format!("{verb} {args}\r\n")
        };
        line.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_noop() {
        let pkt = Pop3Builder::new().noop().build();
        assert_eq!(pkt, b"NOOP\r\n");
    }

    #[test]
    fn test_build_user() {
        let pkt = Pop3Builder::new().user("alice").build();
        assert_eq!(pkt, b"USER alice\r\n");
    }

    #[test]
    fn test_build_pass() {
        let pkt = Pop3Builder::new().pass("secret").build();
        assert_eq!(pkt, b"PASS secret\r\n");
    }

    #[test]
    fn test_build_ok() {
        let pkt = Pop3Builder::new().ok("POP3 server ready").build();
        assert_eq!(pkt, b"+OK POP3 server ready\r\n");
    }

    #[test]
    fn test_build_err() {
        let pkt = Pop3Builder::new().err("Permission denied").build();
        assert_eq!(pkt, b"-ERR Permission denied\r\n");
    }

    #[test]
    fn test_build_stat_reply() {
        let pkt = Pop3Builder::new().stat_reply(3, 1024).build();
        assert_eq!(pkt, b"+OK 3 1024\r\n");
    }

    #[test]
    fn test_build_list_reply_multiline() {
        let pkt = Pop3Builder::new()
            .list_reply(vec![(1, 512), (2, 1024)])
            .build();
        let s = String::from_utf8(pkt).unwrap();
        assert!(s.starts_with("+OK 2 messages\r\n"));
        assert!(s.contains("1 512\r\n"));
        assert!(s.contains("2 1024\r\n"));
        assert!(s.ends_with(".\r\n"));
    }

    #[test]
    fn test_build_retr() {
        let pkt = Pop3Builder::new().retr(1).build();
        assert_eq!(pkt, b"RETR 1\r\n");
    }

    #[test]
    fn test_build_dele() {
        let pkt = Pop3Builder::new().dele(3).build();
        assert_eq!(pkt, b"DELE 3\r\n");
    }

    #[test]
    fn test_build_top() {
        let pkt = Pop3Builder::new().top(1, 5).build();
        assert_eq!(pkt, b"TOP 1 5\r\n");
    }

    #[test]
    fn test_build_quit() {
        let pkt = Pop3Builder::new().quit().build();
        assert_eq!(pkt, b"QUIT\r\n");
    }

    #[test]
    fn test_build_list_no_arg() {
        let pkt = Pop3Builder::new().list(None).build();
        assert_eq!(pkt, b"LIST\r\n");
    }

    #[test]
    fn test_build_list_with_arg() {
        let pkt = Pop3Builder::new().list(Some(5)).build();
        assert_eq!(pkt, b"LIST 5\r\n");
    }
}
