//! SMTP packet builder.
//!
//! Provides a fluent API for constructing SMTP commands and replies.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::smtp::builder::SmtpBuilder;
//!
//! // Build an EHLO command
//! let pkt = SmtpBuilder::new().ehlo("client.example.com").build();
//! assert_eq!(pkt, b"EHLO client.example.com\r\n");
//!
//! // Build a 250 OK reply
//! let pkt = SmtpBuilder::new().ok("OK").build();
//! assert_eq!(pkt, b"250 OK\r\n");
//! ```

/// Builder for SMTP messages (commands and replies).
#[must_use]
#[derive(Debug, Clone)]
pub struct SmtpBuilder {
    reply_code: Option<u16>,
    command: Option<String>,
    text: String,
    multiline: bool,
    extra_lines: Vec<String>,
}

impl Default for SmtpBuilder {
    fn default() -> Self {
        Self {
            reply_code: None,
            command: Some("NOOP".to_string()),
            text: String::new(),
            multiline: false,
            extra_lines: Vec::new(),
        }
    }
}

impl SmtpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Reply builders (server-side)
    // ========================================================================

    pub fn reply(mut self, code: u16, text: impl Into<String>) -> Self {
        self.reply_code = Some(code);
        self.command = None;
        self.text = text.into();
        self
    }

    pub fn multiline(mut self, lines: Vec<String>) -> Self {
        self.multiline = true;
        self.extra_lines = lines;
        self
    }

    /// 220 Service ready (server greeting).
    pub fn service_ready(self, domain: impl Into<String>) -> Self {
        let text = format!("{} ESMTP", domain.into());
        self.reply(220, text)
    }

    /// 221 Closing connection.
    pub fn closing(self) -> Self {
        self.reply(221, "Bye")
    }

    /// 235 Authentication successful.
    pub fn auth_success(self) -> Self {
        self.reply(235, "Authentication successful")
    }

    /// 250 OK (single-line).
    pub fn ok(self, text: impl Into<String>) -> Self {
        self.reply(250, text)
    }

    /// 250 OK (multi-line, EHLO response).
    pub fn ehlo_response(mut self, domain: impl Into<String>, extensions: Vec<String>) -> Self {
        self.reply_code = Some(250);
        self.command = None;
        self.multiline = true;
        self.text = domain.into();
        self.extra_lines = extensions;
        self
    }

    /// 334 Server challenge (AUTH).
    pub fn auth_challenge(self, challenge: impl Into<String>) -> Self {
        self.reply(334, challenge)
    }

    /// 354 Start mail input.
    pub fn start_mail_input(self) -> Self {
        self.reply(354, "Start mail input; end with <CRLF>.<CRLF>")
    }

    /// 421 Service unavailable.
    pub fn service_unavailable(self) -> Self {
        self.reply(421, "Service not available")
    }

    /// 450 Mailbox temporarily unavailable.
    pub fn mailbox_temp_unavailable(self, text: impl Into<String>) -> Self {
        self.reply(450, text)
    }

    /// 530 Authentication required.
    pub fn auth_required(self) -> Self {
        self.reply(530, "Authentication required")
    }

    /// 535 Authentication failed.
    pub fn auth_failed(self) -> Self {
        self.reply(535, "Authentication credentials invalid")
    }

    /// 550 Mailbox not found.
    pub fn mailbox_not_found(self, text: impl Into<String>) -> Self {
        self.reply(550, text)
    }

    // ========================================================================
    // Command builders (client-side)
    // ========================================================================

    pub fn command(mut self, verb: impl Into<String>, args: impl Into<String>) -> Self {
        self.command = Some(verb.into().to_ascii_uppercase());
        self.reply_code = None;
        self.text = args.into();
        self
    }

    /// EHLO <domain> (Extended HELLO, RFC 5321)
    pub fn ehlo(self, domain: impl Into<String>) -> Self {
        self.command("EHLO", domain)
    }

    /// HELO <domain>
    pub fn helo(self, domain: impl Into<String>) -> Self {
        self.command("HELO", domain)
    }

    /// MAIL FROM:<address>
    pub fn mail_from(self, address: impl Into<String>) -> Self {
        let addr = address.into();
        let args = if addr.contains('<') {
            format!("FROM:{addr}")
        } else {
            format!("FROM:<{addr}>")
        };
        self.command("MAIL", args)
    }

    /// RCPT TO:<address>
    pub fn rcpt_to(self, address: impl Into<String>) -> Self {
        let addr = address.into();
        let args = if addr.contains('<') {
            format!("TO:{addr}")
        } else {
            format!("TO:<{addr}>")
        };
        self.command("RCPT", args)
    }

    /// DATA (begin message body input)
    pub fn data(self) -> Self {
        self.command("DATA", "")
    }

    /// RSET (reset transaction)
    pub fn rset(self) -> Self {
        self.command("RSET", "")
    }

    /// VRFY <address>
    pub fn vrfy(self, address: impl Into<String>) -> Self {
        self.command("VRFY", address)
    }

    /// EXPN <list>
    pub fn expn(self, list: impl Into<String>) -> Self {
        self.command("EXPN", list)
    }

    /// HELP [command]
    pub fn help(self, topic: impl Into<String>) -> Self {
        self.command("HELP", topic)
    }

    /// NOOP
    pub fn noop(self) -> Self {
        self.command("NOOP", "")
    }

    /// QUIT
    pub fn quit(self) -> Self {
        self.command("QUIT", "")
    }

    /// AUTH <mechanism> [initial-response]
    pub fn auth(self, mechanism: impl Into<String>, initial_resp: impl Into<String>) -> Self {
        let mech = mechanism.into();
        let init = initial_resp.into();
        let args = if init.is_empty() {
            mech
        } else {
            format!("{mech} {init}")
        };
        self.command("AUTH", args)
    }

    /// STARTTLS (upgrade to TLS, RFC 3207)
    pub fn starttls(self) -> Self {
        self.command("STARTTLS", "")
    }

    // ========================================================================
    // Build
    // ========================================================================

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        if let Some(code) = self.reply_code {
            self.build_reply(code)
        } else {
            self.build_command()
        }
    }

    fn build_reply(&self, code: u16) -> Vec<u8> {
        let mut out = Vec::new();
        if self.multiline {
            out.extend_from_slice(format!("{:03}-{}\r\n", code, self.text).as_bytes());
            for line in &self.extra_lines {
                // Multi-line: intermediate lines use NNN-
                out.extend_from_slice(format!("{code:03}-{line}\r\n").as_bytes());
            }
            // Last line uses space separator
            out.extend_from_slice(format!("{code:03} OK\r\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{:03} {}\r\n", code, self.text).as_bytes());
        }
        out
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
        let pkt = SmtpBuilder::new().noop().build();
        assert_eq!(pkt, b"NOOP\r\n");
    }

    #[test]
    fn test_build_ehlo() {
        let pkt = SmtpBuilder::new().ehlo("client.example.com").build();
        assert_eq!(pkt, b"EHLO client.example.com\r\n");
    }

    #[test]
    fn test_build_mail_from() {
        let pkt = SmtpBuilder::new().mail_from("user@example.com").build();
        assert_eq!(pkt, b"MAIL FROM:<user@example.com>\r\n");
    }

    #[test]
    fn test_build_rcpt_to() {
        let pkt = SmtpBuilder::new().rcpt_to("dest@example.com").build();
        assert_eq!(pkt, b"RCPT TO:<dest@example.com>\r\n");
    }

    #[test]
    fn test_build_data_command() {
        let pkt = SmtpBuilder::new().data().build();
        assert_eq!(pkt, b"DATA\r\n");
    }

    #[test]
    fn test_build_quit() {
        let pkt = SmtpBuilder::new().quit().build();
        assert_eq!(pkt, b"QUIT\r\n");
    }

    #[test]
    fn test_build_service_ready() {
        let pkt = SmtpBuilder::new().service_ready("mail.example.com").build();
        assert_eq!(pkt, b"220 mail.example.com ESMTP\r\n");
    }

    #[test]
    fn test_build_ok() {
        let pkt = SmtpBuilder::new().ok("OK").build();
        assert_eq!(pkt, b"250 OK\r\n");
    }

    #[test]
    fn test_build_start_mail_input() {
        let pkt = SmtpBuilder::new().start_mail_input().build();
        assert_eq!(pkt, b"354 Start mail input; end with <CRLF>.<CRLF>\r\n");
    }

    #[test]
    fn test_build_ehlo_multiline_response() {
        let pkt = SmtpBuilder::new()
            .ehlo_response(
                "mail.example.com",
                vec![
                    "PIPELINING".to_string(),
                    "SIZE 10485760".to_string(),
                    "AUTH LOGIN PLAIN".to_string(),
                ],
            )
            .build();
        let s = String::from_utf8(pkt).unwrap();
        assert!(s.starts_with("250-mail.example.com\r\n"));
        assert!(s.contains("250-PIPELINING\r\n"));
        assert!(s.contains("250-SIZE 10485760\r\n"));
        assert!(s.ends_with("250 OK\r\n"));
    }

    #[test]
    fn test_build_auth() {
        let pkt = SmtpBuilder::new().auth("LOGIN", "").build();
        assert_eq!(pkt, b"AUTH LOGIN\r\n");
    }

    #[test]
    fn test_build_starttls() {
        let pkt = SmtpBuilder::new().starttls().build();
        assert_eq!(pkt, b"STARTTLS\r\n");
    }
}
