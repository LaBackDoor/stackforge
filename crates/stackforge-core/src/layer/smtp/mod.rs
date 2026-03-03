//! SMTP (Simple Mail Transfer Protocol) layer implementation.
//!
//! Implements RFC 5321 SMTP and RFC 1869 ESMTP packet parsing as a zero-copy
//! view into a packet buffer.
//!
//! ## Protocol Overview
//!
//! SMTP is a text-based protocol operating over TCP. Standard ports:
//! - **25**: MTA-to-MTA relay
//! - **587**: Client submission (RFC 6409)
//! - **465**: SMTPS (deprecated, but still widely used)
//!
//! ## Packet Format
//!
//! **Client Command:**
//! ```text
//! VERB [parameters]\r\n
//! ```
//!
//! **Server Reply:**
//! ```text
//! NNN<SP>text\r\n              (single-line)
//! NNN-text\r\n ... NNN<SP>text\r\n  (multi-line)
//! ```
//!
//! ## SMTP Commands (RFC 5321 §4.1)
//!
//! | Command    | Description                        |
//! |------------|------------------------------------|
//! | EHLO       | Extended HELLO (ESMTP)             |
//! | HELO       | HELLO                              |
//! | MAIL       | Begin mail transaction (FROM)      |
//! | RCPT       | Identify recipient (TO)            |
//! | DATA       | Begin message data                 |
//! | RSET       | Reset transaction                  |
//! | VRFY       | Verify address                     |
//! | EXPN       | Expand mailing list                |
//! | HELP       | Help information                   |
//! | NOOP       | No operation                       |
//! | QUIT       | Terminate connection               |
//! | AUTH       | Authenticate (RFC 4954)            |
//! | STARTTLS   | Start TLS negotiation (RFC 3207)   |

pub mod builder;
pub use builder::SmtpBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum SMTP payload size.
pub const SMTP_MIN_HEADER_LEN: usize = 4;

/// SMTP standard relay port.
pub const SMTP_PORT: u16 = 25;

/// SMTP submission port (RFC 6409).
pub const SMTP_SUBMISSION_PORT: u16 = 587;

/// SMTPS (over TLS) port.
pub const SMTPS_PORT: u16 = 465;

// ============================================================================
// SMTP Reply code constants (RFC 5321 §4.2)
// ============================================================================
pub const REPLY_SYSTEM_STATUS: u16 = 211;
pub const REPLY_HELP: u16 = 214;
pub const REPLY_SERVICE_READY: u16 = 220;
pub const REPLY_CLOSING: u16 = 221;
pub const REPLY_AUTH_SUCCESS: u16 = 235;
pub const REPLY_OK: u16 = 250;
pub const REPLY_USER_NOT_LOCAL: u16 = 251;
pub const REPLY_CANNOT_VRFY: u16 = 252;
pub const REPLY_AUTH_INPUT: u16 = 334;
pub const REPLY_DATA_INPUT: u16 = 354;
pub const REPLY_SERVICE_UNAVAIL: u16 = 421;
pub const REPLY_MAILBOX_UNAVAIL: u16 = 450;
pub const REPLY_LOCAL_ERROR: u16 = 451;
pub const REPLY_INSUFF_STORAGE: u16 = 452;
pub const REPLY_TEMP_AUTH_FAIL: u16 = 454;
pub const REPLY_CMD_UNRECOGNIZED: u16 = 500;
pub const REPLY_ARG_SYNTAX_ERROR: u16 = 501;
pub const REPLY_CMD_NOT_IMPL: u16 = 502;
pub const REPLY_BAD_CMD_SEQUENCE: u16 = 503;
pub const REPLY_CMD_NOT_IMPL_PARAM: u16 = 504;
pub const REPLY_AUTH_REQUIRED: u16 = 530;
pub const REPLY_AUTH_FAILED: u16 = 535;
pub const REPLY_MAILBOX_UNAVAIL_PERM: u16 = 550;
pub const REPLY_USER_NOT_LOCAL_PERM: u16 = 551;
pub const REPLY_EXCEED_STORAGE: u16 = 552;
pub const REPLY_MAILBOX_NAME_INVALID: u16 = 553;
pub const REPLY_TRANSACTION_FAILED: u16 = 554;

// ============================================================================
// SMTP Command verbs
// ============================================================================
pub const CMD_EHLO: &str = "EHLO";
pub const CMD_HELO: &str = "HELO";
pub const CMD_MAIL: &str = "MAIL";
pub const CMD_RCPT: &str = "RCPT";
pub const CMD_DATA: &str = "DATA";
pub const CMD_RSET: &str = "RSET";
pub const CMD_VRFY: &str = "VRFY";
pub const CMD_EXPN: &str = "EXPN";
pub const CMD_HELP: &str = "HELP";
pub const CMD_NOOP: &str = "NOOP";
pub const CMD_QUIT: &str = "QUIT";
pub const CMD_AUTH: &str = "AUTH";
pub const CMD_STARTTLS: &str = "STARTTLS";
pub const CMD_BDAT: &str = "BDAT";

pub static SMTP_COMMANDS: &[&str] = &[
    "EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN", "HELP", "NOOP", "QUIT", "AUTH",
    "STARTTLS", "BDAT",
];

/// Field names for Python/generic access.
pub static SMTP_FIELD_NAMES: &[&str] = &[
    "command",
    "args",
    "reply_code",
    "reply_text",
    "is_response",
    "is_multiline",
    "mailfrom",
    "rcptto",
    "raw",
];

// ============================================================================
// Payload detection
// ============================================================================

/// Returns true if `buf` looks like an SMTP control-connection payload.
#[must_use]
pub fn is_smtp_payload(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    // Check for SMTP reply (3-digit code)
    if buf[0].is_ascii_digit() && buf[1].is_ascii_digit() && buf[2].is_ascii_digit() {
        return buf.len() < 4 || matches!(buf[3], b' ' | b'-' | b'\r' | b'\n');
    }
    // Check for SMTP commands
    if let Ok(text) = std::str::from_utf8(buf) {
        let upper = text.to_ascii_uppercase();
        let first_word = upper.split_ascii_whitespace().next().unwrap_or("");
        return SMTP_COMMANDS.contains(&first_word);
    }
    false
}

// ============================================================================
// SmtpLayer - zero-copy view
// ============================================================================

/// A zero-copy view into an SMTP layer within a packet buffer.
#[must_use]
#[derive(Debug, Clone)]
pub struct SmtpLayer {
    pub index: LayerIndex,
}

impl SmtpLayer {
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Smtp, 0, len),
        }
    }

    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.index.end.min(buf.len());
        &buf[self.index.start..end]
    }

    fn first_line<'a>(&self, buf: &'a [u8]) -> &'a str {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s).unwrap_or("");
        text.lines().next().unwrap_or("").trim_end_matches('\r')
    }

    /// Returns true if this message is a server reply (3-digit code).
    pub fn is_response(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.len() >= 3 && s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit()
    }

    /// Returns true if this is a multi-line reply.
    pub fn is_multiline(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.len() >= 4
            && s[0].is_ascii_digit()
            && s[1].is_ascii_digit()
            && s[2].is_ascii_digit()
            && s[3] == b'-'
    }

    /// Returns the 3-digit reply code.
    pub fn reply_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 3,
                have: s.len(),
            });
        }
        if s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit() {
            Ok(u16::from(s[0] - b'0') * 100 + u16::from(s[1] - b'0') * 10 + u16::from(s[2] - b'0'))
        } else {
            Err(FieldError::InvalidValue(
                "reply_code: not a valid 3-digit reply code".into(),
            ))
        }
    }

    /// Returns the reply text (after the code and separator).
    pub fn reply_text(&self, buf: &[u8]) -> Result<String, FieldError> {
        let line = self.first_line(buf);
        if line.len() >= 4 {
            Ok(line[4..].to_string())
        } else if line.len() == 3 {
            Ok(String::new())
        } else {
            Err(FieldError::InvalidValue(
                "reply_text: invalid reply format".into(),
            ))
        }
    }

    /// Returns the command verb (for client commands).
    pub fn command(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("command: non-UTF8 payload".into()))?;
        let word = text.split_ascii_whitespace().next().unwrap_or("");
        Ok(word.to_ascii_uppercase())
    }

    /// Returns the command arguments.
    pub fn args(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("args: non-UTF8 payload".into()))?;
        let first_line = text.lines().next().unwrap_or("");
        let rest = first_line
            .splitn(2, ' ')
            .nth(1)
            .unwrap_or("")
            .trim_end_matches(|c| c == '\r' || c == '\n');
        Ok(rest.to_string())
    }

    /// Extracts the MAIL FROM address from a MAIL command.
    ///
    /// Input: `MAIL FROM:<user@example.com>`
    /// Output: `user@example.com`
    pub fn mailfrom(&self, buf: &[u8]) -> Result<String, FieldError> {
        let args = self.args(buf)?;
        let upper_args = args.to_ascii_uppercase();
        if !upper_args.starts_with("FROM:") {
            return Err(FieldError::InvalidValue(
                "mailfrom: not a MAIL FROM command".into(),
            ));
        }
        let addr_part = &args[5..]; // skip "FROM:"
        Ok(extract_angle_address(addr_part))
    }

    /// Extracts the RCPT TO address from a RCPT command.
    ///
    /// Input: `RCPT TO:<user@example.com>`
    /// Output: `user@example.com`
    pub fn rcptto(&self, buf: &[u8]) -> Result<String, FieldError> {
        let args = self.args(buf)?;
        let upper_args = args.to_ascii_uppercase();
        if !upper_args.starts_with("TO:") {
            return Err(FieldError::InvalidValue(
                "rcptto: not a RCPT TO command".into(),
            ));
        }
        let addr_part = &args[3..]; // skip "TO:"
        Ok(extract_angle_address(addr_part))
    }

    /// Returns the raw payload as a string.
    pub fn raw(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        String::from_utf8_lossy(s).to_string()
    }

    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "command" => Some(self.command(buf).map(FieldValue::Str)),
            "args" => Some(self.args(buf).map(FieldValue::Str)),
            "reply_code" => Some(self.reply_code(buf).map(FieldValue::U16)),
            "reply_text" => Some(self.reply_text(buf).map(FieldValue::Str)),
            "is_response" => Some(Ok(FieldValue::Bool(self.is_response(buf)))),
            "is_multiline" => Some(Ok(FieldValue::Bool(self.is_multiline(buf)))),
            "mailfrom" => Some(self.mailfrom(buf).map(FieldValue::Str)),
            "rcptto" => Some(self.rcptto(buf).map(FieldValue::Str)),
            "raw" => Some(Ok(FieldValue::Str(self.raw(buf)))),
            _ => None,
        }
    }
}

/// Extract an email address from angle brackets `<user@example.com>` or bare.
fn extract_angle_address(s: &str) -> String {
    let s = s.trim();
    if let (Some(start), Some(end)) = (s.find('<'), s.rfind('>')) {
        s[start + 1..end].to_string()
    } else {
        s.to_string()
    }
}

impl Layer for SmtpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Smtp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        let text = String::from_utf8_lossy(s);
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        format!("SMTP {}", first_line)
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.slice(buf).len()
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        if let Ok(code) = self.reply_code(buf) {
            code.to_be_bytes().to_vec()
        } else if let Ok(cmd) = self.command(buf) {
            cmd.into_bytes()
        } else {
            vec![]
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        SMTP_FIELD_NAMES
    }
}

/// Returns a human-readable display of SMTP layer fields.
pub fn smtp_show_fields(l: &SmtpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.is_response(buf) {
        if let Ok(code) = l.reply_code(buf) {
            fields.push(("reply_code", code.to_string()));
        }
        if let Ok(text) = l.reply_text(buf) {
            fields.push(("reply_text", text));
        }
        fields.push(("is_multiline", l.is_multiline(buf).to_string()));
    } else {
        if let Ok(cmd) = l.command(buf) {
            fields.push(("command", cmd));
        }
        if let Ok(args) = l.args(buf) {
            if !args.is_empty() {
                fields.push(("args", args));
            }
        }
    }
    fields
}

/// Returns a description for an SMTP reply code.
pub fn reply_code_description(code: u16) -> &'static str {
    match code {
        211 => "System status, or system help reply",
        214 => "Help message",
        220 => "Service ready",
        221 => "Service closing transmission channel",
        235 => "Authentication successful",
        250 => "Requested mail action okay, completed",
        251 => "User not local; will forward",
        252 => "Cannot VRFY user, but will accept message",
        334 => "Server challenge (AUTH)",
        354 => "Start mail input; end with <CRLF>.<CRLF>",
        421 => "Service not available, closing channel",
        450 => "Requested mail action not taken: mailbox unavailable",
        451 => "Requested action aborted: local error",
        452 => "Requested action not taken: insufficient storage",
        454 => "Temporary authentication failure",
        500 => "Syntax error, command unrecognized",
        501 => "Syntax error in parameters or arguments",
        502 => "Command not implemented",
        503 => "Bad sequence of commands",
        504 => "Command parameter not implemented",
        530 => "Authentication required",
        535 => "Authentication credentials invalid",
        550 => "Requested action not taken: mailbox unavailable",
        551 => "User not local; please try forwarding",
        552 => "Requested mail action aborted: exceeded storage allocation",
        553 => "Requested action not taken: mailbox name not allowed",
        554 => "Transaction failed",
        _ => "Unknown reply code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerIndex;

    fn make_layer(data: &[u8]) -> SmtpLayer {
        SmtpLayer::new(LayerIndex::new(LayerKind::Smtp, 0, data.len()))
    }

    #[test]
    fn test_smtp_detection_reply() {
        assert!(is_smtp_payload(b"220 mail.example.com ESMTP\r\n"));
        assert!(is_smtp_payload(b"250 OK\r\n"));
        assert!(is_smtp_payload(b"354 Start mail input\r\n"));
        assert!(is_smtp_payload(b"550 Mailbox not found\r\n"));
    }

    #[test]
    fn test_smtp_detection_command() {
        assert!(is_smtp_payload(b"EHLO example.com\r\n"));
        assert!(is_smtp_payload(b"MAIL FROM:<user@example.com>\r\n"));
        assert!(is_smtp_payload(b"RCPT TO:<dest@example.com>\r\n"));
        assert!(is_smtp_payload(b"DATA\r\n"));
        assert!(is_smtp_payload(b"QUIT\r\n"));
    }

    #[test]
    fn test_smtp_detection_negative() {
        assert!(!is_smtp_payload(b""));
        assert!(!is_smtp_payload(b"GET / HTTP/1.1"));
        assert!(!is_smtp_payload(b"\x00\x01"));
    }

    #[test]
    fn test_smtp_layer_reply() {
        let data = b"220 mail.example.com ESMTP Postfix\r\n";
        let layer = make_layer(data);
        assert!(layer.is_response(data));
        assert_eq!(layer.reply_code(data).unwrap(), 220);
        assert!(layer.reply_text(data).unwrap().contains("ESMTP"));
    }

    #[test]
    fn test_smtp_layer_multiline() {
        let data = b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n";
        let layer = make_layer(data);
        assert!(layer.is_multiline(data));
        assert_eq!(layer.reply_code(data).unwrap(), 250);
    }

    #[test]
    fn test_smtp_layer_command() {
        let data = b"EHLO client.example.com\r\n";
        let layer = make_layer(data);
        assert!(!layer.is_response(data));
        assert_eq!(layer.command(data).unwrap(), "EHLO");
        assert_eq!(layer.args(data).unwrap(), "client.example.com");
    }

    #[test]
    fn test_smtp_layer_mail_from() {
        let data = b"MAIL FROM:<sender@example.com>\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "MAIL");
        assert_eq!(layer.mailfrom(data).unwrap(), "sender@example.com");
    }

    #[test]
    fn test_smtp_layer_rcpt_to() {
        let data = b"RCPT TO:<recipient@example.com>\r\n";
        let layer = make_layer(data);
        assert_eq!(layer.command(data).unwrap(), "RCPT");
        assert_eq!(layer.rcptto(data).unwrap(), "recipient@example.com");
    }

    #[test]
    fn test_smtp_field_access() {
        let data = b"250 OK\r\n";
        let layer = make_layer(data);
        assert!(matches!(
            layer.get_field(data, "reply_code"),
            Some(Ok(FieldValue::U16(250)))
        ));
        assert!(matches!(
            layer.get_field(data, "is_response"),
            Some(Ok(FieldValue::Bool(true)))
        ));
        assert!(layer.get_field(data, "nonexistent").is_none());
    }

    #[test]
    fn test_smtp_extract_angle_address() {
        assert_eq!(
            extract_angle_address("<user@example.com>"),
            "user@example.com"
        );
        assert_eq!(
            extract_angle_address("user@example.com"),
            "user@example.com"
        );
        assert_eq!(
            extract_angle_address(" <user@example.com> "),
            "user@example.com"
        );
    }
}
