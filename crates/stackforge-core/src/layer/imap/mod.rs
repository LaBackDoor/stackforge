//! IMAP (Internet Message Access Protocol) layer implementation.
//!
//! Implements RFC 3501 `IMAP4rev1` packet parsing as a zero-copy view into a packet buffer.
//!
//! ## Protocol Overview
//!
//! IMAP operates over TCP port 143 (993 for IMAPS).
//! Unlike POP3, IMAP keeps messages on the server and supports folders,
//! multiple clients, and partial message fetching.
//!
//! ## Message Format
//!
//! **Client Command:**
//! ```text
//! tag COMMAND [arguments]\r\n
//! ```
//! Where `tag` is an alphanumeric identifier assigned by the client (e.g., "A001").
//!
//! **Server Untagged Response (data/status):**
//! ```text
//! * STATUS [data]\r\n
//! * NUMBER TYPE [data]\r\n
//! ```
//!
//! **Server Tagged Response (command completion):**
//! ```text
//! tag OK [text]\r\n
//! tag NO [text]\r\n
//! tag BAD [text]\r\n
//! ```
//!
//! **Server Continuation Request:**
//! ```text
//! + [text]\r\n
//! ```
//!
//! ## Server Response Status Codes
//!
//! | Code     | Meaning                              |
//! |----------|--------------------------------------|
//! | OK       | Command completed successfully       |
//! | NO       | Command failed                       |
//! | BAD      | Protocol error                       |
//! | BYE      | Server closing connection            |
//! | PREAUTH  | Already authenticated                |
//!
//! ## Common IMAP Commands (RFC 3501)
//!
//! | Command      | State | Description                        |
//! |--------------|-------|------------------------------------|
//! | CAPABILITY   | Any   | List server capabilities           |
//! | NOOP         | Any   | No-op                              |
//! | LOGOUT       | Any   | End session                        |
//! | AUTHENTICATE | NonAuth| SASL authentication               |
//! | LOGIN        | NonAuth| Plaintext login                   |
//! | STARTTLS     | NonAuth| TLS upgrade (RFC 2595)            |
//! | SELECT       | Auth  | Select mailbox (read-write)        |
//! | EXAMINE      | Auth  | Select mailbox (read-only)         |
//! | CREATE       | Auth  | Create mailbox                     |
//! | DELETE       | Auth  | Delete mailbox                     |
//! | RENAME       | Auth  | Rename mailbox                     |
//! | SUBSCRIBE    | Auth  | Add to subscription list           |
//! | UNSUBSCRIBE  | Auth  | Remove from subscription list      |
//! | LIST         | Auth  | List mailboxes                     |
//! | LSUB         | Auth  | List subscribed mailboxes          |
//! | STATUS       | Auth  | Request mailbox status             |
//! | APPEND       | Auth  | Append message to mailbox          |
//! | CHECK        | Select| Checkpoint mailbox                 |
//! | CLOSE        | Select| Close selected mailbox             |
//! | EXPUNGE      | Select| Remove deleted messages            |
//! | SEARCH       | Select| Search messages                    |
//! | FETCH        | Select| Retrieve message data              |
//! | STORE        | Select| Alter message flags                |
//! | COPY         | Select| Copy messages to another mailbox  |
//! | UID          | Select| UID variant of COPY/FETCH/SEARCH/STORE|

pub mod builder;
pub use builder::ImapBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum IMAP payload size.
pub const IMAP_MIN_HEADER_LEN: usize = 4;

/// IMAP standard port.
pub const IMAP_PORT: u16 = 143;

/// IMAPS (over TLS) port.
pub const IMAPS_PORT: u16 = 993;

// ============================================================================
// IMAP command names
// ============================================================================
pub const CMD_CAPABILITY: &str = "CAPABILITY";
pub const CMD_NOOP: &str = "NOOP";
pub const CMD_LOGOUT: &str = "LOGOUT";
pub const CMD_AUTHENTICATE: &str = "AUTHENTICATE";
pub const CMD_LOGIN: &str = "LOGIN";
pub const CMD_STARTTLS: &str = "STARTTLS";
pub const CMD_SELECT: &str = "SELECT";
pub const CMD_EXAMINE: &str = "EXAMINE";
pub const CMD_CREATE: &str = "CREATE";
pub const CMD_DELETE: &str = "DELETE";
pub const CMD_RENAME: &str = "RENAME";
pub const CMD_SUBSCRIBE: &str = "SUBSCRIBE";
pub const CMD_UNSUBSCRIBE: &str = "UNSUBSCRIBE";
pub const CMD_LIST: &str = "LIST";
pub const CMD_LSUB: &str = "LSUB";
pub const CMD_STATUS: &str = "STATUS";
pub const CMD_APPEND: &str = "APPEND";
pub const CMD_CHECK: &str = "CHECK";
pub const CMD_CLOSE: &str = "CLOSE";
pub const CMD_EXPUNGE: &str = "EXPUNGE";
pub const CMD_SEARCH: &str = "SEARCH";
pub const CMD_FETCH: &str = "FETCH";
pub const CMD_STORE: &str = "STORE";
pub const CMD_COPY: &str = "COPY";
pub const CMD_UID: &str = "UID";

pub static IMAP_COMMANDS: &[&str] = &[
    "CAPABILITY",
    "NOOP",
    "LOGOUT",
    "AUTHENTICATE",
    "LOGIN",
    "STARTTLS",
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
];

/// IMAP tagged response status strings.
pub const STATUS_OK: &str = "OK";
pub const STATUS_NO: &str = "NO";
pub const STATUS_BAD: &str = "BAD";
pub const STATUS_BYE: &str = "BYE";
pub const STATUS_PREAUTH: &str = "PREAUTH";

/// Field names for Python/generic access.
pub static IMAP_FIELD_NAMES: &[&str] = &[
    "tag",
    "command",
    "args",
    "status",
    "text",
    "is_untagged",
    "is_continuation",
    "is_tagged_response",
    "is_client_command",
    "raw",
];

// ============================================================================
// Payload detection
// ============================================================================

/// Returns true if `buf` looks like an IMAP payload.
#[must_use]
pub fn is_imap_payload(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    // Untagged response: "* "
    if buf.starts_with(b"* ") {
        return true;
    }
    // Continuation: "+ "
    if buf.starts_with(b"+ ") || buf == b"+\r\n" || buf == b"+ \r\n" {
        return true;
    }
    // Check for tagged command or tagged response
    if let Ok(text) = std::str::from_utf8(buf) {
        let first_line = text.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            let tag = parts[0];
            let cmd_or_status = parts[1].to_ascii_uppercase();
            // Tag should be alphanumeric
            if !tag.is_empty() && tag.chars().all(|c| c.is_ascii_alphanumeric()) {
                // It's a tagged response: tag + status
                if matches!(
                    cmd_or_status.as_str(),
                    "OK" | "NO" | "BAD" | "BYE" | "PREAUTH"
                ) {
                    return true;
                }
                // It's a client command: tag + COMMAND
                if IMAP_COMMANDS.contains(&cmd_or_status.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

// ============================================================================
// ImapLayer - zero-copy view
// ============================================================================

/// A zero-copy view into an IMAP layer within a packet buffer.
#[must_use]
#[derive(Debug, Clone)]
pub struct ImapLayer {
    pub index: LayerIndex,
}

impl ImapLayer {
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Imap, 0, len),
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

    /// Returns true if this is an untagged server response (starts with "* ").
    #[must_use]
    pub fn is_untagged(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.starts_with(b"* ")
    }

    /// Returns true if this is a continuation request (starts with "+ ").
    #[must_use]
    pub fn is_continuation(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        s.starts_with(b"+ ")
    }

    /// Returns true if this is a tagged server response.
    #[must_use]
    pub fn is_tagged_response(&self, buf: &[u8]) -> bool {
        if self.is_untagged(buf) || self.is_continuation(buf) {
            return false;
        }
        let line = self.first_line(buf);
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return false;
        }
        let status = parts[1].to_ascii_uppercase();
        matches!(status.as_str(), "OK" | "NO" | "BAD" | "BYE" | "PREAUTH")
    }

    /// Returns true if this is a client command.
    #[must_use]
    pub fn is_client_command(&self, buf: &[u8]) -> bool {
        if self.is_untagged(buf) || self.is_continuation(buf) {
            return false;
        }
        let line = self.first_line(buf);
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return false;
        }
        let cmd = parts[1].to_ascii_uppercase();
        IMAP_COMMANDS.contains(&cmd.as_str())
    }

    /// Returns the tag from a tagged command or response.
    ///
    /// Returns "*" for untagged, "+" for continuation.
    pub fn tag(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        if s.starts_with(b"* ") {
            return Ok("*".to_string());
        }
        if s.starts_with(b"+ ") {
            return Ok("+".to_string());
        }
        let text = std::str::from_utf8(s)
            .map_err(|_| FieldError::InvalidValue("tag: non-UTF8 payload".into()))?;
        let tag = text.split_ascii_whitespace().next().unwrap_or("");
        Ok(tag.to_string())
    }

    /// Returns the command verb for a client command.
    pub fn command(&self, buf: &[u8]) -> Result<String, FieldError> {
        let line = self.first_line(buf);
        // Untagged: "* <number> <command> ..." or "* <status> ..."
        if let Some(rest) = line.strip_prefix("* ") {
            let word = rest.split_once(' ').map_or(rest, |(w, _)| w);
            return Ok(word.to_ascii_uppercase());
        }
        // Continuation
        if line.starts_with("+ ") {
            return Ok("+".to_string());
        }
        // Tagged (client or server): "tag CMD/STATUS args"
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            Ok(parts[1].to_ascii_uppercase())
        } else {
            Err(FieldError::InvalidValue(
                "command: cannot parse command from IMAP line".into(),
            ))
        }
    }

    /// Returns the arguments / data portion of the line.
    pub fn args(&self, buf: &[u8]) -> Result<String, FieldError> {
        let line = self.first_line(buf);
        // Untagged
        if let Some(rest) = line.strip_prefix("* ") {
            let args = rest.split_once(' ').map_or("", |(_, a)| a).trim_start();
            return Ok(args.to_string());
        }
        // Continuation
        if let Some(rest) = line.strip_prefix("+ ") {
            return Ok(rest.trim().to_string());
        }
        // Tagged
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            Ok(parts[2].trim().to_string())
        } else {
            Ok(String::new())
        }
    }

    /// Returns the status from a tagged or untagged server response (OK/NO/BAD/BYE/PREAUTH).
    pub fn status(&self, buf: &[u8]) -> Result<String, FieldError> {
        let cmd = self.command(buf)?;
        if matches!(cmd.as_str(), "OK" | "NO" | "BAD" | "BYE" | "PREAUTH") {
            Ok(cmd)
        } else {
            Err(FieldError::InvalidValue(
                "status: not a server status response".into(),
            ))
        }
    }

    /// Returns the text body of a server response (after the status code).
    pub fn text(&self, buf: &[u8]) -> Result<String, FieldError> {
        let args = self.args(buf)?;
        Ok(args)
    }

    /// Returns the raw payload as a string.
    #[must_use]
    pub fn raw(&self, buf: &[u8]) -> String {
        String::from_utf8_lossy(self.slice(buf)).to_string()
    }

    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "tag" => Some(self.tag(buf).map(FieldValue::Str)),
            "command" => Some(self.command(buf).map(FieldValue::Str)),
            "args" => Some(self.args(buf).map(FieldValue::Str)),
            "status" => Some(self.status(buf).map(FieldValue::Str)),
            "text" => Some(self.text(buf).map(FieldValue::Str)),
            "is_untagged" => Some(Ok(FieldValue::Bool(self.is_untagged(buf)))),
            "is_continuation" => Some(Ok(FieldValue::Bool(self.is_continuation(buf)))),
            "is_tagged_response" => Some(Ok(FieldValue::Bool(self.is_tagged_response(buf)))),
            "is_client_command" => Some(Ok(FieldValue::Bool(self.is_client_command(buf)))),
            "raw" => Some(Ok(FieldValue::Str(self.raw(buf)))),
            _ => None,
        }
    }
}

impl Layer for ImapLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Imap
    }

    fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        let text = String::from_utf8_lossy(s);
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        format!("IMAP {first_line}")
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.slice(buf).len()
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        if let Ok(tag) = self.tag(buf) {
            tag.into_bytes()
        } else {
            vec![]
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        IMAP_FIELD_NAMES
    }
}

/// Returns a human-readable display of IMAP layer fields.
#[must_use]
pub fn imap_show_fields(l: &ImapLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if let Ok(tag) = l.tag(buf) {
        fields.push(("tag", tag));
    }
    if let Ok(cmd) = l.command(buf) {
        fields.push(("command", cmd));
        if let Ok(args) = l.args(buf)
            && !args.is_empty()
        {
            fields.push(("args", args));
        }
    }
    fields.push(("is_untagged", l.is_untagged(buf).to_string()));
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::LayerIndex;

    fn make_layer(data: &[u8]) -> ImapLayer {
        ImapLayer::new(LayerIndex::new(LayerKind::Imap, 0, data.len()))
    }

    #[test]
    fn test_imap_detection_untagged() {
        assert!(is_imap_payload(b"* OK IMAP4rev1 server ready\r\n"));
        assert!(is_imap_payload(b"* 3 EXISTS\r\n"));
        assert!(is_imap_payload(b"* BYE server closing\r\n"));
        assert!(is_imap_payload(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"));
    }

    #[test]
    fn test_imap_detection_continuation() {
        assert!(is_imap_payload(b"+ go ahead\r\n"));
        assert!(is_imap_payload(b"+ \r\n"));
    }

    #[test]
    fn test_imap_detection_tagged_response() {
        assert!(is_imap_payload(b"A001 OK LOGIN completed\r\n"));
        assert!(is_imap_payload(b"A002 NO login failed\r\n"));
        assert!(is_imap_payload(b"A003 BAD command unknown\r\n"));
    }

    #[test]
    fn test_imap_detection_client_command() {
        assert!(is_imap_payload(b"A001 LOGIN user pass\r\n"));
        assert!(is_imap_payload(b"A002 SELECT INBOX\r\n"));
        assert!(is_imap_payload(b"A003 FETCH 1:* FLAGS\r\n"));
        assert!(is_imap_payload(b"A004 NOOP\r\n"));
        assert!(is_imap_payload(b"A005 LOGOUT\r\n"));
    }

    #[test]
    fn test_imap_detection_negative() {
        assert!(!is_imap_payload(b""));
        assert!(!is_imap_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!is_imap_payload(b"+OK POP3 server ready\r\n")); // POP3, not IMAP
    }

    #[test]
    fn test_imap_untagged_response() {
        let data = b"* OK IMAP4rev1 Service Ready\r\n";
        let layer = make_layer(data);
        assert!(layer.is_untagged(data));
        assert!(!layer.is_tagged_response(data));
        assert!(!layer.is_continuation(data));
        assert_eq!(layer.tag(data).unwrap(), "*");
        assert_eq!(layer.command(data).unwrap(), "OK");
        assert_eq!(layer.args(data).unwrap(), "IMAP4rev1 Service Ready");
    }

    #[test]
    fn test_imap_untagged_exists() {
        let data = b"* 3 EXISTS\r\n";
        let layer = make_layer(data);
        assert!(layer.is_untagged(data));
        assert_eq!(layer.command(data).unwrap(), "3");
        assert_eq!(layer.args(data).unwrap(), "EXISTS");
    }

    #[test]
    fn test_imap_tagged_ok_response() {
        let data = b"A001 OK LOGIN completed\r\n";
        let layer = make_layer(data);
        assert!(layer.is_tagged_response(data));
        assert_eq!(layer.tag(data).unwrap(), "A001");
        assert_eq!(layer.command(data).unwrap(), "OK");
        assert_eq!(layer.status(data).unwrap(), "OK");
        assert_eq!(layer.args(data).unwrap(), "LOGIN completed");
    }

    #[test]
    fn test_imap_tagged_no_response() {
        let data = b"A002 NO login failed: wrong password\r\n";
        let layer = make_layer(data);
        assert!(layer.is_tagged_response(data));
        assert_eq!(layer.tag(data).unwrap(), "A002");
        assert_eq!(layer.status(data).unwrap(), "NO");
    }

    #[test]
    fn test_imap_client_login_command() {
        let data = b"A001 LOGIN alice password123\r\n";
        let layer = make_layer(data);
        assert!(layer.is_client_command(data));
        assert_eq!(layer.tag(data).unwrap(), "A001");
        assert_eq!(layer.command(data).unwrap(), "LOGIN");
        assert_eq!(layer.args(data).unwrap(), "alice password123");
    }

    #[test]
    fn test_imap_client_select() {
        let data = b"A002 SELECT INBOX\r\n";
        let layer = make_layer(data);
        assert!(layer.is_client_command(data));
        assert_eq!(layer.command(data).unwrap(), "SELECT");
        assert_eq!(layer.args(data).unwrap(), "INBOX");
    }

    #[test]
    fn test_imap_client_fetch() {
        let data = b"A003 FETCH 1:* (FLAGS BODY[HEADER])\r\n";
        let layer = make_layer(data);
        assert!(layer.is_client_command(data));
        assert_eq!(layer.command(data).unwrap(), "FETCH");
    }

    #[test]
    fn test_imap_continuation() {
        let data = b"+ dXNlcm5hbWU=\r\n";
        let layer = make_layer(data);
        assert!(layer.is_continuation(data));
        assert_eq!(layer.tag(data).unwrap(), "+");
    }

    #[test]
    fn test_imap_field_access() {
        let data = b"A001 OK LOGIN completed\r\n";
        let layer = make_layer(data);
        assert!(matches!(
            layer.get_field(data, "tag"),
            Some(Ok(FieldValue::Str(ref t))) if t == "A001"
        ));
        assert!(matches!(
            layer.get_field(data, "is_untagged"),
            Some(Ok(FieldValue::Bool(false)))
        ));
        assert!(matches!(
            layer.get_field(data, "is_tagged_response"),
            Some(Ok(FieldValue::Bool(true)))
        ));
        assert!(layer.get_field(data, "bad_field").is_none());
    }
}
