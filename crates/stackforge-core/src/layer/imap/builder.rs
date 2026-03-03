//! IMAP packet builder.
//!
//! Provides a fluent API for constructing IMAP commands and responses.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::imap::builder::ImapBuilder;
//!
//! // Build a LOGIN command
//! let pkt = ImapBuilder::new().login("A001", "alice", "password").build();
//! assert_eq!(pkt, b"A001 LOGIN alice password\r\n");
//!
//! // Build an untagged OK server greeting
//! let pkt = ImapBuilder::new().server_greeting("IMAP4rev1 Service Ready").build();
//! assert_eq!(pkt, b"* OK IMAP4rev1 Service Ready\r\n");
//! ```

/// Builder for IMAP messages (client commands and server responses).
#[must_use]
#[derive(Debug, Clone)]
pub struct ImapBuilder {
    /// Message tag: "*" for untagged, "+" for continuation, or client tag.
    tag: String,
    /// Command verb or response status.
    command: String,
    /// Arguments or response text.
    args: String,
    /// Additional response lines (for multi-line responses like FETCH data).
    extra_lines: Vec<String>,
}

impl Default for ImapBuilder {
    fn default() -> Self {
        Self {
            tag: "A001".to_string(),
            command: "NOOP".to_string(),
            args: String::new(),
            extra_lines: Vec::new(),
        }
    }
}

impl ImapBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Server Response Builders
    // ========================================================================

    /// Untagged response: `* STATUS [text]`
    pub fn untagged(mut self, status: impl Into<String>, text: impl Into<String>) -> Self {
        self.tag = "*".to_string();
        self.command = status.into().to_ascii_uppercase();
        self.args = text.into();
        self.extra_lines.clear();
        self
    }

    /// Continuation request: `+ [text]`
    pub fn continuation(mut self, text: impl Into<String>) -> Self {
        self.tag = "+".to_string();
        self.command = String::new();
        self.args = text.into();
        self.extra_lines.clear();
        self
    }

    /// Tagged response: `tag STATUS [text]`
    pub fn tagged_response(
        mut self,
        tag: impl Into<String>,
        status: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        self.tag = tag.into();
        self.command = status.into().to_ascii_uppercase();
        self.args = text.into();
        self.extra_lines.clear();
        self
    }

    /// `* OK IMAP4rev1 Service Ready` (server greeting).
    pub fn server_greeting(self, text: impl Into<String>) -> Self {
        self.untagged("OK", text)
    }

    /// `* BYE [text]` (server closing connection).
    pub fn bye(self, text: impl Into<String>) -> Self {
        self.untagged("BYE", text)
    }

    /// `* CAPABILITY [capabilities]`
    pub fn capability(self, caps: impl Into<String>) -> Self {
        self.untagged("CAPABILITY", caps)
    }

    /// `* N EXISTS` (mailbox contains N messages).
    pub fn exists(self, n: u32) -> Self {
        self.untagged(format!("{}", n), "EXISTS")
    }

    /// `* N RECENT` (N messages are recent).
    pub fn recent(self, n: u32) -> Self {
        self.untagged(format!("{}", n), "RECENT")
    }

    /// `* N EXPUNGE` (message N was expunged).
    pub fn expunge_notify(self, n: u32) -> Self {
        self.untagged(format!("{}", n), "EXPUNGE")
    }

    /// `tag OK [text]`
    pub fn ok(self, tag: impl Into<String>, text: impl Into<String>) -> Self {
        self.tagged_response(tag, "OK", text)
    }

    /// `tag NO [text]`
    pub fn no(self, tag: impl Into<String>, text: impl Into<String>) -> Self {
        self.tagged_response(tag, "NO", text)
    }

    /// `tag BAD [text]`
    pub fn bad(self, tag: impl Into<String>, text: impl Into<String>) -> Self {
        self.tagged_response(tag, "BAD", text)
    }

    // ========================================================================
    // Client Command Builders
    // ========================================================================

    fn client_cmd(
        mut self,
        tag: impl Into<String>,
        command: impl Into<String>,
        args: impl Into<String>,
    ) -> Self {
        self.tag = tag.into();
        self.command = command.into().to_ascii_uppercase();
        self.args = args.into();
        self.extra_lines.clear();
        self
    }

    /// `tag CAPABILITY`
    pub fn capability_cmd(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "CAPABILITY", "")
    }

    /// `tag NOOP`
    pub fn noop(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "NOOP", "")
    }

    /// `tag LOGOUT`
    pub fn logout(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "LOGOUT", "")
    }

    /// `tag LOGIN <user> <pass>`
    pub fn login(
        self,
        tag: impl Into<String>,
        user: impl Into<String>,
        pass: impl Into<String>,
    ) -> Self {
        let args = format!("{} {}", user.into(), pass.into());
        self.client_cmd(tag, "LOGIN", args)
    }

    /// `tag AUTHENTICATE <mechanism>`
    pub fn authenticate(self, tag: impl Into<String>, mechanism: impl Into<String>) -> Self {
        self.client_cmd(tag, "AUTHENTICATE", mechanism)
    }

    /// `tag STARTTLS`
    pub fn starttls(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "STARTTLS", "")
    }

    /// `tag SELECT <mailbox>`
    pub fn select(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "SELECT", mailbox)
    }

    /// `tag EXAMINE <mailbox>`
    pub fn examine(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "EXAMINE", mailbox)
    }

    /// `tag CREATE <mailbox>`
    pub fn create(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "CREATE", mailbox)
    }

    /// `tag DELETE <mailbox>`
    pub fn delete(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "DELETE", mailbox)
    }

    /// `tag RENAME <old> <new>`
    pub fn rename(
        self,
        tag: impl Into<String>,
        old: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        let args = format!("{} {}", old.into(), new_name.into());
        self.client_cmd(tag, "RENAME", args)
    }

    /// `tag LIST <ref> <pattern>`
    pub fn list(
        self,
        tag: impl Into<String>,
        reference: impl Into<String>,
        pattern: impl Into<String>,
    ) -> Self {
        let args = format!("\"{}\" \"{}\"", reference.into(), pattern.into());
        self.client_cmd(tag, "LIST", args)
    }

    /// `tag SUBSCRIBE <mailbox>`
    pub fn subscribe(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "SUBSCRIBE", mailbox)
    }

    /// `tag UNSUBSCRIBE <mailbox>`
    pub fn unsubscribe(self, tag: impl Into<String>, mailbox: impl Into<String>) -> Self {
        self.client_cmd(tag, "UNSUBSCRIBE", mailbox)
    }

    /// `tag STATUS <mailbox> (<items>)`
    pub fn status_cmd(
        self,
        tag: impl Into<String>,
        mailbox: impl Into<String>,
        items: impl Into<String>,
    ) -> Self {
        let args = format!("{} ({})", mailbox.into(), items.into());
        self.client_cmd(tag, "STATUS", args)
    }

    /// `tag FETCH <sequence> <items>`
    pub fn fetch(
        self,
        tag: impl Into<String>,
        sequence: impl Into<String>,
        items: impl Into<String>,
    ) -> Self {
        let args = format!("{} {}", sequence.into(), items.into());
        self.client_cmd(tag, "FETCH", args)
    }

    /// `tag STORE <sequence> <flags>`
    pub fn store(
        self,
        tag: impl Into<String>,
        sequence: impl Into<String>,
        mode: impl Into<String>,
        flags: impl Into<String>,
    ) -> Self {
        let args = format!("{} {} ({})", sequence.into(), mode.into(), flags.into());
        self.client_cmd(tag, "STORE", args)
    }

    /// `tag SEARCH <criteria>`
    pub fn search(self, tag: impl Into<String>, criteria: impl Into<String>) -> Self {
        self.client_cmd(tag, "SEARCH", criteria)
    }

    /// `tag COPY <sequence> <mailbox>`
    pub fn copy(
        self,
        tag: impl Into<String>,
        sequence: impl Into<String>,
        mailbox: impl Into<String>,
    ) -> Self {
        let args = format!("{} {}", sequence.into(), mailbox.into());
        self.client_cmd(tag, "COPY", args)
    }

    /// `tag EXPUNGE`
    pub fn expunge(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "EXPUNGE", "")
    }

    /// `tag CLOSE`
    pub fn close(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "CLOSE", "")
    }

    /// `tag CHECK`
    pub fn check(self, tag: impl Into<String>) -> Self {
        self.client_cmd(tag, "CHECK", "")
    }

    /// `tag UID <command> <args>`
    pub fn uid(
        self,
        tag: impl Into<String>,
        command: impl Into<String>,
        args: impl Into<String>,
    ) -> Self {
        let uid_args = format!("{} {}", command.into().to_ascii_uppercase(), args.into());
        self.client_cmd(tag, "UID", uid_args)
    }

    // ========================================================================
    // Build
    // ========================================================================

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.tag == "+" {
            // Continuation
            if self.args.is_empty() {
                out.extend_from_slice(b"+ \r\n");
            } else {
                out.extend_from_slice(format!("+ {}\r\n", self.args).as_bytes());
            }
        } else if self.tag == "*" {
            // Untagged
            if self.args.is_empty() {
                out.extend_from_slice(format!("* {}\r\n", self.command).as_bytes());
            } else {
                out.extend_from_slice(format!("* {} {}\r\n", self.command, self.args).as_bytes());
            }
        } else {
            // Tagged (command or response)
            if self.command.is_empty() {
                out.extend_from_slice(format!("{}\r\n", self.tag).as_bytes());
            } else if self.args.is_empty() {
                out.extend_from_slice(format!("{} {}\r\n", self.tag, self.command).as_bytes());
            } else {
                out.extend_from_slice(
                    format!("{} {} {}\r\n", self.tag, self.command, self.args).as_bytes(),
                );
            }
        }
        // Append extra lines
        for line in &self.extra_lines {
            out.extend_from_slice(format!("{}\r\n", line).as_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_server_greeting() {
        let pkt = ImapBuilder::new()
            .server_greeting("IMAP4rev1 Service Ready")
            .build();
        assert_eq!(pkt, b"* OK IMAP4rev1 Service Ready\r\n");
    }

    #[test]
    fn test_build_bye() {
        let pkt = ImapBuilder::new().bye("Server logging out").build();
        assert_eq!(pkt, b"* BYE Server logging out\r\n");
    }

    #[test]
    fn test_build_ok_response() {
        let pkt = ImapBuilder::new().ok("A001", "LOGIN completed").build();
        assert_eq!(pkt, b"A001 OK LOGIN completed\r\n");
    }

    #[test]
    fn test_build_no_response() {
        let pkt = ImapBuilder::new().no("A002", "login failed").build();
        assert_eq!(pkt, b"A002 NO login failed\r\n");
    }

    #[test]
    fn test_build_bad_response() {
        let pkt = ImapBuilder::new().bad("A003", "unknown command").build();
        assert_eq!(pkt, b"A003 BAD unknown command\r\n");
    }

    #[test]
    fn test_build_login_command() {
        let pkt = ImapBuilder::new()
            .login("A001", "alice", "password123")
            .build();
        assert_eq!(pkt, b"A001 LOGIN alice password123\r\n");
    }

    #[test]
    fn test_build_select_command() {
        let pkt = ImapBuilder::new().select("A002", "INBOX").build();
        assert_eq!(pkt, b"A002 SELECT INBOX\r\n");
    }

    #[test]
    fn test_build_fetch_command() {
        let pkt = ImapBuilder::new().fetch("A003", "1:*", "FLAGS").build();
        assert_eq!(pkt, b"A003 FETCH 1:* FLAGS\r\n");
    }

    #[test]
    fn test_build_store_command() {
        let pkt = ImapBuilder::new()
            .store("A004", "1", "+FLAGS", "\\Seen")
            .build();
        assert_eq!(pkt, b"A004 STORE 1 +FLAGS (\\Seen)\r\n");
    }

    #[test]
    fn test_build_search_command() {
        let pkt = ImapBuilder::new().search("A005", "UNSEEN").build();
        assert_eq!(pkt, b"A005 SEARCH UNSEEN\r\n");
    }

    #[test]
    fn test_build_noop() {
        let pkt = ImapBuilder::new().noop("A006").build();
        assert_eq!(pkt, b"A006 NOOP\r\n");
    }

    #[test]
    fn test_build_logout() {
        let pkt = ImapBuilder::new().logout("A007").build();
        assert_eq!(pkt, b"A007 LOGOUT\r\n");
    }

    #[test]
    fn test_build_exists_untagged() {
        let pkt = ImapBuilder::new().exists(5).build();
        assert_eq!(pkt, b"* 5 EXISTS\r\n");
    }

    #[test]
    fn test_build_recent_untagged() {
        let pkt = ImapBuilder::new().recent(2).build();
        assert_eq!(pkt, b"* 2 RECENT\r\n");
    }

    #[test]
    fn test_build_continuation() {
        let pkt = ImapBuilder::new().continuation("go ahead").build();
        assert_eq!(pkt, b"+ go ahead\r\n");
    }

    #[test]
    fn test_build_uid_fetch() {
        let pkt = ImapBuilder::new().uid("A008", "FETCH", "1:* FLAGS").build();
        assert_eq!(pkt, b"A008 UID FETCH 1:* FLAGS\r\n");
    }

    #[test]
    fn test_build_capability() {
        let pkt = ImapBuilder::new()
            .capability("IMAP4rev1 AUTH=PLAIN STARTTLS")
            .build();
        assert_eq!(pkt, b"* CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS\r\n");
    }
}
