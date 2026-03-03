//! FTP packet builder.
//!
//! Provides a fluent API for constructing FTP command and reply payloads.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::ftp::builder::FtpBuilder;
//!
//! // Build a USER command
//! let pkt = FtpBuilder::new().user("anonymous").build();
//! assert_eq!(pkt, b"USER anonymous\r\n");
//!
//! // Build a 220 service-ready reply
//! let pkt = FtpBuilder::new().service_ready("FTP Server ready").build();
//! assert_eq!(pkt, b"220 FTP Server ready\r\n");
//! ```

/// Builder for FTP control connection messages (commands and replies).
#[must_use]
#[derive(Debug, Clone)]
pub struct FtpBuilder {
    /// If Some, build a server reply with this code.
    reply_code: Option<u16>,
    /// If Some, build a client command with this verb.
    command: Option<String>,
    /// Arguments for command, or text for reply.
    text: String,
    /// If true, use multi-line reply format (code followed by `-`).
    multiline: bool,
    /// Additional lines for multi-line replies.
    extra_lines: Vec<String>,
}

impl Default for FtpBuilder {
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

impl FtpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Reply builders (server-side)
    // ========================================================================

    /// Set the reply code and message text.
    pub fn reply(mut self, code: u16, text: impl Into<String>) -> Self {
        self.reply_code = Some(code);
        self.command = None;
        self.text = text.into();
        self
    }

    /// Make this a multi-line reply with additional intermediate lines.
    pub fn multiline(mut self, lines: Vec<String>) -> Self {
        self.multiline = true;
        self.extra_lines = lines;
        self
    }

    /// Build "220 Service ready" reply.
    pub fn service_ready(self, text: impl Into<String>) -> Self {
        self.reply(220, text)
    }

    /// Build "230 User logged in" reply.
    pub fn user_logged_in(self, text: impl Into<String>) -> Self {
        self.reply(230, text.into())
    }

    /// Build "331 Password required" reply.
    pub fn password_required(self) -> Self {
        self.reply(331, "Password required")
    }

    /// Build "227 Entering Passive Mode" reply.
    pub fn passive_mode(self, h1: u8, h2: u8, h3: u8, h4: u8, p1: u8, p2: u8) -> Self {
        let text = format!("Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})");
        self.reply(227, text)
    }

    /// Build "229 Entering Extended Passive Mode" reply.
    pub fn extended_passive_mode(self, port: u16) -> Self {
        let text = format!("Entering Extended Passive Mode (|||{port}|)");
        self.reply(229, text)
    }

    /// Build "226 Transfer complete" reply.
    pub fn transfer_complete(self) -> Self {
        self.reply(226, "Transfer complete")
    }

    /// Build "150 File status okay" reply.
    pub fn file_status_ok(self) -> Self {
        self.reply(150, "File status okay; about to open data connection")
    }

    /// Build "250 Requested file action OK" reply.
    pub fn file_action_ok(self) -> Self {
        self.reply(250, "Requested file action okay, completed")
    }

    /// Build "257 pathname created" reply.
    pub fn pathname_created(self, path: impl Into<String>) -> Self {
        let path = path.into();
        let text = format!("\"{path}\" created");
        self.reply(257, text)
    }

    /// Build "221 Goodbye" reply.
    pub fn goodbye(self) -> Self {
        self.reply(221, "Goodbye")
    }

    /// Build "421 Service not available" reply.
    pub fn service_not_available(self) -> Self {
        self.reply(421, "Service not available, closing control connection")
    }

    /// Build "530 Not logged in" reply.
    pub fn not_logged_in(self) -> Self {
        self.reply(530, "Not logged in")
    }

    /// Build "550 File unavailable" reply.
    pub fn file_unavailable(self, text: impl Into<String>) -> Self {
        self.reply(550, text)
    }

    /// Build "500 Syntax error" reply.
    pub fn syntax_error(self, text: impl Into<String>) -> Self {
        self.reply(500, text)
    }

    /// Build a FEAT reply (RFC 2389 feature list).
    pub fn feat_reply(mut self, features: Vec<String>) -> Self {
        self.reply_code = Some(211);
        self.command = None;
        self.multiline = true;
        self.text = "Features:".to_string();
        self.extra_lines = features.into_iter().map(|f| format!(" {f}")).collect();
        self
    }

    // ========================================================================
    // Command builders (client-side)
    // ========================================================================

    /// Set a raw command verb and optional args.
    pub fn command(mut self, verb: impl Into<String>, args: impl Into<String>) -> Self {
        self.command = Some(verb.into().to_ascii_uppercase());
        self.reply_code = None;
        self.text = args.into();
        self
    }

    /// Build "USER <name>" command.
    pub fn user(self, username: impl Into<String>) -> Self {
        self.command("USER", username)
    }

    /// Build "PASS <password>" command.
    pub fn pass(self, password: impl Into<String>) -> Self {
        self.command("PASS", password)
    }

    /// Build "QUIT" command.
    pub fn quit(self) -> Self {
        self.command("QUIT", "")
    }

    /// Build "LIST [path]" command.
    pub fn list(self, path: impl Into<String>) -> Self {
        self.command("LIST", path)
    }

    /// Build "NLST [path]" command.
    pub fn nlst(self, path: impl Into<String>) -> Self {
        self.command("NLST", path)
    }

    /// Build "RETR <filename>" command.
    pub fn retr(self, filename: impl Into<String>) -> Self {
        self.command("RETR", filename)
    }

    /// Build "STOR <filename>" command.
    pub fn stor(self, filename: impl Into<String>) -> Self {
        self.command("STOR", filename)
    }

    /// Build "APPE <filename>" command.
    pub fn appe(self, filename: impl Into<String>) -> Self {
        self.command("APPE", filename)
    }

    /// Build "DELE <filename>" command.
    pub fn dele(self, filename: impl Into<String>) -> Self {
        self.command("DELE", filename)
    }

    /// Build "CWD <path>" command.
    pub fn cwd(self, path: impl Into<String>) -> Self {
        self.command("CWD", path)
    }

    /// Build "CDUP" command.
    pub fn cdup(self) -> Self {
        self.command("CDUP", "")
    }

    /// Build "MKD <path>" command.
    pub fn mkd(self, path: impl Into<String>) -> Self {
        self.command("MKD", path)
    }

    /// Build "RMD <path>" command.
    pub fn rmd(self, path: impl Into<String>) -> Self {
        self.command("RMD", path)
    }

    /// Build "PWD" command.
    pub fn pwd(self) -> Self {
        self.command("PWD", "")
    }

    /// Build "SYST" command.
    pub fn syst(self) -> Self {
        self.command("SYST", "")
    }

    /// Build "NOOP" command.
    pub fn noop(self) -> Self {
        self.command("NOOP", "")
    }

    /// Build "PASV" command.
    pub fn pasv(self) -> Self {
        self.command("PASV", "")
    }

    /// Build "EPSV" command.
    pub fn epsv(self) -> Self {
        self.command("EPSV", "")
    }

    /// Build "PORT h1,h2,h3,h4,p1,p2" command.
    pub fn port(self, h1: u8, h2: u8, h3: u8, h4: u8, p1: u8, p2: u8) -> Self {
        let args = format!("{h1},{h2},{h3},{h4},{p1},{p2}");
        self.command("PORT", args)
    }

    /// Build "TYPE <mode>" command (A=ASCII, I=binary).
    pub fn type_cmd(self, mode: char) -> Self {
        self.command("TYPE", mode.to_string())
    }

    /// Build "FEAT" command.
    pub fn feat(self) -> Self {
        self.command("FEAT", "")
    }

    /// Build "SIZE <filename>" command (RFC 3659).
    pub fn size(self, filename: impl Into<String>) -> Self {
        self.command("SIZE", filename)
    }

    /// Build "MDTM <filename>" command (RFC 3659).
    pub fn mdtm(self, filename: impl Into<String>) -> Self {
        self.command("MDTM", filename)
    }

    /// Build "AUTH <mechanism>" command.
    pub fn auth(self, mechanism: impl Into<String>) -> Self {
        self.command("AUTH", mechanism)
    }

    /// Build "RNFR <filename>" command.
    pub fn rnfr(self, filename: impl Into<String>) -> Self {
        self.command("RNFR", filename)
    }

    /// Build "RNTO <filename>" command.
    pub fn rnto(self, filename: impl Into<String>) -> Self {
        self.command("RNTO", filename)
    }

    /// Build "REST <marker>" command.
    pub fn rest(self, offset: u64) -> Self {
        self.command("REST", offset.to_string())
    }

    /// Build "ABOR" command.
    pub fn abor(self) -> Self {
        self.command("ABOR", "")
    }

    /// Build "STAT [path]" command.
    pub fn stat(self, path: impl Into<String>) -> Self {
        self.command("STAT", path)
    }

    /// Build "HELP [topic]" command.
    pub fn help(self, topic: impl Into<String>) -> Self {
        self.command("HELP", topic)
    }

    // ========================================================================
    // Build
    // ========================================================================

    /// Serialize this FTP message to bytes (including CRLF terminator).
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
            // First line: NNN-text
            out.extend_from_slice(format!("{:03}-{}\r\n", code, self.text).as_bytes());
            // Intermediate lines (no code prefix required, but common)
            for line in &self.extra_lines {
                out.extend_from_slice(format!("{line}\r\n").as_bytes());
            }
            // Last line: NNN SP text (or just code)
            out.extend_from_slice(format!("{code:03} End\r\n").as_bytes());
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
    fn test_build_noop_command() {
        let pkt = FtpBuilder::new().noop().build();
        assert_eq!(pkt, b"NOOP\r\n");
    }

    #[test]
    fn test_build_user_command() {
        let pkt = FtpBuilder::new().user("anonymous").build();
        assert_eq!(pkt, b"USER anonymous\r\n");
    }

    #[test]
    fn test_build_pass_command() {
        let pkt = FtpBuilder::new().pass("secret").build();
        assert_eq!(pkt, b"PASS secret\r\n");
    }

    #[test]
    fn test_build_quit_command() {
        let pkt = FtpBuilder::new().quit().build();
        assert_eq!(pkt, b"QUIT\r\n");
    }

    #[test]
    fn test_build_list_command() {
        let pkt = FtpBuilder::new().list("/pub").build();
        assert_eq!(pkt, b"LIST /pub\r\n");
    }

    #[test]
    fn test_build_retr_command() {
        let pkt = FtpBuilder::new().retr("file.txt").build();
        assert_eq!(pkt, b"RETR file.txt\r\n");
    }

    #[test]
    fn test_build_service_ready_reply() {
        let pkt = FtpBuilder::new().service_ready("FTP Server ready").build();
        assert_eq!(pkt, b"220 FTP Server ready\r\n");
    }

    #[test]
    fn test_build_password_required_reply() {
        let pkt = FtpBuilder::new().password_required().build();
        assert_eq!(pkt, b"331 Password required\r\n");
    }

    #[test]
    fn test_build_passive_mode_reply() {
        let pkt = FtpBuilder::new()
            .passive_mode(192, 168, 1, 1, 200, 50)
            .build();
        assert_eq!(pkt, b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n");
    }

    #[test]
    fn test_build_multiline_reply() {
        let pkt = FtpBuilder::new()
            .feat_reply(vec!["SIZE".to_string(), "MDTM".to_string()])
            .build();
        let s = String::from_utf8(pkt).unwrap();
        assert!(s.starts_with("211-"));
        assert!(s.contains("SIZE\r\n"));
        assert!(s.contains("MDTM\r\n"));
    }

    #[test]
    fn test_build_port_command() {
        let pkt = FtpBuilder::new().port(192, 168, 1, 2, 100, 30).build();
        assert_eq!(pkt, b"PORT 192,168,1,2,100,30\r\n");
    }

    #[test]
    fn test_build_type_command() {
        let pkt = FtpBuilder::new().type_cmd('I').build();
        assert_eq!(pkt, b"TYPE I\r\n");
    }
}
