//! # Stackforge Python Bindings
//!
//! This module provides PyO3-based Python bindings for the Stackforge
//! networking framework.
//!
//! The bindings expose the high-performance Rust packet manipulation
//! engine to Python, enabling Scapy-like ergonomics with native speed.
//!
//! ## Layer Stacking
//!
//! Stackforge supports Scapy-like layer stacking using the `/` operator:
//!
//! ```python
//! from stackforge import Ether, IP, TCP
//!
//! # Build a TCP SYN packet
//! pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
//! print(pkt.show())
//! ```

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use stackforge_core::{
    ArpBuilder as RustArpBuilder, EthernetBuilder as RustEthernetBuilder, FieldValue,
    Http2Builder as RustHttp2Builder, Http2FrameBuilder as RustHttp2FrameBuilder,
    HttpRequestBuilder as RustHttpRequestBuilder, HttpResponseBuilder as RustHttpResponseBuilder,
    IcmpBuilder as RustIcmpBuilder, Icmpv6Builder as RustIcmpv6Builder,
    Ipv4Builder as RustIpv4Builder, Ipv6Builder as RustIpv6Builder, L2tpBuilder as RustL2tpBuilder,
    LayerKind as RustLayerKind, LayerStack as RustLayerStack,
    LayerStackEntry as RustLayerStackEntry, MacAddress, Packet as RustPacket, PacketError,
    QuicBuilder as RustQuicBuilder, SshBuilder as RustSshBuilder, TcpBuilder as RustTcpBuilder,
    TlsRecordBuilder as RustTlsRecordBuilder, UdpBuilder as RustUdpBuilder,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Python-visible wrapper for LayerKind enum.
#[pyclass(name = "LayerKind", eq)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyLayerKind {
    /// Ethernet II frame
    Ethernet,
    Dot3,
    /// Address Resolution Protocol
    Arp,
    /// Internet Protocol version 4
    Ipv4,
    /// Internet Protocol version 6
    Ipv6,
    /// Internet Control Message Protocol
    Icmp,
    /// ICMPv6
    Icmpv6,
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Domain Name System
    Dns,
    Dot1Q,
    Dot1AD,
    Dot1AH,
    LLC,
    SNAP,
    /// Secure Shell Protocol
    Ssh,
    /// Transport Layer Security
    Tls,
    /// IEEE 802.15.4
    Dot15d4,
    /// IEEE 802.15.4 with FCS
    Dot15d4Fcs,
    /// IEEE 802.11 (WiFi)
    Dot11,
    /// HTTP/1.x application protocol
    Http,
    /// QUIC transport protocol
    Quic,
    /// Generic/custom protocol layer
    Generic,
    /// HTTP/2 protocol
    Http2,
    /// Layer 2 Tunneling Protocol
    L2tp,
    /// Raw payload data
    Raw,
}

#[pymethods]
impl PyLayerKind {
    /// Returns the human-readable name of this layer kind.
    fn name(&self) -> &'static str {
        self.to_rust().name()
    }

    /// Returns the minimum header size for this layer type.
    fn min_header_size(&self) -> usize {
        self.to_rust().min_header_size()
    }

    fn __repr__(&self) -> String {
        format!("LayerKind.{}", self.name())
    }

    fn __str__(&self) -> &'static str {
        self.name()
    }
}

impl PyLayerKind {
    fn to_rust(&self) -> RustLayerKind {
        match self {
            PyLayerKind::Ethernet => RustLayerKind::Ethernet,
            PyLayerKind::Dot3 => RustLayerKind::Dot3,
            PyLayerKind::Arp => RustLayerKind::Arp,
            PyLayerKind::Ipv4 => RustLayerKind::Ipv4,
            PyLayerKind::Ipv6 => RustLayerKind::Ipv6,
            PyLayerKind::Icmp => RustLayerKind::Icmp,
            PyLayerKind::Icmpv6 => RustLayerKind::Icmpv6,
            PyLayerKind::Tcp => RustLayerKind::Tcp,
            PyLayerKind::Udp => RustLayerKind::Udp,
            PyLayerKind::Dns => RustLayerKind::Dns,
            PyLayerKind::Dot1Q => RustLayerKind::Dot1Q,
            PyLayerKind::Dot1AD => RustLayerKind::Dot1AD,
            PyLayerKind::Dot1AH => RustLayerKind::Dot1AH,
            PyLayerKind::LLC => RustLayerKind::LLC,
            PyLayerKind::SNAP => RustLayerKind::SNAP,
            PyLayerKind::Ssh => RustLayerKind::Ssh,
            PyLayerKind::Tls => RustLayerKind::Tls,
            PyLayerKind::Dot15d4 => RustLayerKind::Dot15d4,
            PyLayerKind::Dot15d4Fcs => RustLayerKind::Dot15d4Fcs,
            PyLayerKind::Dot11 => RustLayerKind::Dot11,
            PyLayerKind::Http => RustLayerKind::Http,
            PyLayerKind::Quic => RustLayerKind::Quic,
            PyLayerKind::Generic => RustLayerKind::Generic,
            PyLayerKind::Http2 => RustLayerKind::Http2,
            PyLayerKind::L2tp => RustLayerKind::L2tp,
            PyLayerKind::Raw => RustLayerKind::Raw,
        }
    }

    fn from_rust(kind: RustLayerKind) -> Self {
        match kind {
            RustLayerKind::Ethernet => PyLayerKind::Ethernet,
            RustLayerKind::Dot3 => PyLayerKind::Dot3,
            RustLayerKind::Arp => PyLayerKind::Arp,
            RustLayerKind::Ipv4 => PyLayerKind::Ipv4,
            RustLayerKind::Ipv6 => PyLayerKind::Ipv6,
            RustLayerKind::Icmp => PyLayerKind::Icmp,
            RustLayerKind::Icmpv6 => PyLayerKind::Icmpv6,
            RustLayerKind::Tcp => PyLayerKind::Tcp,
            RustLayerKind::Udp => PyLayerKind::Udp,
            RustLayerKind::Dns => PyLayerKind::Dns,
            RustLayerKind::Dot1Q => PyLayerKind::Dot1Q,
            RustLayerKind::Dot1AD => PyLayerKind::Dot1AD,
            RustLayerKind::Dot1AH => PyLayerKind::Dot1AH,
            RustLayerKind::LLC => PyLayerKind::LLC,
            RustLayerKind::SNAP => PyLayerKind::SNAP,
            RustLayerKind::Ssh => PyLayerKind::Ssh,
            RustLayerKind::Tls => PyLayerKind::Tls,
            RustLayerKind::Dot15d4 => PyLayerKind::Dot15d4,
            RustLayerKind::Dot15d4Fcs => PyLayerKind::Dot15d4Fcs,
            RustLayerKind::Dot11 => PyLayerKind::Dot11,
            RustLayerKind::Http => PyLayerKind::Http,
            RustLayerKind::Quic => PyLayerKind::Quic,
            RustLayerKind::Generic => PyLayerKind::Generic,
            RustLayerKind::Http2 => PyLayerKind::Http2,
            RustLayerKind::L2tp => PyLayerKind::L2tp,
            RustLayerKind::Raw => PyLayerKind::Raw,
        }
    }
}

/// Information about a layer within a packet.
#[pyclass(name = "LayerIndex")]
#[derive(Clone)]
pub struct PyLayerIndex {
    /// The type of this layer.
    #[pyo3(get)]
    pub kind: PyLayerKind,
    /// Starting byte offset.
    #[pyo3(get)]
    pub start: usize,
    /// Ending byte offset (exclusive).
    #[pyo3(get)]
    pub end: usize,
}

#[pymethods]
impl PyLayerIndex {
    /// Returns the length of this layer in bytes.
    fn __len__(&self) -> usize {
        self.end - self.start
    }

    fn __repr__(&self) -> String {
        format!(
            "LayerIndex(kind={}, start={}, end={})",
            self.kind.name(),
            self.start,
            self.end
        )
    }
}

/// A high-performance network packet with zero-copy storage.
///
/// This class wraps the Rust Packet implementation, providing Python
/// access to the zero-copy packet manipulation engine.
///
/// Example:
///     >>> from stackforge import Packet, LayerKind
///     >>> pkt = Packet(bytes([...]))
///     >>> pkt.parse()
///     >>> print(pkt.layers)
#[pyclass(name = "Packet")]
pub struct PyPacket {
    inner: RustPacket,
}

#[pymethods]
impl PyPacket {
    /// Creates a new packet from raw bytes.
    ///
    /// Args:
    ///     data: Raw packet bytes (typically from network capture)
    ///
    /// Returns:
    ///     A new Packet instance
    #[new]
    fn new(data: &Bound<'_, PyBytes>) -> Self {
        let bytes = data.as_bytes().to_vec();
        Self {
            inner: RustPacket::from_bytes(bytes),
        }
    }

    /// Creates an empty packet.
    #[staticmethod]
    fn empty() -> Self {
        Self {
            inner: RustPacket::empty(),
        }
    }

    /// Returns the total length of the packet in bytes.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Returns True if the packet is empty.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns True if the packet has been modified.
    #[getter]
    fn is_dirty(&self) -> bool {
        self.inner.is_dirty()
    }

    /// Returns the number of parsed layers.
    #[getter]
    fn layer_count(&self) -> usize {
        self.inner.layer_count()
    }

    /// Returns True if the packet has been parsed.
    #[getter]
    fn is_parsed(&self) -> bool {
        self.inner.is_parsed()
    }

    /// Returns the raw packet bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    /// Parses the packet to identify layer boundaries.
    ///
    /// This performs index-only parsing - it identifies where each
    /// protocol header starts and ends without extracting field values.
    ///
    /// Raises:
    ///     ValueError: If the packet is malformed
    fn parse(&mut self) -> PyResult<()> {
        self.inner
            .parse()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))
    }

    /// Returns a list of all layer indices in this packet.
    #[getter]
    fn layers(&self) -> Vec<PyLayerIndex> {
        self.inner
            .layers()
            .iter()
            .map(|idx| PyLayerIndex {
                kind: PyLayerKind::from_rust(idx.kind),
                start: idx.start,
                end: idx.end,
            })
            .collect()
    }

    /// Checks if a specific layer type exists in this packet.
    ///
    /// Args:
    ///     kind: The LayerKind to check for
    ///
    /// Returns:
    ///     True if the layer exists, False otherwise
    fn has_layer(&self, kind: PyLayerKind) -> bool {
        self.inner.get_layer(kind.to_rust()).is_some()
    }

    /// Returns the bytes for a specific layer.
    ///
    /// Args:
    ///     kind: The LayerKind to retrieve
    ///
    /// Returns:
    ///     The raw bytes of that layer's header
    ///
    /// Raises:
    ///     KeyError: If the layer doesn't exist
    fn get_layer_bytes<'py>(
        &self,
        py: Python<'py>,
        kind: PyLayerKind,
    ) -> PyResult<Bound<'py, PyBytes>> {
        match self.inner.layer_bytes(kind.to_rust()) {
            Ok(bytes) => Ok(PyBytes::new(py, bytes)),
            Err(PacketError::LayerNotFound(_)) => Err(pyo3::exceptions::PyKeyError::new_err(
                format!("Layer {} not found", kind.name()),
            )),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{}", e))),
        }
    }

    /// Returns the payload bytes (data after all parsed headers).
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.payload())
    }

    /// Returns a Scapy-style string representation of the packet.
    ///
    /// For parsed packets, shows a summary of each layer:
    /// `<Ether src=00:11:22:33:44:55 dst=ff:ff:ff:ff:ff:ff | IP 192.168.1.1 > 192.168.1.2 | TCP 80 > 8080 [S]>`
    fn __repr__(&self) -> String {
        if !self.inner.is_parsed() {
            return format!("<Packet len={} [unparsed]>", self.inner.len());
        }

        let buf = self.inner.as_bytes();
        let summaries: Vec<String> = self
            .inner
            .layer_enums()
            .iter()
            .map(|layer| layer.summary(buf))
            .collect();

        if summaries.is_empty() {
            format!("<Packet len={} [no layers]>", self.inner.len())
        } else {
            format!("<{}>", summaries.join(" | "))
        }
    }

    /// Returns a Scapy-style detailed view of the packet structure.
    ///
    /// Displays each layer with all its fields, similar to Scapy's show() method:
    /// ```text
    /// ###[ Ethernet ]###
    ///   dst       = ff:ff:ff:ff:ff:ff
    ///   src       = 00:11:22:33:44:55
    ///   type      = 0x0800 (IPv4)
    /// ###[ IP ]###
    ///   version   = 4
    ///   ihl       = 5
    ///   ...
    /// ```
    fn show(&self) -> String {
        let mut output = String::new();

        if !self.inner.is_parsed() {
            output.push_str(&format!("###[ Packet: {} bytes ]###\n", self.inner.len()));
            output.push_str("  (not parsed - call parse() first)\n");
            return output;
        }

        let buf = self.inner.as_bytes();

        for layer_enum in self.inner.layer_enums() {
            let kind = layer_enum.kind();
            output.push_str(&format!("###[ {} ]###\n", kind.name()));

            // Get all fields for this layer
            let fields = layer_enum.show_fields(buf);

            // Calculate max field name length for alignment
            let max_name_len = fields.iter().map(|(name, _)| name.len()).max().unwrap_or(0);

            for (name, value) in fields {
                output.push_str(&format!(
                    "  {:<width$} = {}\n",
                    name,
                    value,
                    width = max_name_len
                ));
            }
        }

        // Show payload if any
        let payload = self.inner.payload();
        if !payload.is_empty() {
            output.push_str(&format!("###[ Raw Payload: {} bytes ]###\n", payload.len()));
            // Show first 32 bytes as hex preview
            let preview_len = payload.len().min(32);
            let hex_str: String = payload[..preview_len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            output.push_str(&format!("  {}", hex_str));
            if payload.len() > 32 {
                output.push_str("...");
            }
            output.push('\n');
        }

        output
    }

    /// Returns a compact one-line summary of the packet.
    ///
    /// Example: `Ether / IP / TCP 80 > 8080 [S]`
    fn summary(&self) -> String {
        if !self.inner.is_parsed() {
            return format!("Packet ({} bytes, unparsed)", self.inner.len());
        }

        let buf = self.inner.as_bytes();
        let layer_names: Vec<String> = self
            .inner
            .layers()
            .iter()
            .map(|l| l.kind.name().to_string())
            .collect();

        if layer_names.is_empty() {
            format!("Packet ({} bytes, no layers)", self.inner.len())
        } else {
            // Get summary of the last significant layer
            let layers = self.inner.layer_enums();
            if let Some(last) = layers.last() {
                let last_summary = last.summary(buf);
                format!(
                    "{} / {}",
                    layer_names[..layer_names.len() - 1].join(" / "),
                    last_summary
                )
            } else {
                layer_names.join(" / ")
            }
        }
    }

    /// Returns a hexdump of the packet bytes.
    fn hexdump(&self) -> String {
        hexdump_bytes(self.inner.as_bytes())
    }

    /// Dynamic field access - allows pkt.src, pkt.dst, etc.
    ///
    /// Searches through all layers for a field with the given name and returns
    /// its value. This enables Scapy-like field access syntax.
    ///
    /// Example:
    ///     >>> pkt.parse()
    ///     >>> print(pkt.src)  # Returns the MAC or IP source depending on layer
    fn __getattr__<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Py<PyAny>> {
        // Search through layers from bottom to top (like Scapy)
        for layer_enum in self.inner.layer_enums() {
            if let Some(result) = layer_enum.get_field(self.inner.as_bytes(), name) {
                return match result {
                    Ok(value) => field_value_to_python(py, value),
                    Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{}", e))),
                };
            }
        }
        Err(pyo3::exceptions::PyAttributeError::new_err(format!(
            "Packet has no field '{}'",
            name
        )))
    }

    /// Dynamic field mutation - allows pkt.src = "00:11:22:33:44:55", etc.
    ///
    /// Searches through all layers for a field with the given name and sets
    /// its value. This triggers copy-on-write semantics for the underlying buffer.
    ///
    /// Example:
    ///     >>> pkt.parse()
    ///     >>> pkt.src = "00:11:22:33:44:55"
    fn __setattr__(&mut self, name: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        // Search through layers to find which one has this field
        let layer_enums = self.inner.layer_enums();
        for layer_enum in &layer_enums {
            let field_names = layer_enum.field_names();
            if field_names.contains(&name) {
                // Convert Python value to FieldValue
                let field_value = python_to_field_value(value, name, layer_enum)?;

                // Use copy-on-write mutation
                self.inner.with_data_mut(|buf| {
                    if let Some(result) = layer_enum.set_field(buf, name, field_value) {
                        result
                            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}", e)))
                    } else {
                        Err(pyo3::exceptions::PyAttributeError::new_err(format!(
                            "Field '{}' not writable",
                            name
                        )))
                    }
                })?;
                return Ok(());
            }
        }
        Err(pyo3::exceptions::PyAttributeError::new_err(format!(
            "Packet has no field '{}'",
            name
        )))
    }

    /// Returns all field names available across all layers.
    #[getter]
    fn fields(&self) -> Vec<&'static str> {
        let mut all_fields = Vec::new();
        for layer_enum in self.inner.layer_enums() {
            for name in layer_enum.field_names() {
                if !all_fields.contains(name) {
                    all_fields.push(*name);
                }
            }
        }
        all_fields
    }

    /// Get a field value from a specific layer by kind.
    ///
    /// Args:
    ///     kind: The LayerKind to get the field from
    ///     name: The field name
    ///
    /// Returns:
    ///     The field value
    ///
    /// Raises:
    ///     KeyError: If the layer or field doesn't exist
    fn getfieldval<'py>(
        &self,
        py: Python<'py>,
        kind: PyLayerKind,
        name: &str,
    ) -> PyResult<Py<PyAny>> {
        for layer_enum in self.inner.layer_enums() {
            if layer_enum.kind() == kind.to_rust() {
                if let Some(result) = layer_enum.get_field(self.inner.as_bytes(), name) {
                    return match result {
                        Ok(value) => field_value_to_python(py, value),
                        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("{}", e))),
                    };
                } else {
                    return Err(pyo3::exceptions::PyKeyError::new_err(format!(
                        "Field '{}' not found in {} layer",
                        name,
                        kind.name()
                    )));
                }
            }
        }
        Err(pyo3::exceptions::PyKeyError::new_err(format!(
            "Layer {} not found in packet",
            kind.name()
        )))
    }
}

/// Convert a FieldValue to a Python object.
fn field_value_to_python(py: Python<'_>, value: FieldValue) -> PyResult<Py<PyAny>> {
    match value {
        FieldValue::U8(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::U16(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::U32(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::U64(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::Mac(v) => Ok(v.to_string().into_pyobject(py)?.into_any().unbind()),
        FieldValue::Ipv4(v) => Ok(v.to_string().into_pyobject(py)?.into_any().unbind()),
        FieldValue::Ipv6(v) => Ok(v.to_string().into_pyobject(py)?.into_any().unbind()),
        FieldValue::Bytes(v) => Ok(PyBytes::new(py, &v).into_any().unbind()),
        FieldValue::I8(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::I16(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::I32(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::I64(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::Bool(v) => Ok(v.into_pyobject(py)?.to_owned().into_any().unbind()),
        FieldValue::Str(v) => Ok(v.into_pyobject(py)?.into_any().unbind()),
        FieldValue::List(items) => {
            let py_list = pyo3::types::PyList::empty(py);
            for item in items {
                let py_item = field_value_to_python(py, item)?;
                py_list.append(py_item)?;
            }
            Ok(py_list.into_any().unbind())
        }
    }
}

/// Convert a Python value to a FieldValue based on context.
fn python_to_field_value(
    value: &Bound<'_, PyAny>,
    field_name: &str,
    _layer: &stackforge_core::LayerEnum,
) -> PyResult<FieldValue> {
    // Try to get the field descriptor to know the expected type
    // For now, we'll use heuristics based on field name and Python value type

    // If it's a string, try to parse as MAC or IP address
    if let Ok(s) = value.extract::<String>() {
        // Try MAC address first
        if let Ok(mac) = MacAddress::parse(&s) {
            return Ok(FieldValue::Mac(mac));
        }
        // Try IPv4
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Ok(FieldValue::Ipv4(ip));
        }
        // Try IPv6
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            return Ok(FieldValue::Ipv6(ip));
        }
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Cannot parse '{}' as a valid field value",
            s
        )));
    }

    // If it's bytes, return as Bytes
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(FieldValue::Bytes(bytes));
    }

    // Try numeric types
    if let Ok(v) = value.extract::<u64>() {
        // Try to figure out the right size based on the field
        // Use layer.field_names() and common field patterns
        let names_16 = [
            "type", "len", "sport", "dport", "window", "chksum", "urgptr", "id", "frag", "hwtype",
            "ptype", "op",
        ];
        let names_8 = [
            "ttl", "proto", "protocol", "ihl", "version", "tos", "hwlen", "plen", "code",
            "dataofs", "reserved",
        ];
        let names_32 = ["seq", "ack"];

        if names_8.contains(&field_name)
            || v <= u8::MAX as u64
                && names_16.iter().all(|n| *n != field_name)
                && names_32.iter().all(|n| *n != field_name)
        {
            if let Ok(v8) = u8::try_from(v) {
                return Ok(FieldValue::U8(v8));
            }
        }
        if names_16.contains(&field_name) {
            if let Ok(v16) = u16::try_from(v) {
                return Ok(FieldValue::U16(v16));
            }
        }
        if names_32.contains(&field_name) {
            if let Ok(v32) = u32::try_from(v) {
                return Ok(FieldValue::U32(v32));
            }
        }

        // Default fallback based on value range
        if v <= u8::MAX as u64 {
            return Ok(FieldValue::U8(v as u8));
        } else if v <= u16::MAX as u64 {
            return Ok(FieldValue::U16(v as u16));
        } else if v <= u32::MAX as u64 {
            return Ok(FieldValue::U32(v as u32));
        } else {
            return Ok(FieldValue::U64(v));
        }
    }

    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "Cannot convert Python value to field type for '{}'",
        field_name
    )))
}

/// Formats bytes as a hexdump string.
fn hexdump_bytes(data: &[u8]) -> String {
    let mut output = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        // Offset
        output.push_str(&format!("{:08x}  ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                output.push(' ');
            }
            output.push_str(&format!("{:02x} ", byte));
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                if j == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
        }

        // ASCII representation
        output.push(' ');
        output.push('|');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');
        output.push('\n');
    }
    output
}

// ============================================================================
// Layer Stack (for stacking layers with / operator)
// ============================================================================

/// A stack of protocol layers that can be combined using the / operator.
///
/// Example:
///     >>> from stackforge import Ether, IP, TCP
///     >>> pkt = Ether() / IP(dst="192.168.1.1") / TCP(dport=80)
///     >>> print(pkt.show())
#[pyclass(name = "LayerStack")]
#[derive(Clone)]
pub struct PyLayerStack {
    inner: RustLayerStack,
}

#[pymethods]
impl PyLayerStack {
    /// Create a new empty layer stack.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustLayerStack::new(),
        }
    }

    /// Build the layer stack into a Packet.
    fn build(&self) -> PyPacket {
        PyPacket {
            inner: self.inner.build_packet(),
        }
    }

    /// Build the layer stack into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Get the number of layers in the stack.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Stack another layer or layer stack on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut new_stack = self.inner.clone();

        // Try to extract as different layer types
        if let Ok(stack) = other.extract::<PyLayerStack>() {
            new_stack = new_stack.stack(stack.inner);
        } else if let Ok(eth) = other.extract::<PyEther>() {
            new_stack.add(RustLayerStackEntry::Ethernet(eth.inner));
        } else if let Ok(ip) = other.extract::<PyIP>() {
            new_stack.add(RustLayerStackEntry::Ipv4(ip.inner));
        } else if let Ok(tcp) = other.extract::<PyTCP>() {
            new_stack.add(RustLayerStackEntry::Tcp(tcp.inner));
        } else if let Ok(udp) = other.extract::<PyUDP>() {
            new_stack.add(RustLayerStackEntry::Udp(udp.inner));
        } else if let Ok(icmp) = other.extract::<PyICMP>() {
            new_stack.add(RustLayerStackEntry::Icmp(icmp.inner));
        } else if let Ok(arp) = other.extract::<PyARP>() {
            new_stack.add(RustLayerStackEntry::Arp(arp.inner));
        } else if let Ok(ssh) = other.extract::<PySSH>() {
            new_stack.add(RustLayerStackEntry::Ssh(ssh.inner));
        } else if let Ok(tls) = other.extract::<PyTLS>() {
            new_stack.add(RustLayerStackEntry::Tls(tls.inner));
        } else if let Ok(ipv6) = other.extract::<PyIPv6>() {
            new_stack.add(RustLayerStackEntry::Ipv6(ipv6.inner));
        } else if let Ok(icmpv6) = other.extract::<PyICMPv6>() {
            new_stack.add(RustLayerStackEntry::Icmpv6(icmpv6.inner));
        } else if let Ok(http) = other.extract::<PyHTTP>() {
            new_stack.add(RustLayerStackEntry::Raw(http.inner.build()));
        } else if let Ok(http_resp) = other.extract::<PyHTTPResponse>() {
            new_stack.add(RustLayerStackEntry::Raw(http_resp.inner.build()));
        } else if let Ok(quic) = other.extract::<PyQUIC>() {
            new_stack.add(RustLayerStackEntry::Raw(quic.inner.build()));
        } else if let Ok(http2) = other.extract::<PyHTTP2>() {
            new_stack.add(RustLayerStackEntry::Raw(http2.inner.build()));
        } else if let Ok(l2tp) = other.extract::<PyL2tp>() {
            new_stack.add(RustLayerStackEntry::L2tp(l2tp.inner));
        } else if let Ok(raw) = other.extract::<PyRaw>() {
            new_stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            new_stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: new_stack })
    }

    /// Right-hand division (for stacking raw bytes on left).
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut new_stack = RustLayerStack::new();

        // Add the left operand first
        if let Ok(bytes) = other.extract::<Vec<u8>>() {
            new_stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        // Then add our layers
        new_stack = new_stack.stack(self.inner.clone());

        Ok(PyLayerStack { inner: new_stack })
    }

    /// Show the packet structure (like Scapy's show()).
    fn show(&self) -> String {
        let pkt = self.inner.build_packet();
        show_packet(&pkt)
    }

    /// Get a summary of the packet.
    fn summary(&self) -> String {
        let pkt = self.inner.build_packet();
        summary_packet(&pkt)
    }

    fn __repr__(&self) -> String {
        let pkt = self.inner.build_packet();
        repr_packet(&pkt)
    }
}

// Helper functions for packet display
fn show_packet(pkt: &RustPacket) -> String {
    let mut output = String::new();
    let buf = pkt.as_bytes();

    for layer_enum in pkt.layer_enums() {
        let kind = layer_enum.kind();
        output.push_str(&format!("###[ {} ]###\n", kind.name()));

        let fields = layer_enum.show_fields(buf);
        let max_name_len = fields.iter().map(|(name, _)| name.len()).max().unwrap_or(0);

        for (name, value) in fields {
            output.push_str(&format!(
                "  {:<width$} = {}\n",
                name,
                value,
                width = max_name_len
            ));
        }
    }

    let payload = pkt.payload();
    if !payload.is_empty() {
        output.push_str(&format!("###[ Raw Payload: {} bytes ]###\n", payload.len()));
        let preview_len = payload.len().min(32);
        let hex_str: String = payload[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        output.push_str(&format!("  {}", hex_str));
        if payload.len() > 32 {
            output.push_str("...");
        }
        output.push('\n');
    }

    output
}

fn summary_packet(pkt: &RustPacket) -> String {
    let layer_names: Vec<String> = pkt
        .layers()
        .iter()
        .map(|l| l.kind.name().to_string())
        .collect();

    if layer_names.is_empty() {
        format!("Packet ({} bytes)", pkt.len())
    } else {
        layer_names.join(" / ")
    }
}

fn repr_packet(pkt: &RustPacket) -> String {
    let buf = pkt.as_bytes();
    let summaries: Vec<String> = pkt
        .layer_enums()
        .iter()
        .map(|layer| layer.summary(buf))
        .collect();

    if summaries.is_empty() {
        format!("<Packet len={}>", pkt.len())
    } else {
        format!("<{}>", summaries.join(" | "))
    }
}

// ============================================================================
// Ethernet Layer Builder
// ============================================================================

/// Ethernet II frame builder.
///
/// Example:
///     >>> eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
///     >>> print(eth.show())
#[pyclass(name = "Ether")]
#[derive(Clone)]
pub struct PyEther {
    inner: RustEthernetBuilder,
}

#[pymethods]
impl PyEther {
    /// Create a new Ethernet frame.
    ///
    /// Args:
    ///     dst: Destination MAC address (default: broadcast)
    ///     src: Source MAC address (default: 00:00:00:00:00:00)
    ///     type: EtherType (auto-set based on payload)
    #[new]
    #[pyo3(signature = (dst=None, src=None, r#type=None))]
    fn new(dst: Option<&str>, src: Option<&str>, r#type: Option<u16>) -> PyResult<Self> {
        let mut builder = RustEthernetBuilder::new();

        if let Some(dst_str) = dst {
            let mac = MacAddress::parse(dst_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid MAC: {}", e))
            })?;
            builder = builder.dst(mac);
        }

        if let Some(src_str) = src {
            let mac = MacAddress::parse(src_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid MAC: {}", e))
            })?;
            builder = builder.src(mac);
        }

        if let Some(etype) = r#type {
            builder = builder.ethertype(etype);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Ethernet(self.inner.clone()));

        // Add the other layer
        if let Ok(ip) = other.extract::<PyIP>() {
            stack.add(RustLayerStackEntry::Ipv4(ip.inner));
        } else if let Ok(ipv6) = other.extract::<PyIPv6>() {
            stack.add(RustLayerStackEntry::Ipv6(ipv6.inner));
        } else if let Ok(tcp) = other.extract::<PyTCP>() {
            stack.add(RustLayerStackEntry::Tcp(tcp.inner));
        } else if let Ok(arp) = other.extract::<PyARP>() {
            stack.add(RustLayerStackEntry::Arp(arp.inner));
        } else if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<Ether>".to_string()
    }
}

// ============================================================================
// IPv4 Layer Builder
// ============================================================================

/// IPv4 packet builder.
///
/// Example:
///     >>> ip = IP(dst="192.168.1.1", ttl=64)
///     >>> print(ip.show())
#[pyclass(name = "IP")]
#[derive(Clone)]
pub struct PyIP {
    inner: RustIpv4Builder,
}

#[pymethods]
impl PyIP {
    /// Create a new IPv4 packet.
    ///
    /// Args:
    ///     src: Source IP address
    ///     dst: Destination IP address
    ///     ttl: Time to live (default: 64)
    ///     proto: Protocol number (auto-set based on payload)
    ///     id: Identification field
    ///     flags: IP flags (DF, MF) - string or int
    ///     frag: Fragment offset
    ///     tos: Type of service
    #[new]
    #[pyo3(signature = (src=None, dst=None, ttl=None, proto=None, id=None, flags=None, frag=None, tos=None, len=None))]
    fn new(
        src: Option<&str>,
        dst: Option<&str>,
        ttl: Option<u8>,
        proto: Option<u8>,
        id: Option<u16>,
        flags: Option<&Bound<'_, PyAny>>,
        frag: Option<u16>,
        tos: Option<u8>,
        len: Option<u16>,
    ) -> PyResult<Self> {
        let mut builder = RustIpv4Builder::new();

        if let Some(src_str) = src {
            let ip: Ipv4Addr = src_str.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid IP: {}", e))
            })?;
            builder = builder.src(ip);
        }

        if let Some(dst_str) = dst {
            let ip: Ipv4Addr = dst_str.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid IP: {}", e))
            })?;
            builder = builder.dst(ip);
        }

        if let Some(t) = ttl {
            builder = builder.ttl(t);
        }

        if let Some(p) = proto {
            builder = builder.protocol(p);
        }

        if let Some(i) = id {
            builder = builder.id(i);
        }

        if let Some(flags_val) = flags {
            // Accept both string ("DF", "MF") and int (0, 1, 2, 3)
            if let Ok(flag_str) = flags_val.extract::<String>() {
                for c in flag_str.chars() {
                    match c {
                        'D' | 'd' => builder = builder.dont_fragment(),
                        'M' | 'm' => builder = builder.more_fragments(),
                        _ => {}
                    }
                }
            } else if let Ok(flag_int) = flags_val.extract::<u8>() {
                // Bit 0 = reserved, Bit 1 = DF, Bit 2 = MF
                if flag_int & 0x02 != 0 {
                    builder = builder.dont_fragment();
                }
                if flag_int & 0x01 != 0 {
                    builder = builder.more_fragments();
                }
            }
        }

        if let Some(f) = frag {
            builder = builder.frag_offset(f);
        }

        if let Some(t) = tos {
            builder = builder.tos(t);
        }

        if let Some(l) = len {
            builder = builder.total_len(l);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Ipv4(self.inner.clone()));

        // Add the other layer
        if let Ok(tcp) = other.extract::<PyTCP>() {
            stack.add(RustLayerStackEntry::Tcp(tcp.inner));
        } else if let Ok(udp) = other.extract::<PyUDP>() {
            stack.add(RustLayerStackEntry::Udp(udp.inner));
        } else if let Ok(icmp) = other.extract::<PyICMP>() {
            stack.add(RustLayerStackEntry::Icmp(icmp.inner));
        } else if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<IP>".to_string()
    }
}

// ============================================================================
// TCP Layer Builder
// ============================================================================

/// TCP segment builder.
///
/// Example:
///     >>> tcp = TCP(dport=80, sport=12345, flags="S")
///     >>> print(tcp.show())
#[pyclass(name = "TCP")]
#[derive(Clone)]
pub struct PyTCP {
    inner: RustTcpBuilder,
}

#[pymethods]
impl PyTCP {
    /// Create a new TCP segment.
    ///
    /// Args:
    ///     sport: Source port (default: 20)
    ///     dport: Destination port (default: 80)
    ///     seq: Sequence number
    ///     ack: Acknowledgment number
    ///     flags: TCP flags as string (S=SYN, A=ACK, F=FIN, R=RST, P=PSH) or int
    ///     window: Window size
    ///     urgptr: Urgent pointer
    #[new]
    #[pyo3(signature = (sport=None, dport=None, seq=None, ack=None, flags=None, window=None, dataofs=None, urgptr=None))]
    fn new(
        sport: Option<u16>,
        dport: Option<u16>,
        seq: Option<u32>,
        ack: Option<u32>,
        flags: Option<&Bound<'_, PyAny>>,
        window: Option<u16>,
        dataofs: Option<u8>,
        urgptr: Option<u16>,
    ) -> PyResult<Self> {
        let mut builder = RustTcpBuilder::new();

        if let Some(p) = sport {
            builder = builder.src_port(p);
        }

        if let Some(p) = dport {
            builder = builder.dst_port(p);
        }

        if let Some(s) = seq {
            builder = builder.seq(s);
        }

        if let Some(a) = ack {
            builder = builder.ack_num(a);
        }

        if let Some(flags_val) = flags {
            // Accept both string ("S", "SA", etc.) and int (0-255)
            if let Ok(flag_str) = flags_val.extract::<String>() {
                builder = builder.flags_str(&flag_str);
            } else if let Ok(flag_int) = flags_val.extract::<u8>() {
                // If flags = 0, no flags are set (which is valid)
                use stackforge_core::layer::tcp::TcpFlags;
                builder = builder.flags(TcpFlags::from_byte(flag_int));
            }
        }

        if let Some(w) = window {
            builder = builder.window(w);
        }

        if let Some(d) = dataofs {
            builder = builder.data_offset(d);
        }

        if let Some(u) = urgptr {
            builder = builder.urgptr(u);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Tcp(self.inner.clone()));

        // Add the other layer (TCP can have TLS or raw payload)
        if let Ok(tls) = other.extract::<PyTLS>() {
            stack.add(RustLayerStackEntry::Tls(tls.inner));
        } else if let Ok(ssh) = other.extract::<PySSH>() {
            stack.add(RustLayerStackEntry::Ssh(ssh.inner));
        } else if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<TCP>".to_string()
    }
}

// ============================================================================
// UDP Layer Builder
// ============================================================================

/// UDP datagram builder.
///
/// Example:
///     >>> udp = UDP(sport=1234, dport=53)
///     >>> print(udp.show())
#[pyclass(name = "UDP")]
#[derive(Clone)]
pub struct PyUDP {
    inner: RustUdpBuilder,
}

#[pymethods]
impl PyUDP {
    /// Create a new UDP datagram.
    ///
    /// Args:
    ///     sport: Source port (default: 53)
    ///     dport: Destination port (default: 53)
    ///     len: UDP length (auto-calculated if not specified)
    ///     chksum: UDP checksum (auto-calculated if not specified)
    #[new]
    #[pyo3(signature = (sport=None, dport=None, len=None, chksum=None))]
    fn new(
        sport: Option<u16>,
        dport: Option<u16>,
        len: Option<u16>,
        chksum: Option<u16>,
    ) -> PyResult<Self> {
        let mut builder = RustUdpBuilder::new();

        if let Some(p) = sport {
            builder = builder.src_port(p);
        }

        if let Some(p) = dport {
            builder = builder.dst_port(p);
        }

        if let Some(l) = len {
            builder = builder.length(l);
        }

        if let Some(c) = chksum {
            builder = builder.checksum(c);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Udp(self.inner.clone()));

        // Add the other layer (UDP can only have raw payload)
        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<UDP>".to_string()
    }
}

// ============================================================================
// ICMP Layer Builder
// ============================================================================

/// ICMP message builder.
///
/// Example:
///     >>> icmp = ICMP.echo_request(id=0x1234, seq=1)
///     >>> icmp = ICMP.dest_unreach(code=3)  # Port unreachable
#[pyclass(name = "ICMP")]
#[derive(Clone)]
pub struct PyICMP {
    inner: RustIcmpBuilder,
}

#[pymethods]
impl PyICMP {
    /// Create a generic ICMP message (use factory methods for specific types).
    ///
    /// Args:
    ///     type: ICMP type (0-255)
    ///     code: ICMP code (0-255)
    ///     chksum: Checksum (auto-calculated if not specified)
    #[new]
    #[pyo3(signature = (r#type=8, code=0, chksum=None))]
    fn new(r#type: Option<u8>, code: Option<u8>, chksum: Option<u16>) -> PyResult<Self> {
        let mut builder = RustIcmpBuilder::new();

        if let Some(t) = r#type {
            builder = builder.icmp_type(t);
        }

        if let Some(c) = code {
            builder = builder.code(c);
        }

        if let Some(ck) = chksum {
            builder = builder.checksum(ck);
        }

        Ok(Self { inner: builder })
    }

    // ========== Factory Methods (Class Methods) ==========

    /// Create an ICMP echo request (ping).
    ///
    /// Args:
    ///     id: Identifier
    ///     seq: Sequence number
    ///
    /// Example:
    ///     >>> ping = ICMP.echo_request(id=0x1234, seq=1)
    #[classmethod]
    #[pyo3(signature = (id, seq))]
    fn echo_request(_cls: &Bound<'_, pyo3::types::PyType>, id: u16, seq: u16) -> Self {
        Self {
            inner: RustIcmpBuilder::echo_request(id, seq),
        }
    }

    /// Create an ICMP echo reply (pong).
    ///
    /// Args:
    ///     id: Identifier (should match request)
    ///     seq: Sequence number (should match request)
    #[classmethod]
    #[pyo3(signature = (id, seq))]
    fn echo_reply(_cls: &Bound<'_, pyo3::types::PyType>, id: u16, seq: u16) -> Self {
        Self {
            inner: RustIcmpBuilder::echo_reply(id, seq),
        }
    }

    /// Create an ICMP destination unreachable message.
    ///
    /// Args:
    ///     code: Unreachable code (0=net, 1=host, 2=protocol, 3=port, 4=frag-needed)
    ///
    /// Example:
    ///     >>> icmp = ICMP.dest_unreach(code=3)  # Port unreachable
    #[classmethod]
    #[pyo3(signature = (code))]
    fn dest_unreach(_cls: &Bound<'_, pyo3::types::PyType>, code: u8) -> Self {
        Self {
            inner: RustIcmpBuilder::dest_unreach(code),
        }
    }

    /// Create an ICMP destination unreachable - fragmentation needed.
    ///
    /// Args:
    ///     mtu: Next-hop MTU value
    #[classmethod]
    #[pyo3(signature = (mtu))]
    fn dest_unreach_need_frag(_cls: &Bound<'_, pyo3::types::PyType>, mtu: u16) -> Self {
        Self {
            inner: RustIcmpBuilder::dest_unreach_need_frag(mtu),
        }
    }

    /// Create an ICMP redirect message.
    ///
    /// Args:
    ///     code: Redirect code (0=network, 1=host, 2=TOS+network, 3=TOS+host)
    ///     gateway: Gateway IP address (as string, e.g., "192.168.1.1")
    #[classmethod]
    #[pyo3(signature = (code, gateway))]
    fn redirect(_cls: &Bound<'_, pyo3::types::PyType>, code: u8, gateway: &str) -> PyResult<Self> {
        let gw: Ipv4Addr = gateway.parse().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("Invalid IPv4 address for gateway")
        })?;

        Ok(Self {
            inner: RustIcmpBuilder::redirect(code, gw),
        })
    }

    /// Create an ICMP time exceeded message.
    ///
    /// Args:
    ///     code: Time exceeded code (0=TTL exceeded, 1=fragment reassembly)
    #[classmethod]
    #[pyo3(signature = (code=0))]
    fn time_exceeded(_cls: &Bound<'_, pyo3::types::PyType>, code: u8) -> Self {
        Self {
            inner: RustIcmpBuilder::time_exceeded(code),
        }
    }

    /// Create an ICMP parameter problem message.
    ///
    /// Args:
    ///     ptr: Pointer to the problematic byte
    #[classmethod]
    #[pyo3(signature = (ptr))]
    fn param_problem(_cls: &Bound<'_, pyo3::types::PyType>, ptr: u8) -> Self {
        Self {
            inner: RustIcmpBuilder::param_problem(ptr),
        }
    }

    /// Create an ICMP timestamp request.
    ///
    /// Args:
    ///     id: Identifier
    ///     seq: Sequence number
    ///     ts_ori: Originate timestamp (milliseconds since midnight UT)
    ///     ts_rx: Receive timestamp (0 for request)
    ///     ts_tx: Transmit timestamp (0 for request)
    #[classmethod]
    #[pyo3(signature = (id, seq, ts_ori=0, ts_rx=0, ts_tx=0))]
    fn timestamp_request(
        _cls: &Bound<'_, pyo3::types::PyType>,
        id: u16,
        seq: u16,
        ts_ori: u32,
        ts_rx: u32,
        ts_tx: u32,
    ) -> Self {
        Self {
            inner: RustIcmpBuilder::timestamp_request(id, seq, ts_ori, ts_rx, ts_tx),
        }
    }

    /// Create an ICMP timestamp reply.
    ///
    /// Args:
    ///     id: Identifier
    ///     seq: Sequence number
    ///     ts_ori: Originate timestamp from request
    ///     ts_rx: Receive timestamp
    ///     ts_tx: Transmit timestamp
    #[classmethod]
    #[pyo3(signature = (id, seq, ts_ori, ts_rx, ts_tx))]
    fn timestamp_reply(
        _cls: &Bound<'_, pyo3::types::PyType>,
        id: u16,
        seq: u16,
        ts_ori: u32,
        ts_rx: u32,
        ts_tx: u32,
    ) -> Self {
        Self {
            inner: RustIcmpBuilder::timestamp_reply(id, seq, ts_ori, ts_rx, ts_tx),
        }
    }

    // ========== Instance Methods ==========

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Icmp(self.inner.clone()));

        // Add the other layer (ICMP can only have raw payload)
        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<ICMP>".to_string()
    }
}

// ============================================================================
// ARP Layer Builder
// ============================================================================

/// ARP packet builder.
///
/// Example:
///     >>> arp = ARP(op="who-has", pdst="192.168.1.1")
///     >>> print(arp.show())
#[pyclass(name = "ARP")]
#[derive(Clone)]
pub struct PyARP {
    inner: RustArpBuilder,
}

#[pymethods]
impl PyARP {
    /// Create a new ARP packet.
    ///
    /// Args:
    ///     op: Operation ("who-has" or "is-at", or numeric 1/2)
    ///     hwtype: Hardware type (default: 1 for Ethernet)
    ///     ptype: Protocol type (default: 0x0800 for IPv4)
    ///     hwsrc: Hardware source address
    ///     psrc: Protocol source address
    ///     hwdst: Hardware destination address
    ///     pdst: Protocol destination address
    #[new]
    #[pyo3(signature = (op=None, hwtype=None, ptype=None, hwsrc=None, psrc=None, hwdst=None, pdst=None))]
    fn new(
        op: Option<&Bound<'_, PyAny>>,
        hwtype: Option<u16>,
        ptype: Option<u16>,
        hwsrc: Option<&str>,
        psrc: Option<&str>,
        hwdst: Option<&str>,
        pdst: Option<&str>,
    ) -> PyResult<Self> {
        let mut builder = RustArpBuilder::new();

        if let Some(op_val) = op {
            if let Ok(op_str) = op_val.extract::<String>() {
                match op_str.to_lowercase().as_str() {
                    "who-has" | "request" | "1" => builder = builder.op(1), // REQUEST
                    "is-at" | "reply" | "2" => builder = builder.op(2),     // REPLY
                    _ => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "Invalid ARP operation",
                        ));
                    }
                }
            } else if let Ok(op_num) = op_val.extract::<u16>() {
                builder = builder.op(op_num);
            }
        }

        if let Some(hwt) = hwtype {
            builder = builder.hwtype(hwt);
        }

        if let Some(pt) = ptype {
            builder = builder.ptype(pt);
        }

        if let Some(mac_str) = hwsrc {
            let mac = MacAddress::parse(mac_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid MAC: {}", e))
            })?;
            builder = builder.hwsrc(mac);
        }

        if let Some(ip_str) = psrc {
            let ip: Ipv4Addr = ip_str.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid IP: {}", e))
            })?;
            builder = builder.psrc(ip);
        }

        if let Some(mac_str) = hwdst {
            let mac = MacAddress::parse(mac_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid MAC: {}", e))
            })?;
            builder = builder.hwdst(mac);
        }

        if let Some(ip_str) = pdst {
            let ip: Ipv4Addr = ip_str.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Invalid IP: {}", e))
            })?;
            builder = builder.pdst(ip);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Arp(self.inner.clone()));

        // ARP doesn't really have payloads, but support raw data
        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<ARP>".to_string()
    }
}

// ============================================================================
// Raw Layer (Payload)
// ============================================================================

/// Raw payload data.
///
/// Example:
///     >>> raw = Raw(load=b"Hello, World!")
///     >>> raw = Raw.from_hex("deadbeef")
///     >>> raw = Raw.zeros(100)
#[pyclass(name = "Raw")]
#[derive(Clone)]
pub struct PyRaw {
    data: Vec<u8>,
}

#[pymethods]
impl PyRaw {
    /// Create a raw payload layer.
    ///
    /// Args:
    ///     load: Raw bytes payload (bytes or string)
    #[new]
    #[pyo3(signature = (load=None))]
    fn new(load: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let data = if let Some(l) = load {
            if let Ok(bytes) = l.extract::<Vec<u8>>() {
                bytes
            } else if let Ok(s) = l.extract::<String>() {
                s.into_bytes()
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "load must be bytes or string",
                ));
            }
        } else {
            Vec::new()
        };

        Ok(Self { data })
    }

    /// Create a Raw layer from a hex string.
    ///
    /// Args:
    ///     hex_str: Hex string (e.g., "deadbeef" or "de:ad:be:ef")
    ///
    /// Returns:
    ///     Raw layer with the decoded bytes
    ///
    /// Example:
    ///     >>> raw = Raw.from_hex("deadbeef")
    ///     >>> raw = Raw.from_hex("de ad be ef")
    #[staticmethod]
    fn from_hex(hex_str: &str) -> PyResult<Self> {
        // Remove common separators (spaces, colons, dashes)
        let clean: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        if clean.is_empty() || clean.len() % 2 != 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Invalid hex string: must be non-empty with even number of hex digits",
            ));
        }

        let bytes: Result<Vec<u8>, _> = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
            .collect();

        match bytes {
            Ok(data) => Ok(Self { data }),
            Err(_) => Err(pyo3::exceptions::PyValueError::new_err(
                "Invalid hex string",
            )),
        }
    }

    /// Create a Raw layer filled with zeros.
    ///
    /// Args:
    ///     length: Number of zero bytes
    ///
    /// Example:
    ///     >>> raw = Raw.zeros(100)
    #[staticmethod]
    fn zeros(length: usize) -> Self {
        Self {
            data: vec![0u8; length],
        }
    }

    /// Create a Raw layer with a repeated byte value.
    ///
    /// Args:
    ///     byte: Byte value to repeat (0-255)
    ///     count: Number of times to repeat
    ///
    /// Example:
    ///     >>> raw = Raw.repeat(0x41, 10)  # "AAAAAAAAAA"
    #[staticmethod]
    fn repeat(byte: u8, count: usize) -> Self {
        Self {
            data: vec![byte; count],
        }
    }

    /// Create a Raw layer with a repeated pattern.
    ///
    /// Args:
    ///     pattern: Bytes pattern to repeat
    ///     length: Total length of the result
    ///
    /// Example:
    ///     >>> raw = Raw.pattern(b"AB", 7)  # b"ABABABA"
    #[staticmethod]
    fn pattern(pattern: Vec<u8>, length: usize) -> Self {
        Self {
            data: pattern.iter().cycle().take(length).copied().collect(),
        }
    }

    /// Get the raw payload data.
    #[getter]
    fn load<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data)
    }

    /// Get the hex representation of the payload.
    #[getter]
    fn hex(&self) -> String {
        self.data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Get a hex representation with spaces between bytes.
    fn hexdump(&self) -> String {
        self.data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Pad the payload to a minimum length with zeros.
    fn pad(&self, min_len: usize) -> Self {
        let mut data = self.data.clone();
        if data.len() < min_len {
            data.resize(min_len, 0);
        }
        Self { data }
    }

    /// Pad the payload to a minimum length with a specific byte.
    fn pad_with(&self, min_len: usize, byte: u8) -> Self {
        let mut data = self.data.clone();
        if data.len() < min_len {
            data.resize(min_len, byte);
        }
        Self { data }
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Raw(self.data.clone()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data)
    }

    fn __len__(&self) -> usize {
        self.data.len()
    }

    fn __repr__(&self) -> String {
        if self.data.len() <= 16 {
            format!("<Raw load={}>", self.hex())
        } else {
            format!("<Raw load={} bytes>", self.data.len())
        }
    }

    fn __str__(&self) -> String {
        self.hexdump()
    }
}

// ============================================================================
// SSH Layer Builder
// ============================================================================

/// SSH version exchange builder.
///
/// Example:
///     >>> ssh = SSH.version_exchange("OpenSSH_9.2p1")
///     >>> ssh = SSH()  # default version string
#[pyclass(name = "SSH")]
#[derive(Clone)]
pub struct PySSH {
    inner: RustSshBuilder,
}

#[pymethods]
impl PySSH {
    /// Create a new SSH version exchange message.
    ///
    /// Args:
    ///     version: SSH version string (default: "stackforge")
    #[new]
    #[pyo3(signature = (version=None))]
    fn new(version: Option<&str>) -> PyResult<Self> {
        let builder = if let Some(v) = version {
            RustSshBuilder::version_exchange(v)
        } else {
            RustSshBuilder::new()
        };
        Ok(Self { inner: builder })
    }

    /// Create an SSH version exchange message.
    ///
    /// Args:
    ///     version: Version string (e.g., "OpenSSH_9.2p1")
    ///
    /// Example:
    ///     >>> ssh = SSH.version_exchange("OpenSSH_9.2p1")
    #[classmethod]
    #[pyo3(signature = (version))]
    fn version_exchange(_cls: &Bound<'_, pyo3::types::PyType>, version: &str) -> Self {
        Self {
            inner: RustSshBuilder::version_exchange(version),
        }
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Ssh(self.inner.clone()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<SSH>".to_string()
    }
}

// ============================================================================
// TLS Layer Builder
// ============================================================================

/// TLS record builder.
///
/// Constructs TLS record layer packets with configurable content type,
/// version, and fragment data. Supports the "Permissive Parser, Explicit
/// Builder" pattern for security research and fuzzing.
///
/// Example:
///     >>> tls = TLS(type=22, version=0x0303)
///     >>> tls = TLS()  # default: Handshake, TLS 1.2
#[pyclass(name = "TLS")]
#[derive(Clone)]
pub struct PyTLS {
    inner: RustTlsRecordBuilder,
}

#[pymethods]
impl PyTLS {
    /// Create a new TLS record.
    ///
    /// Args:
    ///     type: Content type (20=CCS, 21=Alert, 22=Handshake, 23=AppData)
    ///     version: Protocol version (e.g., 0x0303 for TLS 1.2)
    ///     len: Explicit length (None = auto-calculate)
    ///     fragment: Fragment data bytes
    #[new]
    #[pyo3(signature = (r#type=None, version=None, len=None, fragment=None))]
    fn new(
        r#type: Option<u8>,
        version: Option<u16>,
        len: Option<u16>,
        fragment: Option<Vec<u8>>,
    ) -> Self {
        let mut builder = RustTlsRecordBuilder::new();
        if let Some(ct) = r#type {
            builder = builder.content_type_raw(ct);
        }
        if let Some(v) = version {
            builder = builder.version(v);
        }
        if let Some(l) = len {
            builder = builder.length(Some(l));
        }
        if let Some(f) = fragment {
            builder = builder.fragment(f);
        }
        Self { inner: builder }
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Tls(self.inner.clone()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<TLS>".to_string()
    }
}

// ============================================================================
// IPv6 Layer Builder
// ============================================================================

/// IPv6 packet builder.
///
/// Example:
///     >>> ip6 = IPv6(src="::1", dst="2001:db8::1", hop_limit=64)
///     >>> pkt = Ether() / IPv6(dst="::1") / ICMPv6.echo_request(id=1, seq=1)
#[pyclass(name = "IPv6")]
#[derive(Clone)]
pub struct PyIPv6 {
    inner: RustIpv6Builder,
}

#[pymethods]
impl PyIPv6 {
    /// Create a new IPv6 packet.
    ///
    /// Args:
    ///     src: Source IPv6 address
    ///     dst: Destination IPv6 address
    ///     hop_limit: Hop limit (analogous to TTL)
    ///     traffic_class: Traffic class byte
    ///     flow_label: Flow label (20 bits)
    ///     next_header: Next header protocol number
    #[new]
    #[pyo3(signature = (src=None, dst=None, hop_limit=None, traffic_class=None, flow_label=None, next_header=None))]
    fn new(
        src: Option<&str>,
        dst: Option<&str>,
        hop_limit: Option<u8>,
        traffic_class: Option<u8>,
        flow_label: Option<u32>,
        next_header: Option<u8>,
    ) -> PyResult<Self> {
        let mut builder = RustIpv6Builder::new();
        if let Some(s) = src {
            let addr: Ipv6Addr = s.parse().map_err(|e: std::net::AddrParseError| {
                pyo3::exceptions::PyValueError::new_err(e.to_string())
            })?;
            builder = builder.src(addr);
        }
        if let Some(d) = dst {
            let addr: Ipv6Addr = d.parse().map_err(|e: std::net::AddrParseError| {
                pyo3::exceptions::PyValueError::new_err(e.to_string())
            })?;
            builder = builder.dst(addr);
        }
        if let Some(h) = hop_limit {
            builder = builder.hop_limit(h);
        }
        if let Some(tc) = traffic_class {
            builder = builder.traffic_class(tc);
        }
        if let Some(fl) = flow_label {
            builder = builder.flow_label(fl);
        }
        if let Some(nh) = next_header {
            builder = builder.next_header(nh);
        }
        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Ipv6(self.inner.clone()));

        if let Ok(icmpv6) = other.extract::<PyICMPv6>() {
            stack.add(RustLayerStackEntry::Icmpv6(icmpv6.inner));
        } else if let Ok(tcp) = other.extract::<PyTCP>() {
            stack.add(RustLayerStackEntry::Tcp(tcp.inner));
        } else if let Ok(udp) = other.extract::<PyUDP>() {
            stack.add(RustLayerStackEntry::Udp(udp.inner));
        } else if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division (for Ether() / IPv6()).
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(eth) = other.extract::<PyEther>() {
            stack.add(RustLayerStackEntry::Ethernet(eth.inner));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Ipv6(self.inner.clone()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.clone().build())
    }

    /// Build the layer into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.clone().build())
    }

    fn __repr__(&self) -> String {
        "<IPv6>".to_string()
    }
}

// ============================================================================
// ICMPv6 Layer Builder
// ============================================================================

/// ICMPv6 message builder.
///
/// Example:
///     >>> icmpv6 = ICMPv6.echo_request(id=0x1234, seq=1)
///     >>> icmpv6 = ICMPv6.neighbor_solicitation(target="fe80::1")
#[pyclass(name = "ICMPv6")]
#[derive(Clone)]
pub struct PyICMPv6 {
    inner: RustIcmpv6Builder,
}

#[pymethods]
impl PyICMPv6 {
    /// Create a generic ICMPv6 message (use factory methods for specific types).
    ///
    /// Args:
    ///     type: ICMPv6 type (0-255)
    ///     code: ICMPv6 code (0-255)
    ///     chksum: Checksum (auto-calculated if not specified)
    #[new]
    #[pyo3(signature = (r#type=128, code=0, chksum=None))]
    fn new(r#type: Option<u8>, code: Option<u8>, chksum: Option<u16>) -> PyResult<Self> {
        let mut builder = RustIcmpv6Builder::new();
        if let Some(t) = r#type {
            builder = builder.icmpv6_type(t);
        }
        if let Some(c) = code {
            builder = builder.code(c);
        }
        if let Some(ck) = chksum {
            builder = builder.checksum(ck);
        }
        Ok(Self { inner: builder })
    }

    // ========== Factory Methods (Class Methods) ==========

    /// Create an ICMPv6 echo request (ping6).
    ///
    /// Args:
    ///     id: Identifier
    ///     seq: Sequence number
    #[classmethod]
    #[pyo3(signature = (id, seq))]
    fn echo_request(_cls: &Bound<'_, pyo3::types::PyType>, id: u16, seq: u16) -> Self {
        Self {
            inner: RustIcmpv6Builder::echo_request(id, seq),
        }
    }

    /// Create an ICMPv6 echo reply (pong6).
    ///
    /// Args:
    ///     id: Identifier (should match request)
    ///     seq: Sequence number (should match request)
    #[classmethod]
    #[pyo3(signature = (id, seq))]
    fn echo_reply(_cls: &Bound<'_, pyo3::types::PyType>, id: u16, seq: u16) -> Self {
        Self {
            inner: RustIcmpv6Builder::echo_reply(id, seq),
        }
    }

    /// Create a Neighbor Solicitation (NDP) packet.
    ///
    /// Args:
    ///     target: Target IPv6 address (as string, e.g., "fe80::1")
    #[classmethod]
    #[pyo3(signature = (target))]
    fn neighbor_solicitation(
        _cls: &Bound<'_, pyo3::types::PyType>,
        target: &str,
    ) -> PyResult<Self> {
        let addr: Ipv6Addr = target.parse().map_err(|e: std::net::AddrParseError| {
            pyo3::exceptions::PyValueError::new_err(e.to_string())
        })?;
        Ok(Self {
            inner: RustIcmpv6Builder::neighbor_solicitation(addr),
        })
    }

    /// Create a Neighbor Advertisement (NDP) packet.
    ///
    /// Args:
    ///     target: Target IPv6 address (as string, e.g., "fe80::1")
    #[classmethod]
    #[pyo3(signature = (target))]
    fn neighbor_advertisement(
        _cls: &Bound<'_, pyo3::types::PyType>,
        target: &str,
    ) -> PyResult<Self> {
        let addr: Ipv6Addr = target.parse().map_err(|e: std::net::AddrParseError| {
            pyo3::exceptions::PyValueError::new_err(e.to_string())
        })?;
        Ok(Self {
            inner: RustIcmpv6Builder::neighbor_advertisement(addr),
        })
    }

    /// Create a Router Solicitation (NDP) packet.
    #[classmethod]
    fn router_solicitation(_cls: &Bound<'_, pyo3::types::PyType>) -> Self {
        Self {
            inner: RustIcmpv6Builder::router_solicitation(),
        }
    }

    /// Create a Router Advertisement (NDP) packet.
    #[classmethod]
    fn router_advertisement(_cls: &Bound<'_, pyo3::types::PyType>) -> Self {
        Self {
            inner: RustIcmpv6Builder::router_advertisement(),
        }
    }

    // ========== Instance Methods ==========

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Icmpv6(self.inner.clone()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division (for IPv6() / ICMPv6()).
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(ipv6) = other.extract::<PyIPv6>() {
            stack.add(RustLayerStackEntry::Ipv6(ipv6.inner));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Icmpv6(self.inner.clone()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the layer into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<ICMPv6>".to_string()
    }
}

// ============================================================================
// HTTP Layer Builder (request)
// ============================================================================

/// HTTP/1.x request builder.
///
/// Example:
///     >>> http = HTTP(method="GET", uri="/index.html")
///     >>> http = HTTP(method="POST", uri="/api", body=b"data")
#[pyclass(name = "HTTP")]
#[derive(Clone)]
pub struct PyHTTP {
    inner: RustHttpRequestBuilder,
}

#[pymethods]
impl PyHTTP {
    /// Create a new HTTP/1.x request.
    ///
    /// Args:
    ///     method: HTTP method (default: "GET")
    ///     uri: Request URI (default: "/")
    ///     version: HTTP version (default: "HTTP/1.1")
    ///     headers: List of (name, value) header tuples
    ///     body: Request body bytes
    #[new]
    #[pyo3(signature = (method=None, uri=None, version=None, body=None))]
    fn new(
        method: Option<&str>,
        uri: Option<&str>,
        version: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut builder = RustHttpRequestBuilder::new();
        if let Some(m) = method {
            builder = builder.method(m);
        }
        if let Some(u) = uri {
            builder = builder.uri(u);
        }
        if let Some(v) = version {
            builder = builder.version(v);
        }
        if let Some(b) = body {
            builder = builder.body(b);
        }
        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Raw(self.inner.build()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division.
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Raw(self.inner.build()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the layer into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<HTTP>".to_string()
    }
}

// ============================================================================
// HTTP Response Layer Builder
// ============================================================================

/// HTTP/1.x response builder.
///
/// Example:
///     >>> resp = HTTPResponse(status=200, reason="OK", body=b"hello")
#[pyclass(name = "HTTPResponse")]
#[derive(Clone)]
pub struct PyHTTPResponse {
    inner: RustHttpResponseBuilder,
}

#[pymethods]
impl PyHTTPResponse {
    /// Create a new HTTP/1.x response.
    ///
    /// Args:
    ///     status: HTTP status code (default: 200)
    ///     reason: Reason phrase (default: "OK")
    ///     version: HTTP version (default: "HTTP/1.1")
    ///     body: Response body bytes
    #[new]
    #[pyo3(signature = (status=None, reason=None, version=None, body=None))]
    fn new(
        status: Option<u16>,
        reason: Option<&str>,
        version: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut builder = RustHttpResponseBuilder::new();
        if let Some(s) = status {
            let r = reason.unwrap_or("OK");
            builder = builder.status(s, r);
        } else if let Some(r) = reason {
            builder = builder.status(200, r);
        }
        if let Some(v) = version {
            builder = builder.version(v);
        }
        if let Some(b) = body {
            builder = builder.body(b);
        }
        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Raw(self.inner.build()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division.
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Raw(self.inner.build()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the layer into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the layer into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<HTTPResponse>".to_string()
    }
}

// ============================================================================
// QUIC Layer Builder
// ============================================================================

/// QUIC packet builder (RFC 9000).
///
/// Example:
///     >>> quic = QUIC.initial(dst_conn_id=bytes([1,2,3,4]))
///     >>> quic = QUIC.one_rtt(payload=b"\x01")  # PING frame
#[pyclass(name = "QUIC")]
#[derive(Clone)]
pub struct PyQUIC {
    inner: RustQuicBuilder,
}

#[pymethods]
impl PyQUIC {
    /// Create a new QUIC packet builder.
    ///
    /// Args:
    ///     dst_conn_id: Destination connection ID bytes
    ///     src_conn_id: Source connection ID bytes (long header only)
    ///     payload: Plaintext payload bytes
    ///     packet_number: Packet number
    #[new]
    #[pyo3(signature = (dst_conn_id=None, src_conn_id=None, payload=None, packet_number=None))]
    fn new(
        dst_conn_id: Option<Vec<u8>>,
        src_conn_id: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
        packet_number: Option<u32>,
    ) -> PyResult<Self> {
        let mut builder = RustQuicBuilder::new();
        if let Some(d) = dst_conn_id {
            builder = builder.dst_conn_id(d);
        }
        if let Some(s) = src_conn_id {
            builder = builder.src_conn_id(s);
        }
        if let Some(p) = payload {
            builder = builder.payload(p);
        }
        if let Some(n) = packet_number {
            builder = builder.packet_number(n);
        }
        Ok(Self { inner: builder })
    }

    // ========== Factory Methods (Class Methods) ==========

    /// Create an Initial QUIC packet (long header).
    #[classmethod]
    #[pyo3(signature = (dst_conn_id=None, src_conn_id=None, payload=None))]
    fn initial(
        _cls: &Bound<'_, pyo3::types::PyType>,
        dst_conn_id: Option<Vec<u8>>,
        src_conn_id: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
    ) -> Self {
        let mut builder = RustQuicBuilder::initial();
        if let Some(d) = dst_conn_id {
            builder = builder.dst_conn_id(d);
        }
        if let Some(s) = src_conn_id {
            builder = builder.src_conn_id(s);
        }
        if let Some(p) = payload {
            builder = builder.payload(p);
        }
        Self { inner: builder }
    }

    /// Create a Handshake QUIC packet (long header).
    #[classmethod]
    #[pyo3(signature = (dst_conn_id=None, payload=None))]
    fn handshake(
        _cls: &Bound<'_, pyo3::types::PyType>,
        dst_conn_id: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
    ) -> Self {
        let mut builder = RustQuicBuilder::handshake();
        if let Some(d) = dst_conn_id {
            builder = builder.dst_conn_id(d);
        }
        if let Some(p) = payload {
            builder = builder.payload(p);
        }
        Self { inner: builder }
    }

    /// Create a 1-RTT QUIC packet (short header).
    #[classmethod]
    #[pyo3(signature = (dst_conn_id=None, payload=None))]
    fn one_rtt(
        _cls: &Bound<'_, pyo3::types::PyType>,
        dst_conn_id: Option<Vec<u8>>,
        payload: Option<Vec<u8>>,
    ) -> Self {
        let mut builder = RustQuicBuilder::one_rtt();
        if let Some(d) = dst_conn_id {
            builder = builder.dst_conn_id(d);
        }
        if let Some(p) = payload {
            builder = builder.payload(p);
        }
        Self { inner: builder }
    }

    // ========== Instance Methods ==========

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Raw(self.inner.build()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division.
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Raw(self.inner.build()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the QUIC packet into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the QUIC packet into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<QUIC>".to_string()
    }
}

// ============================================================================
// HTTP/2 Layer Builder
// ============================================================================

/// HTTP/2 connection/frame builder.
///
/// Example:
///     >>> h2 = HTTP2()  # connection preface + empty SETTINGS
///     >>> h2 = HTTP2.settings_ack()
#[pyclass(name = "HTTP2")]
#[derive(Clone)]
pub struct PyHTTP2 {
    inner: RustHttp2Builder,
}

#[pymethods]
impl PyHTTP2 {
    /// Create a new HTTP/2 connection builder (includes connection preface).
    #[new]
    #[pyo3(signature = (include_preface=true))]
    fn new(include_preface: bool) -> PyResult<Self> {
        let builder = if include_preface {
            RustHttp2Builder::new()
        } else {
            RustHttp2Builder::without_preface()
        };
        Ok(Self { inner: builder })
    }

    /// Create an HTTP/2 builder from a pre-built SETTINGS frame (no preface).
    #[classmethod]
    fn settings_ack(_cls: &Bound<'_, pyo3::types::PyType>) -> Self {
        Self {
            inner: RustHttp2Builder::without_preface().frame(RustHttp2FrameBuilder::settings_ack()),
        }
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::Raw(self.inner.build()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division.
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::Raw(self.inner.build()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the HTTP/2 bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the HTTP/2 bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<HTTP2>".to_string()
    }
}

// ============================================================================
// L2TP Layer Builder
// ============================================================================

/// L2TPv2 packet builder (RFC 2661).
///
/// Example:
///     >>> l2tp = L2TP()  # default data message
///     >>> l2tp_ctrl = L2TP(msg_type=1, has_length=True, tunnel_id=1, session_id=2)
#[pyclass(name = "L2TP")]
#[derive(Clone)]
pub struct PyL2tp {
    inner: RustL2tpBuilder,
}

#[pymethods]
impl PyL2tp {
    /// Create a new L2TP packet builder.
    ///
    /// Args:
    ///     msg_type: 0=data (default), 1=control
    ///     has_length: if True the Length field is included
    ///     has_sequence: if True Ns and Nr fields are included
    ///     tunnel_id: Tunnel ID (default 0)
    ///     session_id: Session ID (default 0)
    ///     ns: Send sequence number (enables S bit)
    ///     nr: Receive sequence number (enables S bit)
    ///     payload: Raw payload bytes
    #[new]
    #[pyo3(signature = (msg_type=None, has_length=None, has_sequence=None, tunnel_id=None, session_id=None, ns=None, nr=None, payload=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        msg_type: Option<u8>,
        has_length: Option<bool>,
        has_sequence: Option<bool>,
        tunnel_id: Option<u16>,
        session_id: Option<u16>,
        ns: Option<u16>,
        nr: Option<u16>,
        payload: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut builder = RustL2tpBuilder::new();

        if let Some(mt) = msg_type {
            if mt != 0 {
                builder = builder.control();
            }
        }
        if has_length.unwrap_or(false) {
            builder = builder.with_length();
        }
        if has_sequence.unwrap_or(false) {
            builder = builder.with_sequence();
        }
        if let Some(tid) = tunnel_id {
            builder = builder.tunnel_id(tid);
        }
        if let Some(sid) = session_id {
            builder = builder.session_id(sid);
        }
        if let Some(n) = ns {
            builder = builder.ns(n);
        }
        if let Some(n) = nr {
            builder = builder.nr(n);
        }
        if let Some(p) = payload {
            builder = builder.payload(p);
        }

        Ok(Self { inner: builder })
    }

    /// Stack another layer on top using the / operator.
    fn __truediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();
        stack.add(RustLayerStackEntry::L2tp(self.inner.clone()));

        if let Ok(raw) = other.extract::<PyRaw>() {
            stack.add(RustLayerStackEntry::Raw(raw.data));
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = stack.stack(layer_stack.inner);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type",
            ));
        }

        Ok(PyLayerStack { inner: stack })
    }

    /// Right-hand division.
    fn __rtruediv__(&self, other: &Bound<'_, PyAny>) -> PyResult<PyLayerStack> {
        let mut stack = RustLayerStack::new();

        if let Ok(layer_stack) = other.extract::<PyLayerStack>() {
            stack = layer_stack.inner.clone();
        } else if let Ok(bytes) = other.extract::<Vec<u8>>() {
            stack.add(RustLayerStackEntry::Raw(bytes));
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Cannot stack: unsupported layer type on left",
            ));
        }

        stack.add(RustLayerStackEntry::L2tp(self.inner.clone()));
        Ok(PyLayerStack { inner: stack })
    }

    /// Build the L2TP packet into raw bytes.
    fn build<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    /// Build the L2TP packet into raw bytes (alias).
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.build())
    }

    fn __repr__(&self) -> String {
        "<L2TP>".to_string()
    }
}

// ============================================================================
// PCAP I/O
// ============================================================================

/// A captured packet with PCAP metadata (timestamp, wire length).
///
/// Returned by `rdpcap()` and `PcapReader`. Wraps a `Packet` with capture info.
///
/// Example:
///     >>> pkts = rdpcap("capture.pcap")
///     >>> pkts[0].time       # capture timestamp (float seconds)
///     >>> pkts[0].wirelen    # original wire length
///     >>> pkts[0].show()     # show packet contents
#[pyclass(name = "PcapPacket")]
#[derive(Clone)]
pub struct PyPcapPacket {
    inner: stackforge_core::CapturedPacket,
}

#[pymethods]
impl PyPcapPacket {
    /// Get the underlying Packet object.
    #[getter]
    fn packet(&self) -> PyPacket {
        PyPacket {
            inner: self.inner.packet.clone(),
        }
    }

    /// Get the capture timestamp as a float (seconds since epoch).
    #[getter]
    fn time(&self) -> f64 {
        self.inner.metadata.timestamp.as_secs_f64()
    }

    /// Get the original packet length on the wire.
    #[getter]
    fn wirelen(&self) -> u32 {
        self.inner.metadata.orig_len
    }

    fn show(&self) -> String {
        show_packet(&self.inner.packet)
    }

    fn summary(&self) -> String {
        summary_packet(&self.inner.packet)
    }

    fn hexdump(&self) -> String {
        hexdump_bytes(self.inner.packet.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!(
            "<PcapPacket time={:.6} len={}>",
            self.time(),
            self.inner.packet.len()
        )
    }

    fn __len__(&self) -> usize {
        self.inner.packet.len()
    }
}

/// Streaming PCAP reader for large files.
///
/// Reads packets one at a time without loading the entire file into memory.
/// Suitable for gigabyte-sized capture files.
///
/// Example:
///     >>> for pkt in PcapReader("large.pcap"):
///     ...     print(pkt.summary())
#[pyclass(name = "PcapReader")]
pub struct PyPcapReader {
    inner: Option<stackforge_core::PcapIterator<std::io::BufReader<std::fs::File>>>,
}

#[pymethods]
impl PyPcapReader {
    #[new]
    fn new(filename: &str) -> PyResult<Self> {
        let iter = stackforge_core::PcapIterator::open(filename)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;
        Ok(Self { inner: Some(iter) })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<Option<PyPcapPacket>> {
        if let Some(ref mut iter) = slf.inner {
            match iter.next() {
                Some(Ok(cap)) => Ok(Some(PyPcapPacket { inner: cap })),
                Some(Err(e)) => Err(pyo3::exceptions::PyIOError::new_err(format!("{}", e))),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

/// Read packets from a PCAP file.
///
/// Args:
///     filename: Path to the PCAP file
///     count: Maximum number of packets to read (0 = all)
///
/// Returns:
///     List of PcapPacket objects
///
/// Example:
///     >>> pkts = rdpcap("capture.pcap")
///     >>> pkts[0].show()
#[pyfunction]
#[pyo3(signature = (filename, count=0))]
fn rdpcap(filename: &str, count: usize) -> PyResult<Vec<PyPcapPacket>> {
    let iter = stackforge_core::PcapIterator::open(filename)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))?;

    let results: Vec<PyPcapPacket> = if count > 0 {
        iter.take(count)
            .filter_map(|r| r.ok())
            .map(|cap| PyPcapPacket { inner: cap })
            .collect()
    } else {
        iter.filter_map(|r| r.ok())
            .map(|cap| PyPcapPacket { inner: cap })
            .collect()
    };

    Ok(results)
}

/// Write packets to a PCAP file.
///
/// Args:
///     filename: Path to the output PCAP file
///     packets: List of Packet, PcapPacket, or LayerStack objects
///
/// Example:
///     >>> wrpcap("output.pcap", packets)
#[pyfunction]
fn wrpcap(filename: &str, packets: Vec<Bound<'_, pyo3::PyAny>>) -> PyResult<()> {
    let mut captured: Vec<stackforge_core::CapturedPacket> = Vec::with_capacity(packets.len());

    for pkt_any in &packets {
        if let Ok(pcap_pkt) = pkt_any.extract::<PyPcapPacket>() {
            captured.push(pcap_pkt.inner);
        } else if let Ok(pkt) = pkt_any.extract::<PyRef<'_, PyPacket>>() {
            let len = pkt.inner.len() as u32;
            captured.push(stackforge_core::CapturedPacket {
                packet: pkt.inner.clone(),
                metadata: stackforge_core::PcapMetadata {
                    orig_len: len,
                    ..Default::default()
                },
            });
        } else if let Ok(stack) = pkt_any.extract::<PyLayerStack>() {
            let built = stack.inner.build_packet();
            let len = built.len() as u32;
            captured.push(stackforge_core::CapturedPacket {
                packet: built,
                metadata: stackforge_core::PcapMetadata {
                    orig_len: len,
                    ..Default::default()
                },
            });
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "packets must be Packet, PcapPacket, or LayerStack objects",
            ));
        }
    }

    stackforge_core::wrpcap(filename, &captured)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}", e)))
}

/// Stackforge: High-performance network packet manipulation.
///
/// This module provides Python bindings to the Rust networking engine,
/// enabling Scapy-like packet manipulation with native performance.
#[pymodule]
fn stackforge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPacket>()?;
    m.add_class::<PyLayerKind>()?;
    m.add_class::<PyLayerIndex>()?;

    // Layer builders (Scapy-style)
    m.add_class::<PyEther>()?;
    m.add_class::<PyIP>()?;
    m.add_class::<PyTCP>()?;
    m.add_class::<PyUDP>()?;
    m.add_class::<PyICMP>()?;
    m.add_class::<PyARP>()?;
    m.add_class::<PySSH>()?;
    m.add_class::<PyTLS>()?;
    m.add_class::<PyRaw>()?;
    m.add_class::<PyLayerStack>()?;
    // New protocol builders
    m.add_class::<PyIPv6>()?;
    m.add_class::<PyICMPv6>()?;
    m.add_class::<PyHTTP>()?;
    m.add_class::<PyHTTPResponse>()?;
    m.add_class::<PyQUIC>()?;
    m.add_class::<PyHTTP2>()?;
    m.add_class::<PyL2tp>()?;

    // PCAP I/O
    m.add_class::<PyPcapPacket>()?;
    m.add_class::<PyPcapReader>()?;
    m.add_function(wrap_pyfunction!(rdpcap, m)?)?;
    m.add_function(wrap_pyfunction!(wrpcap, m)?)?;
    Ok(())
}
