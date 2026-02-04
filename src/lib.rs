//! # Stackforge Python Bindings
//!
//! This module provides PyO3-based Python bindings for the Stackforge
//! networking framework.
//!
//! The bindings expose the high-performance Rust packet manipulation
//! engine to Python, enabling Scapy-like ergonomics with native speed.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use stackforge_core::{
    FieldValue, LayerKind as RustLayerKind, MacAddress, Packet as RustPacket, PacketError,
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

/// Stackforge: High-performance network packet manipulation.
///
/// This module provides Python bindings to the Rust networking engine,
/// enabling Scapy-like packet manipulation with native performance.
#[pymodule]
fn stackforge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPacket>()?;
    m.add_class::<PyLayerKind>()?;
    m.add_class::<PyLayerIndex>()?;
    Ok(())
}
