use std::time::Duration;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyStopIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use stackforge_core::Packet as RustPacket;
use stackforge_core::sniffer::{
    RawPacket, SnifferConfig, SnifferError, SnifferHandle, WorkerPoolConfig, WorkerPoolSniffer,
    list_interfaces as rust_list_ifaces, validate_filter as rust_validate_filter,
};

use crate::PyPacket;

/// Convert a `SnifferError` into a Python exception.
fn sniffer_err_to_py(err: SnifferError) -> PyErr {
    match err {
        SnifferError::InterfaceNotFound(msg) => PyValueError::new_err(msg),
        SnifferError::PermissionDenied(msg) => PyOSError::new_err(msg),
        SnifferError::InvalidFilter(msg) => PyValueError::new_err(msg),
        SnifferError::ChannelClosed | SnifferError::AlreadyStopped => {
            PyRuntimeError::new_err(err.to_string())
        },
        SnifferError::CaptureError(msg) => PyRuntimeError::new_err(msg),
        SnifferError::Pcap(e) => PyOSError::new_err(e.to_string()),
    }
}

/// Create a parsed `PyPacket` from a raw captured packet.
fn raw_to_pypacket(raw: &RawPacket) -> PyPacket {
    let mut pkt = RustPacket::from_bytes(raw.data.to_vec());
    let _ = pkt.parse();
    PyPacket { inner: pkt }
}

/// Iterator-based packet sniffer.
///
/// Usage:
///     >>> sniffer = Sniffer(iface="en0", filter="tcp port 80", count=10)
///     >>> for pkt in sniffer:
///     ...     print(pkt.summary())
///
///     >>> with Sniffer(iface="en0", count=5) as s:
///     ...     for pkt in s:
///     ...         print(pkt.summary())
#[pyclass(name = "Sniffer")]
pub struct PySniffer {
    handle: Option<SnifferHandle>,
    config_iface: String,
}

#[pymethods]
impl PySniffer {
    #[new]
    #[pyo3(signature = (iface=None, filter=None, count=0, timeout=None, snaplen=65535, promisc=true))]
    fn new(
        iface: Option<&str>,
        filter: Option<&str>,
        count: usize,
        timeout: Option<f64>,
        snaplen: i32,
        promisc: bool,
    ) -> PyResult<Self> {
        let mut config = match iface {
            Some(name) => SnifferConfig::new(name),
            None => SnifferConfig::default(),
        };
        if let Some(f) = filter {
            config = config.filter(f);
        }
        config = config.count(count).snaplen(snaplen).promisc(promisc);
        if let Some(t) = timeout {
            config = config.timeout(Duration::from_secs_f64(t));
        }

        let config_iface = config.iface.clone();
        let handle = SnifferHandle::start(config).map_err(sniffer_err_to_py)?;

        Ok(Self {
            handle: Some(handle),
            config_iface,
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<PyPacket> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("sniffer is stopped"))?;

        // Release the GIL while waiting for the next packet
        let raw = py.detach(|| handle.recv());

        match raw {
            Some(ref pkt) => Ok(raw_to_pypacket(pkt)),
            None => Err(PyStopIteration::new_err(())),
        }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.stop();
        false
    }

    /// Stop the sniffer.
    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join();
        }
    }

    /// Get capture statistics.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("sniffer is stopped"))?;

        let dict = PyDict::new(py);
        dict.set_item("interface", &self.config_iface)?;
        dict.set_item("stopped", handle.is_stopped())?;
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        let active = if self.handle.is_some() {
            "True"
        } else {
            "False"
        };
        format!("Sniffer(iface='{}', active={})", self.config_iface, active)
    }
}

/// Capture packets from a network interface (Scapy-compatible).
///
/// Args:
///     iface: Network interface name (default: system default)
///     filter: BPF filter string (e.g., "tcp port 80")
///     count: Number of packets to capture (0 = unlimited)
///     timeout: Capture timeout in seconds
///     prn: Callback function called for each packet
///     stop_filter: Function that returns True to stop capture
///     snaplen: Maximum bytes per packet (default: 65535)
///     promisc: Enable promiscuous mode (default: True)
///
/// Returns:
///     List of captured Packet objects
#[pyfunction]
#[pyo3(signature = (iface=None, filter=None, count=0, timeout=None, prn=None, stop_filter=None, snaplen=65535, promisc=true))]
pub fn sniff(
    py: Python<'_>,
    iface: Option<&str>,
    filter: Option<&str>,
    count: usize,
    timeout: Option<f64>,
    prn: Option<&Bound<'_, PyAny>>,
    stop_filter: Option<&Bound<'_, PyAny>>,
    snaplen: i32,
    promisc: bool,
) -> PyResult<Vec<PyPacket>> {
    let mut config = match iface {
        Some(name) => SnifferConfig::new(name),
        None => SnifferConfig::default(),
    };
    if let Some(f) = filter {
        config = config.filter(f);
    }
    config = config.count(count).snaplen(snaplen).promisc(promisc);
    if let Some(t) = timeout {
        config = config.timeout(Duration::from_secs_f64(t));
    }

    let handle = SnifferHandle::start(config).map_err(sniffer_err_to_py)?;
    let mut packets = Vec::new();

    loop {
        // Release GIL while waiting
        let raw = py.detach(|| handle.recv());

        match raw {
            Some(ref raw_pkt) => {
                let pkt = raw_to_pypacket(raw_pkt);

                // Call prn callback if provided
                if let Some(callback) = prn {
                    let pkt_obj = Py::new(
                        py,
                        PyPacket {
                            inner: pkt.inner.clone(),
                        },
                    )?;
                    callback.call1((pkt_obj,))?;
                }

                // Check stop_filter
                if let Some(sf) = stop_filter {
                    let pkt_obj = Py::new(
                        py,
                        PyPacket {
                            inner: pkt.inner.clone(),
                        },
                    )?;
                    let result = sf.call1((pkt_obj,))?;
                    if result.is_truthy()? {
                        packets.push(pkt);
                        break;
                    }
                }

                packets.push(pkt);
            },
            None => break,
        }
    }

    Ok(packets)
}

/// List all available network interfaces.
///
/// Returns:
///     List of dicts with keys: name, description, addresses
#[pyfunction]
#[pyo3(name = "list_interfaces")]
pub fn py_list_interfaces(py: Python<'_>) -> PyResult<Vec<Bound<'_, PyDict>>> {
    let ifaces = rust_list_ifaces().map_err(sniffer_err_to_py)?;
    let mut result = Vec::with_capacity(ifaces.len());

    for iface in ifaces {
        let dict = PyDict::new(py);
        dict.set_item("name", &iface.name)?;
        dict.set_item("description", &iface.description)?;
        dict.set_item("addresses", &iface.addresses)?;
        result.push(dict);
    }

    Ok(result)
}

/// Validate a BPF filter string.
///
/// Args:
///     filter: BPF filter string to validate
///
/// Returns:
///     True if valid
///
/// Raises:
///     ValueError: If the filter is invalid
#[pyfunction]
#[pyo3(name = "validate_filter")]
pub fn py_validate_filter(filter: &str) -> PyResult<bool> {
    rust_validate_filter(filter).map_err(sniffer_err_to_py)?;
    Ok(true)
}

// ============================================================================
// Worker Pool Sniffer (multithreaded)
// ============================================================================

/// Multithreaded packet sniffer with a worker pool.
///
/// Uses multiple threads to parse captured packets in parallel,
/// achieving higher throughput on multi-core systems.
///
/// Usage:
///     >>> pool = WorkerPool(iface="en0", num_workers=4, count=100)
///     >>> for pkt in pool:
///     ...     print(pkt.summary())
#[pyclass(name = "WorkerPool")]
pub struct PyWorkerPool {
    inner: Option<WorkerPoolSniffer>,
    config_iface: String,
}

#[pymethods]
impl PyWorkerPool {
    #[new]
    #[pyo3(signature = (iface=None, filter=None, count=0, timeout=None, snaplen=65535, promisc=true, num_workers=None))]
    fn new(
        iface: Option<&str>,
        filter: Option<&str>,
        count: usize,
        timeout: Option<f64>,
        snaplen: i32,
        promisc: bool,
        num_workers: Option<usize>,
    ) -> PyResult<Self> {
        let mut config = match iface {
            Some(name) => SnifferConfig::new(name),
            None => SnifferConfig::default(),
        };
        if let Some(f) = filter {
            config = config.filter(f);
        }
        config = config.count(count).snaplen(snaplen).promisc(promisc);
        if let Some(t) = timeout {
            config = config.timeout(Duration::from_secs_f64(t));
        }

        let mut pool_config = WorkerPoolConfig::default();
        if let Some(n) = num_workers {
            pool_config = pool_config.num_workers(n);
        }

        let config_iface = config.iface.clone();
        let pool = WorkerPoolSniffer::start(config, pool_config).map_err(sniffer_err_to_py)?;

        Ok(Self {
            inner: Some(pool),
            config_iface,
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<PyPacket> {
        let pool = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("worker pool is stopped"))?;

        let parsed = py.detach(|| pool.recv());

        match parsed {
            Some(p) => Ok(PyPacket { inner: p.packet }),
            None => Err(PyStopIteration::new_err(())),
        }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.stop();
        false
    }

    /// Stop the worker pool.
    fn stop(&mut self) {
        if let Some(pool) = self.inner.take() {
            pool.join();
        }
    }

    /// Number of worker threads.
    #[getter]
    fn num_workers(&self) -> usize {
        self.inner.as_ref().map_or(0, |p| p.num_workers())
    }

    /// Whether the pool is running.
    #[getter]
    fn is_running(&self) -> bool {
        self.inner.as_ref().is_some_and(|p| !p.is_stopped())
    }

    fn __repr__(&self) -> String {
        let workers = self.inner.as_ref().map_or(0, |p| p.num_workers());
        let active = self.inner.is_some();
        format!(
            "WorkerPool(iface='{}', workers={}, active={})",
            self.config_iface, workers, active
        )
    }
}

// ============================================================================
// Parallel batch parsing
// ============================================================================

/// Parse a list of raw byte buffers in parallel using a thread pool.
///
/// This is significantly faster than sequential parsing for large batches
/// (thousands of packets or more).
///
/// Args:
///     packets: List of bytes objects to parse
///
/// Returns:
///     List of parsed Packet objects
#[pyfunction]
#[pyo3(name = "parse_batch")]
pub fn py_parse_batch(packets: Vec<Vec<u8>>) -> Vec<PyPacket> {
    let parsed = stackforge_core::parallel::parse_batch(&packets);
    parsed.into_iter().map(|p| PyPacket { inner: p }).collect()
}
