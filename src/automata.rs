use std::net::Ipv4Addr;
use std::time::Duration;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use stackforge_automata::config::AutomatonConfig;
use stackforge_automata::dhcp::lease::PoolConfig;
use stackforge_automata::dhcp::DhcpServer;
use stackforge_automata::error::AutomatonError;
use stackforge_automata::runtime::AutomatonRuntime;
use stackforge_automata::traits::CallbackAutomaton;
use stackforge_core::layer::field::MacAddress;
use stackforge_core::Packet as RustPacket;

use crate::PyPacket;

fn automaton_err_to_py(err: AutomatonError) -> PyErr {
    match err {
        AutomatonError::Config(msg) => PyValueError::new_err(msg),
        AutomatonError::Pcap(e) => PyOSError::new_err(e.to_string()),
        AutomatonError::Runtime(msg) => PyRuntimeError::new_err(msg),
        AutomatonError::Sniffer(e) => PyOSError::new_err(e.to_string()),
        AutomatonError::Send(msg) => PyRuntimeError::new_err(msg),
        AutomatonError::AlreadyRunning => PyRuntimeError::new_err("already running"),
        AutomatonError::NotRunning => PyRuntimeError::new_err("not running"),
    }
}

// ---------------------------------------------------------------------------
// PyAutomatonConfig
// ---------------------------------------------------------------------------

/// Configuration for an automaton runtime.
#[pyclass(name = "AutomatonConfig")]
#[derive(Clone)]
pub struct PyAutomatonConfig {
    inner: AutomatonConfig,
}

#[pymethods]
impl PyAutomatonConfig {
    #[new]
    #[pyo3(signature = (iface=None, bpf_filter=None, snaplen=65535, promisc=true))]
    fn new(
        iface: Option<&str>,
        bpf_filter: Option<String>,
        snaplen: i32,
        promisc: bool,
    ) -> Self {
        let iface_name = iface.unwrap_or("").to_string();
        Self {
            inner: AutomatonConfig {
                iface: if iface_name.is_empty() {
                    default_iface()
                } else {
                    iface_name
                },
                bpf_filter,
                snaplen,
                promisc,
            },
        }
    }
}

fn default_iface() -> String {
    AutomatonConfig::default().iface
}

// ---------------------------------------------------------------------------
// PyAnsweringMachine — callback-based
// ---------------------------------------------------------------------------

/// Callback-based answering machine.
///
/// Usage:
///     >>> def is_request(pkt):
///     ...     return pkt.has_layer(LayerKind.Dhcp)
///     >>> def make_reply(pkt):
///     ...     return b"\xff" * 64  # raw reply bytes
///     >>> am = AnsweringMachine(is_request, make_reply, bpf_filter="udp port 67")
///     >>> am.start(config)
///     >>> am.stop()
#[pyclass(name = "AnsweringMachine")]
pub struct PyAnsweringMachine {
    is_request_fn: Py<PyAny>,
    make_reply_fn: Py<PyAny>,
    bpf_filter: Option<String>,
    runtime: Option<AutomatonRuntime>,
}

#[pymethods]
impl PyAnsweringMachine {
    #[new]
    #[pyo3(signature = (is_request, make_reply, bpf_filter=None))]
    fn new(is_request: Py<PyAny>, make_reply: Py<PyAny>, bpf_filter: Option<String>) -> Self {
        Self {
            is_request_fn: is_request,
            make_reply_fn: make_reply,
            bpf_filter,
            runtime: None,
        }
    }

    /// Start the answering machine.
    fn start(&mut self, py: Python<'_>, config: &PyAutomatonConfig) -> PyResult<()> {
        if self.runtime.is_some() {
            return Err(PyRuntimeError::new_err("already running"));
        }

        let is_req = self.is_request_fn.clone_ref(py);
        let make_rep = self.make_reply_fn.clone_ref(py);
        let bpf = self.bpf_filter.clone();

        let filter_fn = move |pkt: &RustPacket| -> bool {
            Python::attach(|py| {
                let py_pkt = PyPacket {
                    inner: pkt.clone(),
                };
                let result = is_req.call1(py, (py_pkt,));
                result
                    .and_then(|r| r.extract::<bool>(py))
                    .unwrap_or(false)
            })
        };

        let reply_fn = move |pkt: &RustPacket| -> Option<Vec<u8>> {
            Python::attach(|py| {
                let py_pkt = PyPacket {
                    inner: pkt.clone(),
                };
                let result = make_rep.call1(py, (py_pkt,));
                match result {
                    Ok(obj) => {
                        if obj.is_none(py) {
                            return None;
                        }
                        obj.extract::<Vec<u8>>(py).ok()
                    }
                    Err(_) => None,
                }
            })
        };

        let mut automaton = CallbackAutomaton::new(filter_fn, reply_fn);
        if let Some(f) = bpf {
            automaton = automaton.bpf_filter(f);
        }

        let runtime =
            AutomatonRuntime::start(automaton, config.inner.clone()).map_err(automaton_err_to_py)?;
        self.runtime = Some(runtime);
        Ok(())
    }

    /// Stop the answering machine.
    fn stop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.join();
        }
    }

    /// Check if the answering machine is running.
    #[getter]
    fn is_running(&self) -> bool {
        self.runtime.as_ref().is_some_and(|rt| rt.is_running())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, pyo3::types::PyAny>,
        _exc_val: &Bound<'_, pyo3::types::PyAny>,
        _exc_tb: &Bound<'_, pyo3::types::PyAny>,
    ) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// PyDhcpServer
// ---------------------------------------------------------------------------

/// DHCP server pool configuration.
#[pyclass(name = "DhcpPoolConfig")]
#[derive(Clone)]
pub struct PyDhcpPoolConfig {
    inner: PoolConfig,
}

#[pymethods]
impl PyDhcpPoolConfig {
    #[new]
    #[pyo3(signature = (
        pool_start="192.168.1.100",
        pool_end="192.168.1.200",
        server_ip="192.168.1.1",
        subnet_mask="255.255.255.0",
        gateway="192.168.1.1",
        dns_servers=None,
        domain=None,
        lease_time=86400,
        renewal_time=None,
        rebinding_time=None,
    ))]
    fn new(
        pool_start: &str,
        pool_end: &str,
        server_ip: &str,
        subnet_mask: &str,
        gateway: &str,
        dns_servers: Option<Vec<String>>,
        domain: Option<String>,
        lease_time: u32,
        renewal_time: Option<u32>,
        rebinding_time: Option<u32>,
    ) -> PyResult<Self> {
        let parse_ip = |s: &str| -> PyResult<Ipv4Addr> {
            s.parse::<Ipv4Addr>()
                .map_err(|e| PyValueError::new_err(format!("invalid IP: {e}")))
        };

        let dns = match dns_servers {
            Some(addrs) => addrs
                .iter()
                .map(|s| parse_ip(s))
                .collect::<PyResult<Vec<_>>>()?,
            None => vec![
                Ipv4Addr::new(8, 8, 8, 8),
                Ipv4Addr::new(8, 8, 4, 4),
            ],
        };

        Ok(Self {
            inner: PoolConfig {
                pool_start: parse_ip(pool_start)?,
                pool_end: parse_ip(pool_end)?,
                server_ip: parse_ip(server_ip)?,
                subnet_mask: parse_ip(subnet_mask)?,
                gateway: parse_ip(gateway)?,
                dns_servers: dns,
                domain,
                lease_time,
                renewal_time,
                rebinding_time,
            },
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "DhcpPoolConfig(pool={}-{}, server={}, lease_time={})",
            self.inner.pool_start, self.inner.pool_end,
            self.inner.server_ip, self.inner.lease_time
        )
    }
}

/// Full-featured DHCP server.
///
/// Usage:
///     >>> pool = DhcpPoolConfig(pool_start="10.0.0.10", pool_end="10.0.0.200")
///     >>> server = DhcpServerAM(pool, server_mac="aa:bb:cc:dd:ee:ff")
///     >>> server.start(AutomatonConfig(iface="en0"))
///     >>> server.stop()
#[pyclass(name = "DhcpServerAM")]
pub struct PyDhcpServer {
    pool: PoolConfig,
    server_mac: MacAddress,
    sweep_interval: f64,
    runtime: Option<AutomatonRuntime>,
}

#[pymethods]
impl PyDhcpServer {
    #[new]
    #[pyo3(signature = (pool, server_mac=None, sweep_interval=60.0))]
    fn new(
        pool: &PyDhcpPoolConfig,
        server_mac: Option<&str>,
        sweep_interval: f64,
    ) -> PyResult<Self> {
        let mac = match server_mac {
            Some(s) => parse_mac(s)?,
            None => {
                // Use a locally-administered MAC as default
                MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            }
        };

        Ok(Self {
            pool: pool.inner.clone(),
            server_mac: mac,
            sweep_interval,
            runtime: None,
        })
    }

    /// Start the DHCP server.
    fn start(&mut self, config: &PyAutomatonConfig) -> PyResult<()> {
        if self.runtime.is_some() {
            return Err(PyRuntimeError::new_err("already running"));
        }

        let server = DhcpServer::new(self.server_mac, self.pool.clone())
            .sweep_interval(Duration::from_secs_f64(self.sweep_interval));

        let runtime =
            AutomatonRuntime::start(server, config.inner.clone()).map_err(automaton_err_to_py)?;
        self.runtime = Some(runtime);
        Ok(())
    }

    /// Stop the DHCP server.
    fn stop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.join();
        }
    }

    /// Check if the server is running.
    #[getter]
    fn is_running(&self) -> bool {
        self.runtime.as_ref().is_some_and(|rt| rt.is_running())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, pyo3::types::PyAny>,
        _exc_val: &Bound<'_, pyo3::types::PyAny>,
        _exc_tb: &Bound<'_, pyo3::types::PyAny>,
    ) {
        self.stop();
    }

    fn __repr__(&self) -> String {
        format!(
            "DhcpServerAM(pool={}-{}, server={})",
            self.pool.pool_start, self.pool.pool_end, self.pool.server_ip
        )
    }
}

fn parse_mac(s: &str) -> PyResult<MacAddress> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(PyValueError::new_err(format!(
            "invalid MAC address: {s} (expected xx:xx:xx:xx:xx:xx)"
        )));
    }
    let mut octets = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = u8::from_str_radix(part, 16)
            .map_err(|_| PyValueError::new_err(format!("invalid MAC octet: {part}")))?;
    }
    Ok(MacAddress::new(octets))
}
