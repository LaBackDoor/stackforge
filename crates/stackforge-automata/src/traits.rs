use std::time::Duration;

use stackforge_core::Packet;

/// Core trait for answering machines and network automata.
///
/// Implementors define how to filter incoming packets, generate replies,
/// and optionally perform periodic actions.
pub trait Automaton: Send + 'static {
    /// BPF filter for packets this automaton cares about.
    /// Applied at the kernel level for efficiency.
    fn bpf_filter(&self) -> Option<String> {
        None
    }

    /// Check if a received packet is a request this automaton should answer.
    fn is_request(&self, pkt: &Packet) -> bool;

    /// Generate a reply packet for a given request.
    /// Return `None` to silently drop the request.
    fn make_reply(&self, request: &Packet) -> Option<Vec<u8>>;

    /// Called once when the automaton starts.
    fn on_start(&mut self) {}

    /// Called once when the automaton stops.
    fn on_stop(&mut self) {}

    /// Interval for periodic tick. Return `None` to disable.
    fn tick_interval(&self) -> Option<Duration> {
        None
    }

    /// Called on each tick. Use for periodic tasks like sending
    /// gratuitous ARPs or sweeping expired leases.
    fn on_tick(&mut self) -> Option<Vec<Vec<u8>>> {
        None
    }
}

/// A callback-based automaton for use from Python or simple Rust use cases.
///
/// Instead of implementing the trait, users pass closures/function pointers.
pub struct CallbackAutomaton<F, R>
where
    F: Fn(&Packet) -> bool + Send + 'static,
    R: Fn(&Packet) -> Option<Vec<u8>> + Send + 'static,
{
    filter_fn: F,
    reply_fn: R,
    bpf: Option<String>,
    on_start_fn: Option<Box<dyn FnMut() + Send + 'static>>,
    on_stop_fn: Option<Box<dyn FnMut() + Send + 'static>>,
    tick_fn: Option<Box<dyn FnMut() -> Option<Vec<Vec<u8>>> + Send + 'static>>,
    tick_dur: Option<Duration>,
}

impl<F, R> CallbackAutomaton<F, R>
where
    F: Fn(&Packet) -> bool + Send + 'static,
    R: Fn(&Packet) -> Option<Vec<u8>> + Send + 'static,
{
    pub fn new(filter_fn: F, reply_fn: R) -> Self {
        Self {
            filter_fn,
            reply_fn,
            bpf: None,
            on_start_fn: None,
            on_stop_fn: None,
            tick_fn: None,
            tick_dur: None,
        }
    }

    #[must_use]
    pub fn bpf_filter(mut self, filter: impl Into<String>) -> Self {
        self.bpf = Some(filter.into());
        self
    }

    #[must_use]
    pub fn on_start(mut self, f: impl FnMut() + Send + 'static) -> Self {
        self.on_start_fn = Some(Box::new(f));
        self
    }

    #[must_use]
    pub fn on_stop(mut self, f: impl FnMut() + Send + 'static) -> Self {
        self.on_stop_fn = Some(Box::new(f));
        self
    }

    #[must_use]
    pub fn tick(
        mut self,
        interval: Duration,
        f: impl FnMut() -> Option<Vec<Vec<u8>>> + Send + 'static,
    ) -> Self {
        self.tick_dur = Some(interval);
        self.tick_fn = Some(Box::new(f));
        self
    }
}

impl<F, R> Automaton for CallbackAutomaton<F, R>
where
    F: Fn(&Packet) -> bool + Send + 'static,
    R: Fn(&Packet) -> Option<Vec<u8>> + Send + 'static,
{
    fn bpf_filter(&self) -> Option<String> {
        self.bpf.clone()
    }

    fn is_request(&self, pkt: &Packet) -> bool {
        (self.filter_fn)(pkt)
    }

    fn make_reply(&self, request: &Packet) -> Option<Vec<u8>> {
        (self.reply_fn)(request)
    }

    fn on_start(&mut self) {
        if let Some(ref mut f) = self.on_start_fn {
            f();
        }
    }

    fn on_stop(&mut self) {
        if let Some(ref mut f) = self.on_stop_fn {
            f();
        }
    }

    fn tick_interval(&self) -> Option<Duration> {
        self.tick_dur
    }

    fn on_tick(&mut self) -> Option<Vec<Vec<u8>>> {
        if let Some(ref mut f) = self.tick_fn {
            f()
        } else {
            None
        }
    }
}
