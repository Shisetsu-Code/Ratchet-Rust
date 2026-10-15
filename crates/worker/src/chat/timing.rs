//! Opt-in, sampled local diagnostics. Never enable on a deployed Worker: its
//! clock does not advance during synchronous execution. No payloads or secrets.
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Probe {
    start: Option<f64>,
    phases: BTreeMap<&'static str, f64>,
    pub fanout: usize,
}
impl Probe {
    pub fn new(enabled: bool) -> Self {
        Self {
            start: enabled.then(clock),
            ..Self::default()
        }
    }
    pub fn sampled(enabled: bool, sequence: Option<u64>) -> Self {
        Self::new(enabled && sequence.is_some_and(|n| n >= 2 && (n - 1).is_multiple_of(10)))
    }
    pub fn enabled(&self) -> bool {
        self.start.is_some()
    }
    pub fn include_entry(&mut self, entry: f64, decoded: f64) {
        if self.enabled() {
            self.start = Some(entry);
            self.add("frame_decode", decoded - entry);
        }
    }
    pub fn now(&self) -> f64 {
        if self.enabled() { clock() } else { 0.0 }
    }
    pub fn record(&mut self, phase: &'static str, since: f64) {
        if self.enabled() {
            self.add(phase, self.now() - since);
        }
    }
    fn add(&mut self, phase: &'static str, elapsed: f64) {
        if elapsed.is_finite() && elapsed >= 0.0 {
            *self.phases.entry(phase).or_default() += elapsed;
        }
    }
    pub fn add_elapsed(&mut self, phase: &'static str, elapsed: f64) {
        if self.enabled() {
            self.add(phase, elapsed);
        }
    }
    pub fn emit(&self, mut context: serde_json::Value) {
        if let Some(start) = self.start {
            context["phases_ms"] = serde_json::json!(self.phases);
            context["total_ms"] = serde_json::json!(self.now() - start);
            context["fanout"] = serde_json::json!(self.fanout);
            worker::console_log!("RATCHET_TIMING {}", context);
        }
    }
}
pub(super) fn snapshot(enabled: bool) -> f64 {
    if enabled { clock() } else { 0.0 }
}

#[cfg(target_arch = "wasm32")]
fn clock() -> f64 {
    use worker::{
        js_sys::{self, Function, Reflect},
        wasm_bindgen::{JsCast, JsValue},
    };
    thread_local! {
        static CLOCK: Option<(JsValue, Function)> = (|| {
            let performance = Reflect::get(&js_sys::global(), &"performance".into()).ok()?;
            let function = Reflect::get(&performance, &"now".into()).ok()?.dyn_into::<Function>().ok()?;
            Some((performance, function))
        })();
    }
    CLOCK.with(|clock| {
        clock
            .as_ref()
            .and_then(|(owner, function)| function.call0(owner).ok()?.as_f64())
            .unwrap_or(0.0)
    })
}
#[cfg(not(target_arch = "wasm32"))]
fn clock() -> f64 {
    0.0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sampling_excludes_warmup_and_selects_five_of_fifty_messages() {
        assert!(!Probe::sampled(true, Some(1)).enabled());
        assert!(!Probe::sampled(false, Some(11)).enabled());
        assert!(!Probe::sampled(true, None).enabled());
        assert_eq!(
            (2..52)
                .filter(|n| Probe::sampled(true, Some(*n)).enabled())
                .count(),
            5
        );
    }
    #[test]
    fn repeated_fanout_spans_accumulate_and_invalid_clock_values_are_ignored() {
        let mut probe = Probe::new(true);
        probe.add("fanout_send", 1.25);
        probe.add("fanout_send", 2.5);
        probe.add("fanout_send", f64::NAN);
        probe.add("fanout_send", -1.0);
        assert_eq!(probe.phases["fanout_send"], 3.75);
    }
}
