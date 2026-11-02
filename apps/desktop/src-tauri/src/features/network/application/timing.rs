//! Per-target adaptive *probe latency* budgets for native TCP connect and
//! connected UDP scans. This is independent Rust and does NOT assert that an
//! application-layer banner duration is a packet RTT measurement.
//! No timings escape the saved-case scan job or persist between sessions.
use super::scan_service::ScanTransport;
use super::ScanObservation;
use std::time::Duration;

const TCP_INITIAL_MS: u64 = 900;
const UDP_INITIAL_MS: u64 = 600;
const TCP_MIN_MS: u64 = 300;
const TCP_MAX_MS: u64 = 1800;
const UDP_MIN_MS: u64 = 300;
const UDP_MAX_MS: u64 = 1200;
const RETRY_PAUSE: Duration = Duration::from_millis(20);

#[derive(Debug, Clone)]
pub(super) struct HostProbeBudget {
    transport: ScanTransport,
    observed_ms: Option<u64>,
    deviation_ms: u64,
    timeout_ms: u64,
    timeouts: u32,
    responses: u32,
}

impl HostProbeBudget {
    pub(super) fn new(transport: ScanTransport) -> Self {
        Self {
            transport,
            observed_ms: None,
            deviation_ms: 0,
            timeout_ms: match transport {
                ScanTransport::Tcp => TCP_INITIAL_MS,
                ScanTransport::Udp => UDP_INITIAL_MS,
            },
            timeouts: 0,
            responses: 0,
        }
    }

    fn limits(&self) -> (u64, u64) {
        match self.transport {
            ScanTransport::Tcp => (TCP_MIN_MS, TCP_MAX_MS),
            ScanTransport::Udp => (UDP_MIN_MS, UDP_MAX_MS),
        }
    }

    pub(super) fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// One limited retrial is appropriate only for uncertain network silence,
    /// not refusal, unreachable, permission denied or an invalid protocol reply.
    pub(super) fn should_retry(observation: &ScanObservation) -> bool {
        matches!(
            observation.reason.as_str(),
            "connect_timeout_no_response" | "connect_would_block" | "udp_no_response"
        ) && observation.state == "inconclusive"
    }

    /// On silence, bounded exponential backoff gives a delayed peer one
    /// additional chance. Silence never becomes "filtered" by inference.
    pub(super) fn note_silence(&mut self) {
        let (_, max) = self.limits();
        self.timeouts = self.timeouts.saturating_add(1);
        self.timeout_ms = self.timeout_ms.saturating_mul(2).min(max);
    }

    /// This is a measured *whole-probe duration*, not a pure network RTT.
    /// The fixed EWMA update avoids platform-dependent floating-point effects.
    /// Update only from definite responses, not from timeout durations.
    pub(super) fn note_response(&mut self, elapsed_ms: u64) {
        let sample = elapsed_ms.clamp(1, 5000);
        self.responses = self.responses.saturating_add(1);
        match self.observed_ms {
            None => {
                self.observed_ms = Some(sample);
                self.deviation_ms = sample / 2;
            }
            Some(prior) => {
                let difference = prior.abs_diff(sample);
                self.deviation_ms = (3 * self.deviation_ms + difference) / 4;
                self.observed_ms = Some((7 * prior + sample) / 8);
            }
        }
        let (min, max) = self.limits();
        let mean = self.observed_ms.unwrap_or(sample);
        self.timeout_ms = mean
            .saturating_add(self.deviation_ms.saturating_mul(4))
            .saturating_add(100)
            .clamp(min, max);
    }

    pub(super) fn note_final(&mut self, observation: &ScanObservation) {
        if matches!(observation.state.as_str(), "open" | "closed") {
            self.note_response(observation.elapsed_ms);
        } else if Self::should_retry(observation) {
            self.note_silence();
        }
    }

    pub(super) fn retry_pause() -> Duration {
        RETRY_PAUSE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(state: &str, reason: &str) -> ScanObservation {
        ScanObservation {
            host: "127.0.0.1".into(),
            port: 80,
            protocol: "tcp".into(),
            state: state.into(),
            reason: reason.into(),
            method: "tcp_connect".into(),
            service: "unknown".into(),
            service_basis: "none".into(),
            remote_software_claim: None,
            banner: String::new(),
            started_at_ms: 0,
            elapsed_ms: 10,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        }
    }

    #[test]
    fn no_reply_backoff_is_bounded_and_independent_per_host() {
        let mut first = HostProbeBudget::new(ScanTransport::Tcp);
        let second = HostProbeBudget::new(ScanTransport::Tcp);
        assert_eq!(first.timeout().as_millis(), 900);
        first.note_silence();
        assert_eq!(first.timeout().as_millis(), 1800);
        assert_eq!(second.timeout().as_millis(), 900);
        for _ in 0..100 {
            first.note_silence();
        }
        assert_eq!(first.timeout().as_millis(), 1800);
        let mut udp = HostProbeBudget::new(ScanTransport::Udp);
        udp.note_silence();
        assert_eq!(udp.timeout().as_millis(), 1200);
    }

    #[test]
    fn confirmed_responses_converge_without_claiming_rtt() {
        let mut host = HostProbeBudget::new(ScanTransport::Tcp);
        for _ in 0..40 {
            host.note_response(25);
        }
        assert!((TCP_MIN_MS..=TCP_MAX_MS).contains(&(host.timeout().as_millis() as u64)));
        assert_eq!(host.timeout().as_millis(), 300);
        host.note_silence();
        assert_eq!(host.timeout().as_millis(), 600);
        host.note_response(45);
        assert!(host.timeout() <= Duration::from_millis(TCP_MAX_MS));
    }

    #[test]
    fn retry_only_for_uncertain_silence() {
        assert!(HostProbeBudget::should_retry(&sample(
            "inconclusive",
            "connect_timeout_no_response"
        )));
        assert!(HostProbeBudget::should_retry(&sample(
            "inconclusive",
            "udp_no_response"
        )));
        for (state, reason) in [
            ("closed", "tcp_connect_refused"),
            ("unreachable", "network_unreachable"),
            ("inconclusive", "udp_permission_denied"),
            ("inconclusive", "udp_invalid_or_unmatched_response"),
            ("open", "tcp_connect_accepted"),
        ] {
            assert!(!HostProbeBudget::should_retry(&sample(state, reason)));
        }
    }
}
