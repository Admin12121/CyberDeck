//! Process-local lease shared by authorized active Network operations.
//! This is not user authority: individual IPC handlers must still verify the
//! selected backend case, explicit operator approval and target scope.
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActiveOperation {
    TcpUdp = 1,
    TcpDiscovery = 2,
    RawSyn = 3,
    LinkNeighbor = 4,
    IcmpEcho = 5,
}

#[derive(Default)]
pub struct NetworkOperationGate {
    current: AtomicU8,
}
impl NetworkOperationGate {
    pub fn is_active(&self) -> bool {
        self.current.load(Ordering::Acquire) != 0
    }
    pub fn acquire(self: &Arc<Self>, kind: ActiveOperation) -> Result<OperationPermit, String> {
        self.current
            .compare_exchange(0, kind as u8, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                "another case-authorized active network operation is already running".to_string()
            })?;
        Ok(OperationPermit {
            gate: Arc::clone(self),
            kind,
        })
    }
}
pub struct OperationPermit {
    gate: Arc<NetworkOperationGate>,
    kind: ActiveOperation,
}
impl Drop for OperationPermit {
    fn drop(&mut self) {
        // Exact owner token protects against an old worker clearing a later
        // operation's state. Normal operation permits are never duplicated.
        let _ = self.gate.current.compare_exchange(
            self.kind as u8,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    #[test]
    fn permit_blocks_every_other_protocol_until_owner_drops() {
        let gate = Arc::new(NetworkOperationGate::default());
        let first = gate.acquire(ActiveOperation::RawSyn).unwrap();
        assert!(gate.is_active());
        for mode in [
            ActiveOperation::TcpUdp,
            ActiveOperation::TcpDiscovery,
            ActiveOperation::RawSyn,
            ActiveOperation::LinkNeighbor,
            ActiveOperation::IcmpEcho,
        ] {
            assert!(gate.acquire(mode).is_err());
        }
        drop(first);
        assert!(!gate.is_active());
        let next = gate.acquire(ActiveOperation::IcmpEcho).unwrap();
        assert!(gate.is_active());
        drop(next);
        assert!(!gate.is_active());
    }

    #[test]
    fn simultaneous_claims_never_both_succeed() {
        let gate = Arc::new(NetworkOperationGate::default());
        let barrier = Arc::new(Barrier::new(9));
        let acquired = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let gate = Arc::clone(&gate);
                let barrier = Arc::clone(&barrier);
                let acquired = Arc::clone(&acquired);
                scope.spawn(move || {
                    barrier.wait();
                    if let Ok(_permit) = gate.acquire(ActiveOperation::RawSyn) {
                        acquired.fetch_add(1, Ordering::SeqCst);
                        // Hold the winning lease while the other claims run.
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                });
            }
            barrier.wait();
        });
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
        assert!(!gate.is_active());
    }
}
