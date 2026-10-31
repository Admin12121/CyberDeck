//! Legacy crack-history persistence adapter; preserves existing write behavior.
//! Never use this as evidence of encrypted storage: Agent 5 owns that migration.
use crate::evidence::EvidenceCtx;

pub fn persist<'a>(
    ctx: &EvidenceCtx,
    algorithm: &str,
    target: &str,
    engine: &str,
    source: Option<&str>,
    passwords: impl IntoIterator<Item = &'a str>,
) {
    let mut passwords = passwords.into_iter().peekable();
    if passwords.peek().is_none() {
        return;
    }
    let store = ctx.store.lock().expect("artifact store poisoned");
    for password in passwords {
        let _ = store.add_crack_entry(algorithm, target, password, engine, source);
    }
}
