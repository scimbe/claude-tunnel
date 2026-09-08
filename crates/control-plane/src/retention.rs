//! Retention (#775 item 2): `SqliteEnrollment::prune_redeemed_join_tokens`,
//! `SqliteEnrollment::prune_batch_issuance`, `SqliteBootstrap::prune`, and
//! `SqliteEdgeMesh::prune_stale_edges` each already existed with a real, tested
//! implementation -- but nothing ever called them outside their own tests. Every one
//! of those tables grows forever in a real long-running deployment. This module wires
//! them into an hourly background sweep, spawned from `main.rs` the same way #777's
//! `alerts::run_alert_loop` already is (same `shutdown_fired` watch channel, same
//! `tokio::time::interval` + `MissedTickBehavior::Skip` shape) so a SIGTERM stops this
//! loop too instead of leaving a sweep running past the shutdown grace period.

use std::sync::Arc;
use std::time::Duration;

use crate::edge_mesh::SqliteEdgeMesh;
use crate::storage::{SqliteBootstrap, SqliteEnrollment};

/// How often the sweep runs. None of the pruned rows are time-critical to remove
/// promptly -- worst case between ticks is a bounded amount of dead-row bloat -- so
/// this stays well below #777's per-minute alert loop's frequency.
const RETENTION_TICK: Duration = Duration::from_secs(3600);

/// `batch_issuance` rows older than this are pruned. Per
/// [`SqliteEnrollment::prune_batch_issuance`]'s own doc comment, this should
/// comfortably exceed any realistic retry window for the idempotency key it guards.
const BATCH_ISSUANCE_MAX_AGE_SECS: u64 = 24 * 3600;

/// `mesh_edges` rows not heartbeated since this far back are pruned. Deliberately far
/// wider than [`SqliteEdgeMesh`]'s own 120s liveness window used for *ownership
/// resolution* (`OWNERSHIP_LIVENESS_SECS`) -- that window decides whether a live edge
/// is preferred for new assignments; this one decides whether an edge is gone for
/// good. A week comfortably outlasts any real redeploy or maintenance window.
const EDGE_STALE_MAX_AGE_SECS: i64 = 7 * 24 * 3600;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What [`run_retention_loop`] needs from `main.rs`.
pub struct RetentionLoopConfig {
    /// The control-plane SQLite path; the loop opens its own handle on each of the
    /// stores it prunes, same as every other background loop shares that one file.
    pub db_path: String,
}

/// Run the retention loop until `shutdown` turns `true` (or its sender goes away).
/// Spawned once from `main.rs`; every tick is [`tick`].
pub async fn run_retention_loop(cfg: RetentionLoopConfig, shutdown: tokio::sync::watch::Receiver<bool>) {
    let enrollment = match SqliteEnrollment::open(&cfg.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ct-cp: retention: cannot open the enrollment store, retention disabled: {e}");
            return;
        }
    };
    let bootstrap = match SqliteBootstrap::open(&cfg.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ct-cp: retention: cannot open the bootstrap store, retention disabled: {e}");
            return;
        }
    };
    let edge_mesh = match SqliteEdgeMesh::open(&cfg.db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ct-cp: retention: cannot open the edge-mesh store, retention disabled: {e}");
            return;
        }
    };
    run_retention_loop_with(enrollment, bootstrap, edge_mesh, shutdown, RETENTION_TICK).await;
}

/// [`run_retention_loop`] with injectable stores/period (tests). `MissedTickBehavior::
/// Skip`: a tick that overran does not burst-catch-up; it just waits for the next
/// period boundary -- matching [`crate::alerts::run_alert_loop_with`]'s own rationale.
pub(crate) async fn run_retention_loop_with(
    enrollment: Arc<SqliteEnrollment>,
    bootstrap: Arc<SqliteBootstrap>,
    edge_mesh: Arc<SqliteEdgeMesh>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = interval.tick() => {
                tick(&enrollment, &bootstrap, &edge_mesh, unix_now());
            }
            changed = shutdown.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    eprintln!("ct-cp: retention: loop stopped (shutdown)");
}

/// One sweep pass: prunes each of the four dead-retention tables and logs how many
/// rows each removed (`#775` -- forensics/monitoring visibility into a sweep that
/// otherwise runs silently forever).
fn tick(enrollment: &SqliteEnrollment, bootstrap: &SqliteBootstrap, edge_mesh: &SqliteEdgeMesh, now: u64) {
    match enrollment.prune_redeemed_join_tokens(now) {
        Ok(n) if n > 0 => eprintln!("ct-cp: retention: pruned {n} join_tokens row(s) (#775)"),
        Ok(_) => {}
        Err(e) => eprintln!("ct-cp: retention: prune_redeemed_join_tokens failed: {e}"),
    }
    match enrollment.prune_batch_issuance(now, BATCH_ISSUANCE_MAX_AGE_SECS) {
        Ok(n) if n > 0 => eprintln!("ct-cp: retention: pruned {n} batch_issuance row(s) (#775)"),
        Ok(_) => {}
        Err(e) => eprintln!("ct-cp: retention: prune_batch_issuance failed: {e}"),
    }
    match bootstrap.prune(now) {
        Ok(n) if n > 0 => eprintln!("ct-cp: retention: pruned {n} bootstrap_tokens row(s) (#775)"),
        Ok(_) => {}
        Err(e) => eprintln!("ct-cp: retention: bootstrap prune failed: {e}"),
    }
    let edge_cutoff = (now as i64).saturating_sub(EDGE_STALE_MAX_AGE_SECS);
    match edge_mesh.prune_stale_edges(edge_cutoff) {
        Ok(n) if n > 0 => eprintln!("ct-cp: retention: pruned {n} mesh_edges row(s) (#775)"),
        Ok(_) => {}
        Err(e) => eprintln!("ct-cp: retention: prune_stale_edges failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_prunes_all_four_dead_retention_tables_775() {
        use ct_common::{AgentId, TenantId};

        let enrollment = SqliteEnrollment::open_in_memory().unwrap();
        let bootstrap = SqliteBootstrap::open_in_memory().unwrap();
        let edge_mesh = SqliteEdgeMesh::open_in_memory().unwrap();
        let now = 1_000_000u64;

        // join_tokens: a redeemed row is prune-eligible regardless of age.
        let tenant = TenantId("t1".into());
        let token = enrollment.issue_join_token(&tenant, now).unwrap();
        enrollment.redeem(&token, &AgentId("a1".into()), [7u8; 32], now).unwrap();
        assert_eq!(enrollment.agent_count().unwrap(), 1, "redeeming still binds the agent");

        // batch_issuance: mint a batch at a `now` old enough to already be stale relative
        // to the sweep's `now` below.
        let stale_batch_now = now - BATCH_ISSUANCE_MAX_AGE_SECS - 10;
        enrollment
            .issue_join_tokens_idempotent(&tenant, 1, "stale-key", stale_batch_now)
            .unwrap();

        // bootstrap_tokens: mint one, then redeem it so it's prune-eligible.
        let bt = bootstrap.mint("secret", 60, now).unwrap();
        let _ = bootstrap.redeem(&bt, now);

        // mesh_edges: heartbeat once, far enough in the past to be stale at `now`.
        edge_mesh
            .heartbeat("edge-1", "1.2.3.4:1", None, (now as i64) - EDGE_STALE_MAX_AGE_SECS - 10)
            .unwrap();

        tick(&enrollment, &bootstrap, &edge_mesh, now);

        assert_eq!(enrollment.agent_count().unwrap(), 1, "prune never touches agent_bindings");
        // The DELETE affected join_tokens/batch_issuance/bootstrap_tokens/mesh_edges only;
        // re-running prune on the same state now removes nothing further (idempotent).
        assert_eq!(enrollment.prune_redeemed_join_tokens(now).unwrap(), 0);
        assert_eq!(enrollment.prune_batch_issuance(now, BATCH_ISSUANCE_MAX_AGE_SECS).unwrap(), 0);
        assert_eq!(bootstrap.prune(now).unwrap(), 0);
        let edge_cutoff = (now as i64).saturating_sub(EDGE_STALE_MAX_AGE_SECS);
        assert_eq!(edge_mesh.prune_stale_edges(edge_cutoff).unwrap(), 0);
    }

    #[tokio::test]
    async fn loop_stops_when_the_shutdown_signal_fires_775() {
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let bootstrap = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        let edge_mesh = Arc::new(SqliteEdgeMesh::open_in_memory().unwrap());
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(run_retention_loop_with(
            enrollment,
            bootstrap,
            edge_mesh,
            rx,
            Duration::from_millis(20),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "runs until told to stop");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stops promptly")
            .unwrap();
    }
}
