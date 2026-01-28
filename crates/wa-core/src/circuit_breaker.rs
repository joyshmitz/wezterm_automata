//! Circuit breaker infrastructure for reliability hardening.
//!
//! Provides a small state machine with cooldowns and status reporting.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Number of consecutive successes required to close from half-open.
    pub success_threshold: u32,
    /// Cooldown duration while the circuit is open.
    pub open_cooldown: Duration,
}

impl CircuitBreakerConfig {
    /// Create a new configuration.
    #[must_use]
    pub fn new(failure_threshold: u32, success_threshold: u32, open_cooldown: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            open_cooldown,
        }
    }
}

/// Default circuit breaker configuration for WezTerm CLI operations.
impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 1,
            open_cooldown: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
enum CircuitState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen { successes: u32 },
}

/// Public-facing circuit state for status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitStateKind {
    Closed,
    Open,
    HalfOpen,
}

/// Snapshot of circuit breaker status for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    pub state: CircuitStateKind,
    pub consecutive_failures: u32,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_cooldown_ms: u64,
    pub open_for_ms: Option<u64>,
    pub cooldown_remaining_ms: Option<u64>,
    pub half_open_successes: Option<u32>,
}

impl Default for CircuitBreakerStatus {
    fn default() -> Self {
        Self {
            state: CircuitStateKind::Closed,
            consecutive_failures: 0,
            failure_threshold: 0,
            success_threshold: 0,
            open_cooldown_ms: 0,
            open_for_ms: None,
            cooldown_remaining_ms: None,
            half_open_successes: None,
        }
    }
}

/// Circuit breaker state machine.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitState,
    consecutive_failures: u32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker from configuration.
    #[must_use]
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitState::Closed,
            consecutive_failures: 0,
        }
    }

    /// Check whether an operation is allowed to proceed.
    ///
    /// Returns `true` if allowed; `false` if the circuit is open.
    pub fn allow(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.config.open_cooldown {
                    self.state = CircuitState::HalfOpen { successes: 0 };
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen { .. } => true,
        }
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = 0;
            }
            CircuitState::HalfOpen { successes } => {
                let successes = successes + 1;
                if successes >= self.config.success_threshold {
                    self.consecutive_failures = 0;
                    self.state = CircuitState::Closed;
                } else {
                    self.state = CircuitState::HalfOpen { successes };
                }
            }
            CircuitState::Open { .. } => {
                // Ignore successes while open (no operations should run).
            }
        }
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                }
            }
            CircuitState::HalfOpen { .. } => {
                self.state = CircuitState::Open {
                    opened_at: Instant::now(),
                };
            }
            CircuitState::Open { .. } => {
                // Already open; keep cooldown ticking.
            }
        }
    }

    /// Return a status snapshot for reporting.
    #[must_use]
    pub fn status(&self) -> CircuitBreakerStatus {
        match self.state {
            CircuitState::Closed => CircuitBreakerStatus {
                state: CircuitStateKind::Closed,
                consecutive_failures: self.consecutive_failures,
                failure_threshold: self.config.failure_threshold,
                success_threshold: self.config.success_threshold,
                open_cooldown_ms: self.config.open_cooldown.as_millis() as u64,
                open_for_ms: None,
                cooldown_remaining_ms: None,
                half_open_successes: None,
            },
            CircuitState::Open { opened_at } => {
                let elapsed = opened_at.elapsed();
                let remaining = self.config.open_cooldown.checked_sub(elapsed);
                CircuitBreakerStatus {
                    state: CircuitStateKind::Open,
                    consecutive_failures: self.consecutive_failures,
                    failure_threshold: self.config.failure_threshold,
                    success_threshold: self.config.success_threshold,
                    open_cooldown_ms: self.config.open_cooldown.as_millis() as u64,
                    open_for_ms: Some(elapsed.as_millis() as u64),
                    cooldown_remaining_ms: remaining.map(|d| d.as_millis() as u64),
                    half_open_successes: None,
                }
            }
            CircuitState::HalfOpen { successes } => CircuitBreakerStatus {
                state: CircuitStateKind::HalfOpen,
                consecutive_failures: self.consecutive_failures,
                failure_threshold: self.config.failure_threshold,
                success_threshold: self.config.success_threshold,
                open_cooldown_ms: self.config.open_cooldown.as_millis() as u64,
                open_for_ms: None,
                cooldown_remaining_ms: None,
                half_open_successes: Some(successes),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_opens_after_threshold() {
        let mut breaker =
            CircuitBreaker::new(CircuitBreakerConfig::new(2, 1, Duration::from_secs(10)));

        assert!(breaker.allow());
        breaker.record_failure();
        assert!(matches!(breaker.status().state, CircuitStateKind::Closed));

        breaker.record_failure();
        let status = breaker.status();
        assert!(matches!(status.state, CircuitStateKind::Open));
        assert!(status.cooldown_remaining_ms.is_some());
    }

    #[test]
    fn circuit_half_open_closes_on_success() {
        let mut breaker =
            CircuitBreaker::new(CircuitBreakerConfig::new(1, 1, Duration::from_millis(0)));

        breaker.record_failure();
        // Cooldown is zero, so allow transitions to half-open.
        assert!(breaker.allow());
        assert!(matches!(breaker.status().state, CircuitStateKind::HalfOpen));

        breaker.record_success();
        assert!(matches!(breaker.status().state, CircuitStateKind::Closed));
    }

    #[test]
    fn circuit_half_open_failure_reopens() {
        let mut breaker =
            CircuitBreaker::new(CircuitBreakerConfig::new(1, 2, Duration::from_millis(0)));

        breaker.record_failure();
        assert!(breaker.allow());
        assert!(matches!(breaker.status().state, CircuitStateKind::HalfOpen));

        breaker.record_failure();
        assert!(matches!(breaker.status().state, CircuitStateKind::Open));
    }
}
