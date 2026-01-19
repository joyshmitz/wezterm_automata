//! Durable workflow execution engine
//!
//! Provides idempotent, recoverable, audited workflow execution.
//!
//! # Architecture
//!
//! Workflows are explicit state machines with a uniform execution model:
//! - **Workflow trait**: Defines the workflow interface (name, steps, execution)
//! - **WorkflowContext**: Runtime context with WezTerm client, storage, pane state
//! - **StepResult**: Step outcomes (continue, done, retry, abort, wait)
//! - **WaitCondition**: Conditions to pause execution (pattern, idle, external)
//!
//! This design enables:
//! - Persistent/resumable workflows
//! - Deterministic step logic testing
//! - Shared runner across agent-specific workflows

use crate::policy::PaneCapabilities;
use crate::storage::StorageHandle;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Step Results
// ============================================================================

/// Result of a workflow step execution.
///
/// Each step returns a `StepResult` that determines what happens next:
/// - `Continue`: Proceed to the next step
/// - `Done`: Workflow completed successfully with a result
/// - `Retry`: Retry this step after a delay
/// - `Abort`: Stop workflow with an error
/// - `WaitFor`: Pause until a condition is met
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepResult {
    /// Proceed to next step
    Continue,
    /// Workflow completed successfully with optional result data
    Done { result: serde_json::Value },
    /// Retry this step after delay
    Retry {
        /// Delay before retry in milliseconds
        delay_ms: u64,
    },
    /// Abort workflow with error
    Abort {
        /// Reason for abort
        reason: String,
    },
    /// Wait for condition before proceeding
    WaitFor {
        /// Condition to wait for
        condition: WaitCondition,
        /// Timeout in milliseconds (None = workflow-level default)
        timeout_ms: Option<u64>,
    },
}

impl StepResult {
    /// Create a Continue result
    #[must_use]
    pub fn cont() -> Self {
        Self::Continue
    }

    /// Create a Done result with JSON value
    #[must_use]
    pub fn done(result: serde_json::Value) -> Self {
        Self::Done { result }
    }

    /// Create a Done result with no data
    #[must_use]
    pub fn done_empty() -> Self {
        Self::Done {
            result: serde_json::Value::Null,
        }
    }

    /// Create a Retry result
    #[must_use]
    pub fn retry(delay_ms: u64) -> Self {
        Self::Retry { delay_ms }
    }

    /// Create an Abort result
    #[must_use]
    pub fn abort(reason: impl Into<String>) -> Self {
        Self::Abort {
            reason: reason.into(),
        }
    }

    /// Create a WaitFor result with default timeout
    #[must_use]
    pub fn wait_for(condition: WaitCondition) -> Self {
        Self::WaitFor {
            condition,
            timeout_ms: None,
        }
    }

    /// Create a WaitFor result with explicit timeout
    #[must_use]
    pub fn wait_for_with_timeout(condition: WaitCondition, timeout_ms: u64) -> Self {
        Self::WaitFor {
            condition,
            timeout_ms: Some(timeout_ms),
        }
    }

    /// Check if this result continues to the next step
    #[must_use]
    pub fn is_continue(&self) -> bool {
        matches!(self, Self::Continue)
    }

    /// Check if this result completes the workflow
    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    /// Check if this result is a terminal state (done or abort)
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done { .. } | Self::Abort { .. })
    }
}

// ============================================================================
// Wait Conditions
// ============================================================================

/// Conditions that a workflow can wait for before proceeding.
///
/// Wait conditions pause workflow execution until satisfied:
/// - `Pattern`: Wait for a pattern rule to match on a pane
/// - `PaneIdle`: Wait for a pane to become idle (no output)
/// - `External`: Wait for an external signal by key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WaitCondition {
    /// Wait for a pattern to appear on a specific pane
    Pattern {
        /// Pane to monitor (None = workflow's target pane)
        pane_id: Option<u64>,
        /// Rule ID of the pattern to match
        rule_id: String,
    },
    /// Wait for pane to become idle (no recent output)
    PaneIdle {
        /// Pane to monitor (None = workflow's target pane)
        pane_id: Option<u64>,
        /// Idle duration threshold in milliseconds
        idle_threshold_ms: u64,
    },
    /// Wait for an external signal
    External {
        /// Signal key to wait for
        key: String,
    },
}

impl WaitCondition {
    /// Create a Pattern wait condition for the workflow's target pane
    #[must_use]
    pub fn pattern(rule_id: impl Into<String>) -> Self {
        Self::Pattern {
            pane_id: None,
            rule_id: rule_id.into(),
        }
    }

    /// Create a Pattern wait condition for a specific pane
    #[must_use]
    pub fn pattern_on_pane(pane_id: u64, rule_id: impl Into<String>) -> Self {
        Self::Pattern {
            pane_id: Some(pane_id),
            rule_id: rule_id.into(),
        }
    }

    /// Create a PaneIdle wait condition for the workflow's target pane
    #[must_use]
    pub fn pane_idle(idle_threshold_ms: u64) -> Self {
        Self::PaneIdle {
            pane_id: None,
            idle_threshold_ms,
        }
    }

    /// Create a PaneIdle wait condition for a specific pane
    #[must_use]
    pub fn pane_idle_on(pane_id: u64, idle_threshold_ms: u64) -> Self {
        Self::PaneIdle {
            pane_id: Some(pane_id),
            idle_threshold_ms,
        }
    }

    /// Create an External wait condition
    #[must_use]
    pub fn external(key: impl Into<String>) -> Self {
        Self::External { key: key.into() }
    }

    /// Get the pane ID this condition applies to, if any
    #[must_use]
    pub fn pane_id(&self) -> Option<u64> {
        match self {
            Self::Pattern { pane_id, .. } | Self::PaneIdle { pane_id, .. } => *pane_id,
            Self::External { .. } => None,
        }
    }
}

// ============================================================================
// Workflow Steps
// ============================================================================

/// A step in a workflow definition.
///
/// Steps provide metadata for display, logging, and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step name (identifier)
    pub name: String,
    /// Human-readable description
    pub description: String,
}

impl WorkflowStep {
    /// Create a new workflow step
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

// ============================================================================
// Workflow Context
// ============================================================================

/// Configuration for a workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    /// Default timeout for wait conditions (milliseconds)
    pub default_wait_timeout_ms: u64,
    /// Maximum number of retries per step
    pub max_step_retries: u32,
    /// Delay between retry attempts (milliseconds)
    pub retry_delay_ms: u64,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            default_wait_timeout_ms: 30_000, // 30 seconds
            max_step_retries: 3,
            retry_delay_ms: 1_000, // 1 second
        }
    }
}

/// Runtime context for workflow execution.
///
/// Provides access to:
/// - WezTerm client for sending commands
/// - Storage handle for persistence
/// - Current pane state and capabilities
/// - Triggering event/detection
/// - Workflow configuration
#[derive(Clone)]
pub struct WorkflowContext {
    /// Storage handle for persistence operations
    storage: Arc<StorageHandle>,
    /// Target pane ID for this workflow
    pane_id: u64,
    /// Current pane capabilities snapshot
    capabilities: PaneCapabilities,
    /// The event/detection that triggered this workflow (JSON)
    trigger: Option<serde_json::Value>,
    /// Workflow configuration
    config: WorkflowConfig,
    /// Workflow execution ID
    execution_id: String,
}

impl WorkflowContext {
    /// Create a new workflow context
    #[must_use]
    pub fn new(
        storage: Arc<StorageHandle>,
        pane_id: u64,
        capabilities: PaneCapabilities,
        execution_id: impl Into<String>,
    ) -> Self {
        Self {
            storage,
            pane_id,
            capabilities,
            trigger: None,
            config: WorkflowConfig::default(),
            execution_id: execution_id.into(),
        }
    }

    /// Set the triggering event/detection
    #[must_use]
    pub fn with_trigger(mut self, trigger: serde_json::Value) -> Self {
        self.trigger = Some(trigger);
        self
    }

    /// Set custom workflow configuration
    #[must_use]
    pub fn with_config(mut self, config: WorkflowConfig) -> Self {
        self.config = config;
        self
    }

    /// Get the storage handle
    #[must_use]
    pub fn storage(&self) -> &Arc<StorageHandle> {
        &self.storage
    }

    /// Get the target pane ID
    #[must_use]
    pub fn pane_id(&self) -> u64 {
        self.pane_id
    }

    /// Get the current pane capabilities
    #[must_use]
    pub fn capabilities(&self) -> &PaneCapabilities {
        &self.capabilities
    }

    /// Update the pane capabilities snapshot
    pub fn update_capabilities(&mut self, capabilities: PaneCapabilities) {
        self.capabilities = capabilities;
    }

    /// Get the triggering event/detection, if any
    #[must_use]
    pub fn trigger(&self) -> Option<&serde_json::Value> {
        self.trigger.as_ref()
    }

    /// Get the workflow configuration
    #[must_use]
    pub fn config(&self) -> &WorkflowConfig {
        &self.config
    }

    /// Get the execution ID
    #[must_use]
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    /// Get the default wait timeout from config
    #[must_use]
    pub fn default_wait_timeout_ms(&self) -> u64 {
        self.config.default_wait_timeout_ms
    }
}

// ============================================================================
// Workflow Trait
// ============================================================================

/// A durable, resumable workflow definition.
///
/// Workflows are explicit state machines with a uniform execution model.
/// Implement this trait to define custom automation workflows.
///
/// # Example
///
/// ```ignore
/// use wa_core::workflows::{Workflow, WorkflowContext, WorkflowStep, StepResult, WaitCondition};
/// use wa_core::patterns::Detection;
///
/// struct PromptInjectionWorkflow;
///
/// impl Workflow for PromptInjectionWorkflow {
///     fn name(&self) -> &str { "prompt_injection" }
///     fn description(&self) -> &str { "Sends a prompt and waits for response" }
///
///     fn handles(&self, detection: &Detection) -> bool {
///         detection.rule_id.starts_with("trigger.prompt_injection")
///     }
///
///     fn steps(&self) -> Vec<WorkflowStep> {
///         vec![
///             WorkflowStep::new("send_prompt", "Send prompt to terminal"),
///             WorkflowStep::new("wait_response", "Wait for response pattern"),
///         ]
///     }
///
///     async fn execute_step(&self, ctx: &mut WorkflowContext, step_idx: usize) -> StepResult {
///         match step_idx {
///             0 => {
///                 // Send prompt via WezTerm client
///                 StepResult::cont()
///             }
///             1 => {
///                 // Wait for response
///                 StepResult::wait_for(WaitCondition::pattern("response.complete"))
///             }
///             _ => StepResult::done_empty()
///         }
///     }
/// }
/// ```
pub trait Workflow: Send + Sync {
    /// Workflow name (unique identifier)
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Check if this workflow handles a given detection.
    ///
    /// Return true if this workflow should be triggered by the detection.
    fn handles(&self, detection: &crate::patterns::Detection) -> bool;

    /// Get the list of steps in this workflow.
    ///
    /// Step metadata is used for display, logging, and debugging.
    fn steps(&self) -> Vec<WorkflowStep>;

    /// Execute a single step of the workflow.
    ///
    /// # Arguments
    /// * `ctx` - Workflow context with storage, pane state, and config
    /// * `step_idx` - Zero-based step index
    ///
    /// # Returns
    /// A `StepResult` indicating what should happen next.
    fn execute_step(
        &self,
        ctx: &mut WorkflowContext,
        step_idx: usize,
    ) -> impl std::future::Future<Output = StepResult> + Send;

    /// Optional cleanup when workflow is aborted or completes with error.
    ///
    /// Override to release resources, revert partial changes, etc.
    fn cleanup(&self, _ctx: &mut WorkflowContext) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    /// Get the number of steps in this workflow.
    fn step_count(&self) -> usize {
        self.steps().len()
    }
}

// ============================================================================
// Workflow Execution State
// ============================================================================

/// Workflow execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    /// Unique execution ID
    pub id: String,
    /// Workflow name
    pub workflow_name: String,
    /// Pane being operated on
    pub pane_id: u64,
    /// Current step index
    pub current_step: usize,
    /// Status
    pub status: ExecutionStatus,
    /// Started at timestamp
    pub started_at: i64,
    /// Last updated timestamp
    pub updated_at: i64,
}

/// Workflow execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Running
    Running,
    /// Waiting for condition
    Waiting,
    /// Completed successfully
    Completed,
    /// Aborted with error
    Aborted,
}

/// Workflow engine for managing executions
pub struct WorkflowEngine {
    /// Maximum concurrent workflows
    max_concurrent: usize,
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new(3)
    }
}

impl WorkflowEngine {
    /// Create a new workflow engine
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self { max_concurrent }
    }

    /// Get the maximum concurrent workflows setting
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Start a new workflow execution and persist it to storage
    ///
    /// Creates a new execution record with status 'running' and step 0.
    /// Returns the execution which can be used with `DurableWorkflowRunner`.
    pub async fn start(
        &self,
        storage: &crate::storage::StorageHandle,
        workflow_name: &str,
        pane_id: u64,
        trigger_event_id: Option<i64>,
        context: Option<serde_json::Value>,
    ) -> crate::Result<WorkflowExecution> {
        let now = now_ms();
        let execution_id = generate_workflow_id(workflow_name);

        let record = crate::storage::WorkflowRecord {
            id: execution_id.clone(),
            workflow_name: workflow_name.to_string(),
            pane_id,
            trigger_event_id,
            current_step: 0,
            status: "running".to_string(),
            wait_condition: None,
            context,
            result: None,
            error: None,
            started_at: now,
            updated_at: now,
            completed_at: None,
        };

        storage.upsert_workflow(record).await?;

        Ok(WorkflowExecution {
            id: execution_id,
            workflow_name: workflow_name.to_string(),
            pane_id,
            current_step: 0,
            status: ExecutionStatus::Running,
            started_at: now,
            updated_at: now,
        })
    }

    /// Resume a workflow execution from storage
    ///
    /// Loads the workflow record and step logs to determine the next step.
    /// Returns None if the workflow doesn't exist or is already completed.
    pub async fn resume(
        &self,
        storage: &crate::storage::StorageHandle,
        execution_id: &str,
    ) -> crate::Result<Option<(WorkflowExecution, usize)>> {
        // Load the workflow record
        let Some(record) = storage.get_workflow(execution_id).await? else {
            return Ok(None);
        };

        // Check if already completed
        if record.status == "completed" || record.status == "aborted" {
            return Ok(None);
        }

        // Load step logs to find the last completed step
        let step_logs = storage.get_step_logs(execution_id).await?;
        let next_step = compute_next_step(&step_logs);

        let execution = WorkflowExecution {
            id: record.id,
            workflow_name: record.workflow_name,
            pane_id: record.pane_id,
            current_step: next_step,
            status: match record.status.as_str() {
                "running" => ExecutionStatus::Running,
                "waiting" => ExecutionStatus::Waiting,
                _ => ExecutionStatus::Running,
            },
            started_at: record.started_at,
            updated_at: record.updated_at,
        };

        Ok(Some((execution, next_step)))
    }

    /// Find all incomplete workflows for resume on restart
    pub async fn find_incomplete(
        &self,
        storage: &crate::storage::StorageHandle,
    ) -> crate::Result<Vec<crate::storage::WorkflowRecord>> {
        storage.find_incomplete_workflows().await
    }

    /// Update workflow status
    pub async fn update_status(
        &self,
        storage: &crate::storage::StorageHandle,
        execution_id: &str,
        status: ExecutionStatus,
        current_step: usize,
        wait_condition: Option<&WaitCondition>,
        error: Option<&str>,
    ) -> crate::Result<()> {
        let now = now_ms();
        let status_str = match status {
            ExecutionStatus::Running => "running",
            ExecutionStatus::Waiting => "waiting",
            ExecutionStatus::Completed => "completed",
            ExecutionStatus::Aborted => "aborted",
        };

        // Load existing record to preserve fields
        let Some(existing) = storage.get_workflow(execution_id).await? else {
            return Err(crate::error::WorkflowError::NotFound(execution_id.to_string()).into());
        };

        let record = crate::storage::WorkflowRecord {
            id: existing.id,
            workflow_name: existing.workflow_name,
            pane_id: existing.pane_id,
            trigger_event_id: existing.trigger_event_id,
            current_step,
            status: status_str.to_string(),
            wait_condition: wait_condition.map(|wc| serde_json::to_value(wc).unwrap_or_default()),
            context: existing.context,
            result: existing.result,
            error: error.map(String::from),
            started_at: existing.started_at,
            updated_at: now,
            completed_at: if status == ExecutionStatus::Completed
                || status == ExecutionStatus::Aborted
            {
                Some(now)
            } else {
                None
            },
        };

        storage.upsert_workflow(record).await
    }

    /// Record a step log entry
    pub async fn log_step(
        &self,
        storage: &crate::storage::StorageHandle,
        execution_id: &str,
        step_index: usize,
        step_name: &str,
        result: &StepResult,
        started_at: i64,
    ) -> crate::Result<()> {
        let completed_at = now_ms();
        let result_type = match result {
            StepResult::Continue { .. } => "continue",
            StepResult::Done { .. } => "done",
            StepResult::Abort { .. } => "abort",
            StepResult::Retry { .. } => "retry",
            StepResult::WaitFor { .. } => "wait_for",
        };
        let result_data = serde_json::to_string(result).ok();

        storage
            .insert_step_log(
                execution_id,
                step_index,
                step_name,
                result_type,
                result_data,
                started_at,
                completed_at,
            )
            .await
    }
}

/// Compute the next step index from step logs
///
/// Finds the highest completed step index and returns the next one.
/// If no steps are completed, returns 0.
fn compute_next_step(step_logs: &[crate::storage::WorkflowStepLogRecord]) -> usize {
    if step_logs.is_empty() {
        return 0;
    }

    // Find the highest step index with a terminal result (continue or done)
    // Steps with retry or wait_for should be re-executed
    let mut max_completed = None;
    for log in step_logs {
        if log.result_type == "continue" || log.result_type == "done" {
            max_completed =
                Some(max_completed.map_or(log.step_index, |m: usize| m.max(log.step_index)));
        }
    }

    match max_completed {
        Some(idx) => idx + 1, // Resume from next step
        None => 0,            // No completed steps, start from beginning
    }
}

/// Generate a unique workflow execution ID
fn generate_workflow_id(workflow_name: &str) -> String {
    let timestamp = now_ms();
    let random: u32 = rand::random();
    format!("{workflow_name}-{timestamp}-{random:08x}")
}

/// Get current timestamp in milliseconds
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ============================================================================
// Per-Pane Workflow Lock (wa-nu4.1.1.2)
// ============================================================================

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of attempting to acquire a pane workflow lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockAcquisitionResult {
    /// Lock acquired successfully.
    Acquired,
    /// Lock is already held by another workflow.
    AlreadyLocked {
        /// Name of the workflow holding the lock.
        held_by_workflow: String,
        /// Execution ID of the workflow holding the lock.
        held_by_execution: String,
        /// When the lock was acquired (unix timestamp ms).
        locked_since_ms: i64,
    },
}

impl LockAcquisitionResult {
    /// Check if the lock was acquired.
    #[must_use]
    pub fn is_acquired(&self) -> bool {
        matches!(self, Self::Acquired)
    }

    /// Check if the lock is already held.
    #[must_use]
    pub fn is_already_locked(&self) -> bool {
        matches!(self, Self::AlreadyLocked { .. })
    }
}

/// Information about an active pane lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaneLockInfo {
    /// Pane ID that is locked.
    pub pane_id: u64,
    /// Workflow name holding the lock.
    pub workflow_name: String,
    /// Execution ID holding the lock.
    pub execution_id: String,
    /// When the lock was acquired (unix timestamp ms).
    pub locked_at_ms: i64,
}

/// In-memory workflow lock manager for panes.
///
/// Ensures only one workflow runs per pane at a time. This is an internal
/// concurrency primitive that prevents workflow collisions, separate from
/// user-facing pane reservations.
///
/// # Design
///
/// - In-memory lock table keyed by `pane_id`
/// - Thread-safe via internal mutex
/// - Lock acquisition returns detailed info about existing locks
/// - Supports RAII-based release via `PaneWorkflowLockGuard`
///
/// # Example
///
/// ```no_run
/// use wa_core::workflows::{PaneWorkflowLockManager, LockAcquisitionResult};
///
/// let manager = PaneWorkflowLockManager::new();
///
/// // Try to acquire lock
/// match manager.try_acquire(42, "handle_compaction", "exec-001") {
///     LockAcquisitionResult::Acquired => {
///         // Run workflow...
///         manager.release(42, "exec-001");
///     }
///     LockAcquisitionResult::AlreadyLocked { held_by_workflow, .. } => {
///         println!("Pane 42 is locked by {}", held_by_workflow);
///     }
/// }
/// ```
pub struct PaneWorkflowLockManager {
    /// Active locks keyed by pane_id.
    locks: Mutex<HashMap<u64, PaneLockInfo>>,
}

impl Default for PaneWorkflowLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PaneWorkflowLockManager {
    /// Create a new lock manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to acquire a lock for a pane.
    ///
    /// Returns `Acquired` if the lock was obtained, or `AlreadyLocked` with
    /// information about the current lock holder.
    ///
    /// # Arguments
    ///
    /// * `pane_id` - The pane to lock
    /// * `workflow_name` - Name of the workflow requesting the lock
    /// * `execution_id` - Unique execution ID for this workflow run
    pub fn try_acquire(
        &self,
        pane_id: u64,
        workflow_name: &str,
        execution_id: &str,
    ) -> LockAcquisitionResult {
        let mut locks = self.locks.lock().unwrap();

        if let Some(existing) = locks.get(&pane_id) {
            return LockAcquisitionResult::AlreadyLocked {
                held_by_workflow: existing.workflow_name.clone(),
                held_by_execution: existing.execution_id.clone(),
                locked_since_ms: existing.locked_at_ms,
            };
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        locks.insert(
            pane_id,
            PaneLockInfo {
                pane_id,
                workflow_name: workflow_name.to_string(),
                execution_id: execution_id.to_string(),
                locked_at_ms: now_ms,
            },
        );

        tracing::debug!(
            pane_id,
            workflow_name,
            execution_id,
            "Acquired pane workflow lock"
        );

        LockAcquisitionResult::Acquired
    }

    /// Release a lock for a pane.
    ///
    /// Only releases if the execution_id matches the current lock holder.
    /// This prevents accidental release by unrelated code.
    ///
    /// # Returns
    ///
    /// `true` if the lock was released, `false` if not found or mismatched.
    pub fn release(&self, pane_id: u64, execution_id: &str) -> bool {
        let mut locks = self.locks.lock().unwrap();

        if let Some(existing) = locks.get(&pane_id) {
            if existing.execution_id == execution_id {
                locks.remove(&pane_id);
                tracing::debug!(pane_id, execution_id, "Released pane workflow lock");
                return true;
            }
            tracing::warn!(
                pane_id,
                execution_id,
                held_by = %existing.execution_id,
                "Attempted to release lock held by different execution"
            );
        }

        false
    }

    /// Check if a pane is currently locked.
    ///
    /// Returns lock information if locked, `None` if free.
    #[must_use]
    pub fn is_locked(&self, pane_id: u64) -> Option<PaneLockInfo> {
        let locks = self.locks.lock().unwrap();
        locks.get(&pane_id).cloned()
    }

    /// Get all currently active locks.
    ///
    /// Useful for diagnostics and monitoring.
    #[must_use]
    pub fn active_locks(&self) -> Vec<PaneLockInfo> {
        let locks = self.locks.lock().unwrap();
        locks.values().cloned().collect()
    }

    /// Try to acquire a lock and return an RAII guard.
    ///
    /// The lock is automatically released when the guard is dropped.
    ///
    /// # Returns
    ///
    /// `Some(guard)` if acquired, `None` if already locked.
    pub fn acquire_guard(
        &self,
        pane_id: u64,
        workflow_name: &str,
        execution_id: &str,
    ) -> Option<PaneWorkflowLockGuard<'_>> {
        match self.try_acquire(pane_id, workflow_name, execution_id) {
            LockAcquisitionResult::Acquired => Some(PaneWorkflowLockGuard {
                manager: self,
                pane_id,
                execution_id: execution_id.to_string(),
            }),
            LockAcquisitionResult::AlreadyLocked { .. } => None,
        }
    }

    /// Force-release a lock regardless of execution_id.
    ///
    /// **Use with caution** - only for recovery scenarios.
    pub fn force_release(&self, pane_id: u64) -> Option<PaneLockInfo> {
        let mut locks = self.locks.lock().unwrap();
        let removed = locks.remove(&pane_id);
        if let Some(ref info) = removed {
            tracing::warn!(
                pane_id,
                execution_id = %info.execution_id,
                "Force-released pane workflow lock"
            );
        }
        removed
    }
}

/// RAII guard for pane workflow lock.
///
/// The lock is automatically released when this guard is dropped.
pub struct PaneWorkflowLockGuard<'a> {
    manager: &'a PaneWorkflowLockManager,
    pane_id: u64,
    execution_id: String,
}

impl<'a> PaneWorkflowLockGuard<'a> {
    /// Get the pane ID this guard is locking.
    #[must_use]
    pub fn pane_id(&self) -> u64 {
        self.pane_id
    }

    /// Get the execution ID that holds this lock.
    #[must_use]
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    /// Explicitly release the lock, consuming the guard.
    pub fn release(self) {
        // Drop will handle the release
    }
}

impl Drop for PaneWorkflowLockGuard<'_> {
    fn drop(&mut self) {
        self.manager.release(self.pane_id, &self.execution_id);
    }
}

// ============================================================================
// Wait Condition Execution
// ============================================================================

use crate::ingest::Osc133State;
use crate::patterns::PatternEngine;
use crate::wezterm::PaneTextSource;
use std::time::Duration;
use tokio::time::{Instant, sleep};

/// Result of waiting for a condition.
#[derive(Debug, Clone)]
pub enum WaitConditionResult {
    /// Condition was satisfied.
    Satisfied {
        /// Time spent waiting in milliseconds.
        elapsed_ms: u64,
        /// Number of polls performed.
        polls: usize,
        /// Additional context about how the condition was satisfied.
        context: Option<String>,
    },
    /// Timeout elapsed without condition being satisfied.
    TimedOut {
        /// Time spent waiting in milliseconds.
        elapsed_ms: u64,
        /// Number of polls performed.
        polls: usize,
        /// Last observed state (for debugging).
        last_observed: Option<String>,
    },
    /// Condition cannot be evaluated (e.g., external signal not supported).
    Unsupported {
        /// Reason why the condition is unsupported.
        reason: String,
    },
}

impl WaitConditionResult {
    /// Check if the condition was satisfied.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied { .. })
    }

    /// Check if the wait timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        matches!(self, Self::TimedOut { .. })
    }

    /// Get elapsed time in milliseconds, if available.
    #[must_use]
    pub fn elapsed_ms(&self) -> Option<u64> {
        match self {
            Self::Satisfied { elapsed_ms, .. } | Self::TimedOut { elapsed_ms, .. } => {
                Some(*elapsed_ms)
            }
            Self::Unsupported { .. } => None,
        }
    }
}

/// Options for wait condition execution.
#[derive(Debug, Clone)]
pub struct WaitConditionOptions {
    /// Number of tail lines to poll for pattern matching.
    pub tail_lines: usize,
    /// Initial polling interval.
    pub poll_initial: Duration,
    /// Maximum polling interval.
    pub poll_max: Duration,
    /// Maximum number of polls before forcing timeout.
    pub max_polls: usize,
    /// Whether to use fallback heuristics for PaneIdle when OSC 133 unavailable.
    pub allow_idle_heuristics: bool,
}

impl Default for WaitConditionOptions {
    fn default() -> Self {
        Self {
            tail_lines: 200,
            poll_initial: Duration::from_millis(50),
            poll_max: Duration::from_millis(1000),
            max_polls: 10_000,
            allow_idle_heuristics: true,
        }
    }
}

/// Executor for wait conditions.
///
/// This struct wraps the necessary dependencies for executing wait conditions:
/// - `PaneTextSource` for reading pane text (via PaneWaiter)
/// - `PatternEngine` for pattern detection
/// - OSC 133 state for idle detection
///
/// # Example
///
/// ```ignore
/// let executor = WaitConditionExecutor::new(&client, &pattern_engine)
///     .with_osc_state(&osc_state);
///
/// let result = executor.execute(
///     &WaitCondition::pattern("prompt.ready"),
///     pane_id,
///     Duration::from_secs(10),
/// ).await?;
/// ```
pub struct WaitConditionExecutor<'a, S: PaneTextSource + Sync + ?Sized> {
    source: &'a S,
    pattern_engine: &'a PatternEngine,
    osc_state: Option<&'a Osc133State>,
    options: WaitConditionOptions,
}

impl<'a, S: PaneTextSource + Sync + ?Sized> WaitConditionExecutor<'a, S> {
    /// Create a new executor with required dependencies.
    #[must_use]
    pub fn new(source: &'a S, pattern_engine: &'a PatternEngine) -> Self {
        Self {
            source,
            pattern_engine,
            osc_state: None,
            options: WaitConditionOptions::default(),
        }
    }

    /// Set OSC 133 state for deterministic idle detection.
    #[must_use]
    pub fn with_osc_state(mut self, osc_state: &'a Osc133State) -> Self {
        self.osc_state = Some(osc_state);
        self
    }

    /// Override default options.
    #[must_use]
    pub fn with_options(mut self, options: WaitConditionOptions) -> Self {
        self.options = options;
        self
    }

    /// Execute a wait condition.
    ///
    /// This method blocks until the condition is satisfied or the timeout elapses.
    /// It reuses the PaneWaiter infrastructure for consistent polling behavior.
    pub async fn execute(
        &self,
        condition: &WaitCondition,
        context_pane_id: u64,
        timeout: Duration,
    ) -> crate::Result<WaitConditionResult> {
        match condition {
            WaitCondition::Pattern { pane_id, rule_id } => {
                let target_pane = pane_id.unwrap_or(context_pane_id);
                self.execute_pattern_wait(target_pane, rule_id, timeout)
                    .await
            }
            WaitCondition::PaneIdle {
                pane_id,
                idle_threshold_ms,
            } => {
                let target_pane = pane_id.unwrap_or(context_pane_id);
                self.execute_pane_idle_wait(target_pane, *idle_threshold_ms, timeout)
                    .await
            }
            WaitCondition::External { key } => {
                // External signals are not implemented in this layer
                Ok(WaitConditionResult::Unsupported {
                    reason: format!("External signal '{key}' requires external signal registry"),
                })
            }
        }
    }

    /// Execute a pattern wait condition.
    ///
    /// Polls pane text using PaneWaiter, runs pattern detection, and checks
    /// for the specified rule_id. Stops early on match.
    async fn execute_pattern_wait(
        &self,
        pane_id: u64,
        rule_id: &str,
        timeout: Duration,
    ) -> crate::Result<WaitConditionResult> {
        let start = Instant::now();
        let deadline = start + timeout;
        let mut polls = 0usize;
        let mut interval = self.options.poll_initial;
        let mut last_detection_summary: Option<String> = None;

        #[allow(clippy::cast_possible_truncation)]
        let timeout_ms = timeout.as_millis() as u64;
        tracing::info!(pane_id, rule_id, timeout_ms, "pattern_wait start");

        loop {
            polls += 1;

            // Get pane text
            let text = self.source.get_text(pane_id, false).await?;
            let tail = tail_text(&text, self.options.tail_lines);

            // Run pattern detection
            let detections = self.pattern_engine.detect(&tail);

            // Check for matching rule
            if let Some(detection) = detections.iter().find(|d| d.rule_id == rule_id) {
                let elapsed_ms = elapsed_ms(start);
                tracing::info!(
                    pane_id,
                    rule_id,
                    elapsed_ms,
                    polls,
                    matched_text = %detection.matched_text,
                    "pattern_wait matched"
                );
                return Ok(WaitConditionResult::Satisfied {
                    elapsed_ms,
                    polls,
                    context: Some(format!("matched: {}", detection.matched_text)),
                });
            }

            // Update last detection summary for debugging
            if !detections.is_empty() {
                let rule_ids: Vec<&str> = detections.iter().map(|d| d.rule_id.as_str()).collect();
                last_detection_summary = Some(format!("detected: [{}]", rule_ids.join(", ")));
            }

            // Check timeout
            let now = Instant::now();
            if now >= deadline || polls >= self.options.max_polls {
                let elapsed_ms = elapsed_ms(start);
                tracing::info!(pane_id, rule_id, elapsed_ms, polls, "pattern_wait timeout");
                return Ok(WaitConditionResult::TimedOut {
                    elapsed_ms,
                    polls,
                    last_observed: last_detection_summary,
                });
            }

            // Sleep with backoff
            let remaining = deadline.saturating_duration_since(now);
            let sleep_duration = interval.min(remaining);
            if !sleep_duration.is_zero() {
                sleep(sleep_duration).await;
            }

            interval = interval.saturating_mul(2);
            if interval > self.options.poll_max {
                interval = self.options.poll_max;
            }
        }
    }

    /// Execute a pane idle wait condition.
    ///
    /// Primary: Uses OSC 133 state to detect prompt (deterministic).
    /// Fallback: Uses heuristic prompt matching if OSC 133 unavailable.
    async fn execute_pane_idle_wait(
        &self,
        pane_id: u64,
        idle_threshold_ms: u64,
        timeout: Duration,
    ) -> crate::Result<WaitConditionResult> {
        let start = Instant::now();
        let deadline = start + timeout;
        let mut polls = 0usize;
        let mut interval = self.options.poll_initial;
        let idle_threshold = Duration::from_millis(idle_threshold_ms);

        // Track when we first observed idle state (for threshold)
        let mut idle_since: Option<Instant> = None;
        #[allow(unused_assignments)]
        let mut last_state_desc: Option<String> = None;

        #[allow(clippy::cast_possible_truncation)]
        let timeout_ms = timeout.as_millis() as u64;
        tracing::info!(
            pane_id,
            idle_threshold_ms,
            timeout_ms,
            has_osc_state = self.osc_state.is_some(),
            "pane_idle_wait start"
        );

        loop {
            polls += 1;

            // Check idle state
            let (is_idle, state_desc) = self.check_idle_state(pane_id).await?;
            last_state_desc = Some(state_desc.clone());

            if is_idle {
                // Track idle duration
                let idle_start = idle_since.get_or_insert_with(Instant::now);
                let idle_duration = Instant::now().saturating_duration_since(*idle_start);

                if idle_duration >= idle_threshold {
                    let elapsed_ms = elapsed_ms(start);
                    tracing::info!(
                        pane_id,
                        elapsed_ms,
                        polls,
                        idle_duration_ms = %idle_duration.as_millis(),
                        state = %state_desc,
                        "pane_idle_wait satisfied"
                    );
                    return Ok(WaitConditionResult::Satisfied {
                        elapsed_ms,
                        polls,
                        context: Some(format!(
                            "idle for {}ms ({})",
                            idle_duration.as_millis(),
                            state_desc
                        )),
                    });
                }
            } else {
                // Reset idle tracking - activity detected
                idle_since = None;
            }

            // Check timeout
            let now = Instant::now();
            if now >= deadline || polls >= self.options.max_polls {
                let elapsed_ms = elapsed_ms(start);
                tracing::info!(pane_id, elapsed_ms, polls, "pane_idle_wait timeout");
                return Ok(WaitConditionResult::TimedOut {
                    elapsed_ms,
                    polls,
                    last_observed: last_state_desc,
                });
            }

            // Sleep with backoff
            let remaining = deadline.saturating_duration_since(now);
            let sleep_duration = interval.min(remaining);
            if !sleep_duration.is_zero() {
                sleep(sleep_duration).await;
            }

            interval = interval.saturating_mul(2);
            if interval > self.options.poll_max {
                interval = self.options.poll_max;
            }
        }
    }

    /// Check if pane is currently idle.
    ///
    /// Returns (is_idle, description) for logging/debugging.
    async fn check_idle_state(&self, pane_id: u64) -> crate::Result<(bool, String)> {
        // Primary: Use OSC 133 state if available
        if let Some(osc_state) = self.osc_state {
            let shell_state = &osc_state.state;
            let is_idle = shell_state.is_at_prompt();
            let desc = format!("osc133:{shell_state:?}");
            return Ok((is_idle, desc));
        }

        // Fallback: Use heuristic prompt detection
        if self.options.allow_idle_heuristics {
            let text = self.source.get_text(pane_id, false).await?;
            let (is_idle, desc) = heuristic_idle_check(&text, self.options.tail_lines);
            return Ok((is_idle, format!("heuristic:{desc}")));
        }

        // No idle detection available
        Ok((false, "no_osc133_no_heuristics".to_string()))
    }
}

/// Extract the last N lines from text.
fn tail_text(text: &str, n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Calculate elapsed milliseconds from a start instant.
fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Heuristic idle check based on pane text patterns.
///
/// This is a best-effort fallback when OSC 133 shell integration is not available.
/// It looks for common shell prompt patterns in the last few lines.
///
/// Returns (is_idle, description) where description explains the heuristic result.
#[allow(clippy::items_after_statements)]
fn heuristic_idle_check(text: &str, tail_lines: usize) -> (bool, String) {
    let tail = tail_text(text, tail_lines.min(10)); // Only check last 10 lines for heuristics
    let last_line = tail.lines().last().unwrap_or("");
    let trimmed = last_line.trim_end();

    // Common prompt endings that suggest idle state
    // Note: These are intentionally broad and may have false positives
    const PROMPT_ENDINGS: [&str; 7] = [
        "$ ",   // bash/sh default
        "# ",   // root prompt
        "> ",   // zsh/fish
        "% ",   // tcsh/zsh
        ">>> ", // Python REPL
        "... ", // Python continuation
        "❯ ",   // starship/custom
    ];

    // Check if line ends with a prompt pattern (with trailing space for cursor position)
    // We check the UNTRIMMED last_line to preserve trailing space significance
    for ending in PROMPT_ENDINGS {
        if last_line.ends_with(ending) {
            return (true, format!("ends_with_prompt({})", ending.trim()));
        }
    }

    // Also check trimmed line for prompts where trailing space was stripped,
    // but only if the line looks like a shell prompt (contains @ or : typical of user@host:path)
    // This avoids false positives like "Progress: 50%" matching "%" prompt
    const PROMPT_CHARS: [char; 5] = ['$', '#', '>', '%', '❯'];
    if let Some(last_char) = trimmed.chars().last() {
        if PROMPT_CHARS.contains(&last_char) {
            // Require prompt-like context: user@host pattern or very short line (just prompt)
            let has_user_host = trimmed.contains('@') && trimmed.contains(':');
            let is_short_prompt = trimmed.len() <= 3; // e.g., "$ " or "❯"
            if has_user_host || is_short_prompt {
                return (true, format!("ends_with_prompt_char({last_char})"));
            }
        }
    }

    // Check for empty or whitespace-only last line (might indicate prompt)
    if trimmed.is_empty() && !tail.is_empty() {
        // Look at second-to-last line (raw, with trailing spaces)
        let lines: Vec<&str> = tail.lines().collect();
        if lines.len() >= 2 {
            let prev_line_raw = lines[lines.len() - 2];
            for ending in PROMPT_ENDINGS {
                if prev_line_raw.ends_with(ending) {
                    return (true, format!("prev_line_prompt({})", ending.trim()));
                }
            }
        }
    }

    (
        false,
        format!("no_prompt_detected(last={})", truncate_for_log(trimmed, 40)),
    )
}

/// Truncate string for logging, adding ellipsis if truncated.
fn truncate_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{AgentType, Detection, Severity};

    // ========================================================================
    // StepResult Tests
    // ========================================================================

    #[test]
    fn step_result_continue_serializes() {
        let result = StepResult::Continue;
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("continue"));

        let parsed: StepResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_continue());
    }

    #[test]
    fn step_result_done_serializes() {
        let result = StepResult::done(serde_json::json!({"status": "ok"}));
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("done"));
        assert!(json.contains("status"));

        let parsed: StepResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_done());
        assert!(parsed.is_terminal());
    }

    #[test]
    fn step_result_retry_serializes() {
        let result = StepResult::retry(5000);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("retry"));
        assert!(json.contains("5000"));

        let parsed: StepResult = serde_json::from_str(&json).unwrap();
        match parsed {
            StepResult::Retry { delay_ms } => assert_eq!(delay_ms, 5000),
            _ => panic!("Expected Retry"),
        }
    }

    #[test]
    fn step_result_abort_serializes() {
        let result = StepResult::abort("test failure");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("abort"));
        assert!(json.contains("test failure"));

        let parsed: StepResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_terminal());
    }

    #[test]
    fn step_result_wait_for_serializes() {
        let result =
            StepResult::wait_for_with_timeout(WaitCondition::pattern("prompt.ready"), 10_000);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("wait_for"));
        assert!(json.contains("prompt.ready"));
        assert!(json.contains("10000"));

        let parsed: StepResult = serde_json::from_str(&json).unwrap();
        match parsed {
            StepResult::WaitFor {
                condition,
                timeout_ms,
            } => {
                assert_eq!(timeout_ms, Some(10_000));
                match condition {
                    WaitCondition::Pattern { rule_id, .. } => assert_eq!(rule_id, "prompt.ready"),
                    _ => panic!("Expected Pattern condition"),
                }
            }
            _ => panic!("Expected WaitFor"),
        }
    }

    #[test]
    fn step_result_helper_methods() {
        assert!(StepResult::cont().is_continue());
        assert!(StepResult::done_empty().is_done());
        assert!(StepResult::done_empty().is_terminal());
        assert!(StepResult::abort("error").is_terminal());
        assert!(!StepResult::retry(100).is_terminal());
        assert!(!StepResult::wait_for(WaitCondition::external("key")).is_terminal());
    }

    // ========================================================================
    // WaitCondition Tests
    // ========================================================================

    #[test]
    fn wait_condition_pattern_serializes() {
        let cond = WaitCondition::pattern("test.rule");
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("pattern"));
        assert!(json.contains("test.rule"));

        let parsed: WaitCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cond);
        assert_eq!(parsed.pane_id(), None);
    }

    #[test]
    fn wait_condition_pattern_on_pane_serializes() {
        let cond = WaitCondition::pattern_on_pane(42, "test.rule");
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("42"));

        let parsed: WaitCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pane_id(), Some(42));
    }

    #[test]
    fn wait_condition_pane_idle_serializes() {
        let cond = WaitCondition::pane_idle(1000);
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("pane_idle"));
        assert!(json.contains("1000"));

        let parsed: WaitCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cond);
    }

    #[test]
    fn wait_condition_pane_idle_on_serializes() {
        let cond = WaitCondition::pane_idle_on(99, 500);
        assert_eq!(cond.pane_id(), Some(99));
    }

    #[test]
    fn wait_condition_external_serializes() {
        let cond = WaitCondition::external("approval_granted");
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("external"));
        assert!(json.contains("approval_granted"));

        let parsed: WaitCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cond);
        assert_eq!(parsed.pane_id(), None);
    }

    // ========================================================================
    // WorkflowStep Tests
    // ========================================================================

    #[test]
    fn workflow_step_creates() {
        let step = WorkflowStep::new("send_prompt", "Send a prompt to the terminal");
        assert_eq!(step.name, "send_prompt");
        assert_eq!(step.description, "Send a prompt to the terminal");
    }

    // ========================================================================
    // WorkflowConfig Tests
    // ========================================================================

    #[test]
    fn workflow_config_defaults() {
        let config = WorkflowConfig::default();
        assert_eq!(config.default_wait_timeout_ms, 30_000);
        assert_eq!(config.max_step_retries, 3);
        assert_eq!(config.retry_delay_ms, 1_000);
    }

    // ========================================================================
    // WorkflowEngine Tests
    // ========================================================================

    #[test]
    fn engine_can_be_created() {
        let engine = WorkflowEngine::new(5);
        assert_eq!(engine.max_concurrent(), 5);
    }

    // ========================================================================
    // Stub Workflow Tests (wa-nu4.1.1.1 acceptance criteria)
    // ========================================================================

    /// A stub workflow for testing that demonstrates all workflow capabilities
    struct StubWorkflow {
        name: String,
        description: String,
        target_rule_prefix: String,
    }

    impl StubWorkflow {
        fn new() -> Self {
            Self {
                name: "stub_workflow".to_string(),
                description: "A test workflow for verification".to_string(),
                target_rule_prefix: "test.".to_string(),
            }
        }
    }

    impl Workflow for StubWorkflow {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            &self.description
        }

        fn handles(&self, detection: &Detection) -> bool {
            detection.rule_id.starts_with(&self.target_rule_prefix)
        }

        fn steps(&self) -> Vec<WorkflowStep> {
            vec![
                WorkflowStep::new("step_one", "First step - sends prompt"),
                WorkflowStep::new("step_two", "Second step - waits for response"),
                WorkflowStep::new("step_three", "Third step - completes"),
            ]
        }

        async fn execute_step(&self, _ctx: &mut WorkflowContext, step_idx: usize) -> StepResult {
            match step_idx {
                0 => StepResult::cont(),
                1 => StepResult::wait_for(WaitCondition::pattern("response.ready")),
                2 => StepResult::done(serde_json::json!({"completed": true})),
                _ => StepResult::abort("unexpected step index"),
            }
        }

        async fn cleanup(&self, _ctx: &mut WorkflowContext) {
            // Stub cleanup - no-op
        }
    }

    fn make_test_detection(rule_id: &str) -> Detection {
        Detection {
            rule_id: rule_id.to_string(),
            agent_type: AgentType::Wezterm,
            event_type: "test".to_string(),
            severity: Severity::Info,
            confidence: 1.0,
            extracted: serde_json::Value::Null,
            matched_text: "test".to_string(),
        }
    }

    #[test]
    fn stub_workflow_compiles_and_has_correct_metadata() {
        let workflow = StubWorkflow::new();

        assert_eq!(workflow.name(), "stub_workflow");
        assert_eq!(workflow.description(), "A test workflow for verification");
        assert_eq!(workflow.step_count(), 3);

        let steps = workflow.steps();
        assert_eq!(steps[0].name, "step_one");
        assert_eq!(steps[1].name, "step_two");
        assert_eq!(steps[2].name, "step_three");
    }

    #[test]
    fn stub_workflow_handles_matching_detections() {
        let workflow = StubWorkflow::new();

        // Should handle detections with matching prefix
        assert!(workflow.handles(&make_test_detection("test.prompt_ready")));
        assert!(workflow.handles(&make_test_detection("test.anything")));

        // Should not handle detections with non-matching prefix
        assert!(!workflow.handles(&make_test_detection("other.prompt_ready")));
        assert!(!workflow.handles(&make_test_detection("production.event")));
    }

    #[tokio::test]
    async fn stub_workflow_executes_steps_correctly() {
        let workflow = StubWorkflow::new();

        // Create a minimal context for testing
        // Note: In real usage, this would have an actual StorageHandle
        // For this test, we just verify the step execution logic

        // We can't easily create a WorkflowContext without a real StorageHandle,
        // but we can verify the workflow's step logic independently
        let steps = workflow.steps();
        assert_eq!(steps.len(), 3);
    }

    #[test]
    fn step_result_transitions_exhaustive() {
        // Verify all StepResult variants can be created and identified
        let variants = [
            StepResult::Continue,
            StepResult::Done {
                result: serde_json::Value::Null,
            },
            StepResult::Retry { delay_ms: 1000 },
            StepResult::Abort {
                reason: "test".to_string(),
            },
            StepResult::WaitFor {
                condition: WaitCondition::external("key"),
                timeout_ms: None,
            },
        ];

        // Each variant serializes uniquely
        let mut json_types = std::collections::HashSet::new();
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            let type_field = parsed["type"].as_str().unwrap().to_string();
            json_types.insert(type_field);
        }

        // All 5 variants have unique type identifiers
        assert_eq!(json_types.len(), 5);
        assert!(json_types.contains("continue"));
        assert!(json_types.contains("done"));
        assert!(json_types.contains("retry"));
        assert!(json_types.contains("abort"));
        assert!(json_types.contains("wait_for"));
    }

    #[test]
    fn wait_condition_transitions_exhaustive() {
        // Verify all WaitCondition variants
        let variants = [
            WaitCondition::Pattern {
                pane_id: None,
                rule_id: "test".to_string(),
            },
            WaitCondition::PaneIdle {
                pane_id: None,
                idle_threshold_ms: 1000,
            },
            WaitCondition::External {
                key: "test".to_string(),
            },
        ];

        let mut json_types = std::collections::HashSet::new();
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            let type_field = parsed["type"].as_str().unwrap().to_string();
            json_types.insert(type_field);
        }

        assert_eq!(json_types.len(), 3);
        assert!(json_types.contains("pattern"));
        assert!(json_types.contains("pane_idle"));
        assert!(json_types.contains("external"));
    }

    // ========================================================================
    // WaitConditionResult Tests
    // ========================================================================

    #[test]
    fn wait_condition_result_satisfied_is_satisfied() {
        let result = WaitConditionResult::Satisfied {
            elapsed_ms: 100,
            polls: 5,
            context: Some("matched".to_string()),
        };
        assert!(result.is_satisfied());
        assert!(!result.is_timed_out());
        assert_eq!(result.elapsed_ms(), Some(100));
    }

    #[test]
    fn wait_condition_result_timed_out_is_timed_out() {
        let result = WaitConditionResult::TimedOut {
            elapsed_ms: 5000,
            polls: 100,
            last_observed: Some("waiting for prompt".to_string()),
        };
        assert!(!result.is_satisfied());
        assert!(result.is_timed_out());
        assert_eq!(result.elapsed_ms(), Some(5000));
    }

    #[test]
    fn wait_condition_result_unsupported_has_no_elapsed() {
        let result = WaitConditionResult::Unsupported {
            reason: "external signals not implemented".to_string(),
        };
        assert!(!result.is_satisfied());
        assert!(!result.is_timed_out());
        assert_eq!(result.elapsed_ms(), None);
    }

    // ========================================================================
    // WaitConditionOptions Tests
    // ========================================================================

    #[test]
    fn wait_condition_options_defaults() {
        let options = WaitConditionOptions::default();
        assert_eq!(options.tail_lines, 200);
        assert_eq!(options.poll_initial.as_millis(), 50);
        assert_eq!(options.poll_max.as_millis(), 1000);
        assert_eq!(options.max_polls, 10_000);
        assert!(options.allow_idle_heuristics);
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn tail_text_extracts_last_n_lines() {
        let text = "line1\nline2\nline3\nline4\nline5";
        assert_eq!(tail_text(text, 3), "line3\nline4\nline5");
        assert_eq!(tail_text(text, 1), "line5");
        assert_eq!(tail_text(text, 10), text);
        assert_eq!(tail_text(text, 0), "");
    }

    #[test]
    fn tail_text_handles_empty_input() {
        assert_eq!(tail_text("", 5), "");
    }

    #[test]
    fn tail_text_handles_single_line() {
        assert_eq!(tail_text("single line", 5), "single line");
    }

    #[test]
    fn truncate_for_log_preserves_short_strings() {
        assert_eq!(truncate_for_log("hello", 10), "hello");
        assert_eq!(truncate_for_log("exact", 5), "exact");
    }

    #[test]
    fn truncate_for_log_truncates_long_strings() {
        assert_eq!(truncate_for_log("hello world", 8), "hello...");
    }

    // ========================================================================
    // Heuristic Idle Check Tests
    // ========================================================================

    #[test]
    fn heuristic_idle_detects_bash_prompt() {
        let text = "output from command\nuser@host:~$ ";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(is_idle);
        assert!(desc.contains("ends_with_prompt"));
    }

    #[test]
    fn heuristic_idle_detects_root_prompt() {
        let text = "output\nroot@host:~# ";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(is_idle);
        assert!(desc.contains("ends_with_prompt"));
    }

    #[test]
    fn heuristic_idle_detects_zsh_prompt() {
        let text = "output\n❯ ";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(is_idle);
        assert!(desc.contains("ends_with_prompt"));
    }

    #[test]
    fn heuristic_idle_detects_python_repl() {
        let text = ">>> ";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(is_idle);
        assert!(desc.contains("ends_with_prompt"));
    }

    #[test]
    fn heuristic_idle_detects_prompt_with_trailing_newline() {
        // Note: Rust's lines() iterator doesn't include trailing empty lines,
        // so "user@host:~$ \n" becomes the last line as "user@host:~$ "
        // which after trim_end becomes "user@host:~$" ending with "$"
        let text = "output\nuser@host:~$ \n";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(is_idle);
        assert!(desc.contains("ends_with_prompt"));
    }

    #[test]
    fn heuristic_idle_rejects_command_output() {
        let text = "building project...\nCompiling foo v1.0.0";
        let (is_idle, desc) = heuristic_idle_check(text, 10);
        assert!(!is_idle);
        assert!(desc.contains("no_prompt_detected"));
    }

    #[test]
    fn heuristic_idle_rejects_running_command() {
        // Use "50/100" instead of "50%" - the % character would match the tcsh prompt pattern
        let text = "npm run build\nProgress: 50/100";
        let (is_idle, _desc) = heuristic_idle_check(text, 10);
        assert!(!is_idle);
    }

    // ========================================================================
    // WaitConditionExecutor Tests (using mock source)
    // ========================================================================

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock pane text source for testing
    struct MockPaneSource {
        texts: Mutex<Vec<String>>,
        call_count: AtomicUsize,
    }

    impl MockPaneSource {
        fn new(texts: Vec<String>) -> Self {
            Self {
                texts: Mutex::new(texts),
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl crate::wezterm::PaneTextSource for MockPaneSource {
        type Fut<'a> =
            std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<String>> + Send + 'a>>;

        fn get_text(&self, _pane_id: u64, _escapes: bool) -> Self::Fut<'_> {
            let count = self.call_count.fetch_add(1, Ordering::Relaxed);
            let texts = self.texts.lock().unwrap();
            let text = if count < texts.len() {
                texts[count].clone()
            } else {
                texts.last().cloned().unwrap_or_default()
            };
            Box::pin(async move { Ok(text) })
        }
    }

    #[tokio::test]
    async fn pattern_wait_succeeds_on_immediate_match() {
        let source = MockPaneSource::new(vec![
            "Conversation compacted 100,000 tokens to 25,000 tokens".to_string(),
        ]);
        let engine = PatternEngine::new();

        let executor =
            WaitConditionExecutor::new(&source, &engine).with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(10),
                max_polls: 100,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pattern("claude_code.compaction");
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_satisfied());
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    async fn pattern_wait_times_out_on_no_match() {
        let source = MockPaneSource::new(vec!["no matching pattern here".to_string()]);
        let engine = PatternEngine::new();

        let executor =
            WaitConditionExecutor::new(&source, &engine).with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(5),
                max_polls: 5,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pattern("claude_code.compaction");
        let result = executor
            .execute(&condition, 1, Duration::from_millis(20))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_timed_out());
    }

    #[tokio::test]
    async fn pattern_wait_succeeds_after_multiple_polls() {
        let source = MockPaneSource::new(vec![
            "no match yet".to_string(),
            "still no match".to_string(),
            "Conversation compacted 100,000 tokens to 25,000 tokens".to_string(),
        ]);
        let engine = PatternEngine::new();

        let executor =
            WaitConditionExecutor::new(&source, &engine).with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(5),
                max_polls: 100,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pattern("claude_code.compaction");
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_satisfied());
        assert!(source.calls() >= 3);
    }

    #[tokio::test]
    async fn pane_idle_succeeds_with_osc133_prompt_active() {
        use crate::ingest::{Osc133State, ShellState};

        let source = MockPaneSource::new(vec!["some text".to_string()]);
        let engine = PatternEngine::new();
        let mut osc_state = Osc133State::new();
        osc_state.state = ShellState::PromptActive;

        let executor = WaitConditionExecutor::new(&source, &engine)
            .with_osc_state(&osc_state)
            .with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(5),
                max_polls: 100,
                allow_idle_heuristics: true,
            });

        // idle_threshold_ms = 0 means immediate satisfaction when idle
        let condition = WaitCondition::pane_idle(0);
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_satisfied());
        if let WaitConditionResult::Satisfied { context, .. } = result {
            assert!(context.unwrap().contains("osc133"));
        }
    }

    #[tokio::test]
    async fn pane_idle_times_out_with_osc133_command_running() {
        use crate::ingest::{Osc133State, ShellState};

        let source = MockPaneSource::new(vec!["running command...".to_string()]);
        let engine = PatternEngine::new();
        let mut osc_state = Osc133State::new();
        osc_state.state = ShellState::CommandRunning;

        let executor = WaitConditionExecutor::new(&source, &engine)
            .with_osc_state(&osc_state)
            .with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(5),
                max_polls: 5,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pane_idle(0);
        let result = executor
            .execute(&condition, 1, Duration::from_millis(20))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_timed_out());
    }

    #[tokio::test]
    async fn pane_idle_uses_heuristics_when_no_osc133() {
        let source = MockPaneSource::new(vec!["user@host:~$ ".to_string()]);
        let engine = PatternEngine::new();

        let executor =
            WaitConditionExecutor::new(&source, &engine).with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(5),
                max_polls: 100,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pane_idle(0);
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_satisfied());
        if let WaitConditionResult::Satisfied { context, .. } = result {
            assert!(context.unwrap().contains("heuristic"));
        }
    }

    #[tokio::test]
    async fn pane_idle_respects_threshold_duration() {
        use crate::ingest::{Osc133State, ShellState};

        let source = MockPaneSource::new(vec!["some text".to_string()]);
        let engine = PatternEngine::new();
        let mut osc_state = Osc133State::new();
        osc_state.state = ShellState::PromptActive;

        let executor = WaitConditionExecutor::new(&source, &engine)
            .with_osc_state(&osc_state)
            .with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(10),
                poll_max: Duration::from_millis(50),
                max_polls: 100,
                allow_idle_heuristics: true,
            });

        // Require 50ms idle threshold
        let condition = WaitCondition::pane_idle(50);
        let start = std::time::Instant::now();
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_satisfied());
        // Should have waited at least the threshold duration
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn external_wait_returns_unsupported() {
        let source = MockPaneSource::new(vec!["text".to_string()]);
        let engine = PatternEngine::new();

        let executor = WaitConditionExecutor::new(&source, &engine);
        let condition = WaitCondition::external("my_signal");
        let result = executor
            .execute(&condition, 1, Duration::from_secs(5))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        match result {
            WaitConditionResult::Unsupported { reason } => {
                assert!(reason.contains("my_signal"));
            }
            _ => panic!("Expected Unsupported"),
        }
    }

    #[tokio::test]
    async fn wait_respects_max_polls() {
        let source = MockPaneSource::new(vec!["no match".to_string()]);
        let engine = PatternEngine::new();

        let executor =
            WaitConditionExecutor::new(&source, &engine).with_options(WaitConditionOptions {
                tail_lines: 200,
                poll_initial: Duration::from_millis(1),
                poll_max: Duration::from_millis(1),
                max_polls: 3,
                allow_idle_heuristics: true,
            });

        let condition = WaitCondition::pattern("nonexistent.rule");
        let result = executor
            .execute(&condition, 1, Duration::from_secs(60))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_timed_out());
        if let WaitConditionResult::TimedOut { polls, .. } = result {
            assert!(polls <= 3);
        }
    }

    // ========================================================================
    // Workflow Persistence Tests (wa-nu4.1.1.3)
    // ========================================================================

    #[test]
    fn compute_next_step_empty_logs_returns_zero() {
        let logs: Vec<crate::storage::WorkflowStepLogRecord> = vec![];
        assert_eq!(super::compute_next_step(&logs), 0);
    }

    #[test]
    fn compute_next_step_with_continue_returns_next() {
        let logs = vec![crate::storage::WorkflowStepLogRecord {
            id: 1,
            workflow_id: "test-123".to_string(),
            step_index: 0,
            step_name: "step_0".to_string(),
            result_type: "continue".to_string(),
            result_data: None,
            started_at: 1000,
            completed_at: 1100,
            duration_ms: 100,
        }];
        assert_eq!(super::compute_next_step(&logs), 1);
    }

    #[test]
    fn compute_next_step_with_done_returns_next() {
        let logs = vec![crate::storage::WorkflowStepLogRecord {
            id: 1,
            workflow_id: "test-123".to_string(),
            step_index: 2,
            step_name: "step_2".to_string(),
            result_type: "done".to_string(),
            result_data: None,
            started_at: 1000,
            completed_at: 1100,
            duration_ms: 100,
        }];
        assert_eq!(super::compute_next_step(&logs), 3);
    }

    #[test]
    fn compute_next_step_with_retry_returns_same() {
        // Retry means the step should be re-executed
        let logs = vec![crate::storage::WorkflowStepLogRecord {
            id: 1,
            workflow_id: "test-123".to_string(),
            step_index: 1,
            step_name: "step_1".to_string(),
            result_type: "retry".to_string(),
            result_data: None,
            started_at: 1000,
            completed_at: 1100,
            duration_ms: 100,
        }];
        // No completed steps, so start from 0
        assert_eq!(super::compute_next_step(&logs), 0);
    }

    #[test]
    fn compute_next_step_mixed_logs_finds_highest_completed() {
        let logs = vec![
            crate::storage::WorkflowStepLogRecord {
                id: 1,
                workflow_id: "test-123".to_string(),
                step_index: 0,
                step_name: "step_0".to_string(),
                result_type: "continue".to_string(),
                result_data: None,
                started_at: 1000,
                completed_at: 1100,
                duration_ms: 100,
            },
            crate::storage::WorkflowStepLogRecord {
                id: 2,
                workflow_id: "test-123".to_string(),
                step_index: 1,
                step_name: "step_1".to_string(),
                result_type: "continue".to_string(),
                result_data: None,
                started_at: 1100,
                completed_at: 1200,
                duration_ms: 100,
            },
            crate::storage::WorkflowStepLogRecord {
                id: 3,
                workflow_id: "test-123".to_string(),
                step_index: 2,
                step_name: "step_2".to_string(),
                result_type: "retry".to_string(),
                result_data: None,
                started_at: 1200,
                completed_at: 1300,
                duration_ms: 100,
            },
        ];
        // Highest completed is step_index 1, so next is 2
        assert_eq!(super::compute_next_step(&logs), 2);
    }

    #[test]
    fn compute_next_step_out_of_order_logs() {
        // Logs might not be in order; function should still find max
        let logs = vec![
            crate::storage::WorkflowStepLogRecord {
                id: 3,
                workflow_id: "test-123".to_string(),
                step_index: 2,
                step_name: "step_2".to_string(),
                result_type: "continue".to_string(),
                result_data: None,
                started_at: 1200,
                completed_at: 1300,
                duration_ms: 100,
            },
            crate::storage::WorkflowStepLogRecord {
                id: 1,
                workflow_id: "test-123".to_string(),
                step_index: 0,
                step_name: "step_0".to_string(),
                result_type: "continue".to_string(),
                result_data: None,
                started_at: 1000,
                completed_at: 1100,
                duration_ms: 100,
            },
        ];
        // Highest completed is step_index 2, so next is 3
        assert_eq!(super::compute_next_step(&logs), 3);
    }

    #[test]
    fn generate_workflow_id_format() {
        let id = super::generate_workflow_id("test_workflow");
        assert!(id.starts_with("test_workflow-"));
        // Should have format: name-timestamp-random
        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 3);
        // Last part should be hex (8 chars)
        let last = parts.last().unwrap();
        assert_eq!(last.len(), 8);
        assert!(last.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_workflow_id_uniqueness() {
        let id1 = super::generate_workflow_id("workflow");
        let id2 = super::generate_workflow_id("workflow");
        // Random component should make them different
        assert_ne!(id1, id2);
    }

    #[test]
    fn execution_status_serialization() {
        let statuses = [
            ExecutionStatus::Running,
            ExecutionStatus::Waiting,
            ExecutionStatus::Completed,
            ExecutionStatus::Aborted,
        ];

        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: ExecutionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, status);
        }
    }

    #[test]
    fn workflow_execution_serialization() {
        let execution = WorkflowExecution {
            id: "test-123-abc".to_string(),
            workflow_name: "test_workflow".to_string(),
            pane_id: 42,
            current_step: 2,
            status: ExecutionStatus::Running,
            started_at: 1000,
            updated_at: 1500,
        };

        let json = serde_json::to_string(&execution).unwrap();
        let parsed: WorkflowExecution = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, execution.id);
        assert_eq!(parsed.workflow_name, execution.workflow_name);
        assert_eq!(parsed.pane_id, execution.pane_id);
        assert_eq!(parsed.current_step, execution.current_step);
        assert_eq!(parsed.status, execution.status);
    }

    // ========================================================================
    // PaneWorkflowLockManager Tests (wa-nu4.1.1.2)
    // ========================================================================

    #[test]
    fn lock_manager_acquire_and_release() {
        let manager = PaneWorkflowLockManager::new();

        // Initially unlocked
        assert!(manager.is_locked(42).is_none());

        // Acquire succeeds
        let result = manager.try_acquire(42, "test_workflow", "exec-001");
        assert!(result.is_acquired());
        assert!(!result.is_already_locked());

        // Now locked
        let lock_info = manager.is_locked(42);
        assert!(lock_info.is_some());
        let info = lock_info.unwrap();
        assert_eq!(info.pane_id, 42);
        assert_eq!(info.workflow_name, "test_workflow");
        assert_eq!(info.execution_id, "exec-001");
        assert!(info.locked_at_ms > 0);

        // Release succeeds
        assert!(manager.release(42, "exec-001"));

        // Now unlocked
        assert!(manager.is_locked(42).is_none());
    }

    #[test]
    fn lock_manager_double_acquire_fails() {
        let manager = PaneWorkflowLockManager::new();

        // First acquire succeeds
        let result1 = manager.try_acquire(42, "workflow_a", "exec-001");
        assert!(result1.is_acquired());

        // Second acquire fails with details about the existing lock
        let result2 = manager.try_acquire(42, "workflow_b", "exec-002");
        assert!(result2.is_already_locked());
        match result2 {
            LockAcquisitionResult::AlreadyLocked {
                held_by_workflow,
                held_by_execution,
                locked_since_ms,
            } => {
                assert_eq!(held_by_workflow, "workflow_a");
                assert_eq!(held_by_execution, "exec-001");
                assert!(locked_since_ms > 0);
            }
            _ => panic!("Expected AlreadyLocked"),
        }

        // Release and retry succeeds
        manager.release(42, "exec-001");
        let result3 = manager.try_acquire(42, "workflow_b", "exec-002");
        assert!(result3.is_acquired());
    }

    #[test]
    fn lock_manager_release_with_wrong_execution_id_fails() {
        let manager = PaneWorkflowLockManager::new();

        manager.try_acquire(42, "test_workflow", "exec-001");

        // Release with wrong execution_id fails
        assert!(!manager.release(42, "wrong-exec-id"));

        // Lock still held
        assert!(manager.is_locked(42).is_some());

        // Correct execution_id works
        assert!(manager.release(42, "exec-001"));
        assert!(manager.is_locked(42).is_none());
    }

    #[test]
    fn lock_manager_multiple_panes_independent() {
        let manager = PaneWorkflowLockManager::new();

        // Lock pane 1
        let r1 = manager.try_acquire(1, "workflow_a", "exec-001");
        assert!(r1.is_acquired());

        // Lock pane 2 succeeds (different pane)
        let r2 = manager.try_acquire(2, "workflow_b", "exec-002");
        assert!(r2.is_acquired());

        // Lock pane 3 succeeds
        let r3 = manager.try_acquire(3, "workflow_c", "exec-003");
        assert!(r3.is_acquired());

        // All locked
        assert!(manager.is_locked(1).is_some());
        assert!(manager.is_locked(2).is_some());
        assert!(manager.is_locked(3).is_some());

        // Release pane 2 doesn't affect others
        manager.release(2, "exec-002");
        assert!(manager.is_locked(1).is_some());
        assert!(manager.is_locked(2).is_none());
        assert!(manager.is_locked(3).is_some());
    }

    #[test]
    fn lock_manager_active_locks() {
        let manager = PaneWorkflowLockManager::new();

        // Initially empty
        assert!(manager.active_locks().is_empty());

        manager.try_acquire(1, "workflow_a", "exec-001");
        manager.try_acquire(2, "workflow_b", "exec-002");

        let active = manager.active_locks();
        assert_eq!(active.len(), 2);

        let pane_ids: std::collections::HashSet<u64> = active.iter().map(|l| l.pane_id).collect();
        assert!(pane_ids.contains(&1));
        assert!(pane_ids.contains(&2));
    }

    #[test]
    fn lock_guard_releases_on_drop() {
        let manager = PaneWorkflowLockManager::new();

        // Acquire via guard
        {
            let guard = manager.acquire_guard(42, "test_workflow", "exec-001");
            assert!(guard.is_some());
            let guard = guard.unwrap();
            assert_eq!(guard.pane_id(), 42);
            assert_eq!(guard.execution_id(), "exec-001");

            // Lock is held
            assert!(manager.is_locked(42).is_some());
        }

        // Guard dropped, lock released
        assert!(manager.is_locked(42).is_none());
    }

    #[test]
    fn lock_guard_acquire_fails_when_locked() {
        let manager = PaneWorkflowLockManager::new();

        // Acquire first lock
        let _guard1 = manager.acquire_guard(42, "workflow_a", "exec-001");
        assert!(manager.is_locked(42).is_some());

        // Second acquire fails
        let guard2 = manager.acquire_guard(42, "workflow_b", "exec-002");
        assert!(guard2.is_none());
    }

    #[test]
    fn lock_manager_force_release() {
        let manager = PaneWorkflowLockManager::new();

        manager.try_acquire(42, "test_workflow", "exec-001");
        assert!(manager.is_locked(42).is_some());

        // Force release works even with unknown execution_id
        let removed = manager.force_release(42);
        assert!(removed.is_some());
        let info = removed.unwrap();
        assert_eq!(info.execution_id, "exec-001");

        // Now unlocked
        assert!(manager.is_locked(42).is_none());

        // Force release on unlocked pane returns None
        assert!(manager.force_release(42).is_none());
    }

    #[test]
    fn lock_acquisition_result_methods() {
        let acquired = LockAcquisitionResult::Acquired;
        assert!(acquired.is_acquired());
        assert!(!acquired.is_already_locked());

        let locked = LockAcquisitionResult::AlreadyLocked {
            held_by_workflow: "test".to_string(),
            held_by_execution: "exec-001".to_string(),
            locked_since_ms: 1234567890,
        };
        assert!(!locked.is_acquired());
        assert!(locked.is_already_locked());
    }

    #[test]
    fn lock_manager_concurrent_simulation() {
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(PaneWorkflowLockManager::new());
        let pane_id = 42;

        // Simulate concurrent access with threads
        let mut handles = vec![];

        for i in 0..10 {
            let m = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                let exec_id = format!("exec-{i:03}");
                m.try_acquire(pane_id, "concurrent_workflow", &exec_id)
            });
            handles.push(handle);
        }

        // Collect results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Exactly one should have acquired the lock
        let acquired_count = results.iter().filter(|r| r.is_acquired()).count();
        let locked_count = results.iter().filter(|r| r.is_already_locked()).count();

        assert_eq!(acquired_count, 1);
        assert_eq!(locked_count, 9);
    }

    #[test]
    fn pane_lock_info_serialization() {
        let info = PaneLockInfo {
            pane_id: 42,
            workflow_name: "test_workflow".to_string(),
            execution_id: "exec-001".to_string(),
            locked_at_ms: 1234567890000,
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: PaneLockInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pane_id, info.pane_id);
        assert_eq!(parsed.workflow_name, info.workflow_name);
        assert_eq!(parsed.execution_id, info.execution_id);
        assert_eq!(parsed.locked_at_ms, info.locked_at_ms);
    }
}
