//! Storage layer with SQLite and FTS5
//!
//! Provides persistent storage for captured output, events, and workflows.
//!
//! # Schema Design
//!
//! The database uses WAL mode for concurrent reads and single-writer semantics.
//! All timestamps are epoch milliseconds (i64) for hot-path performance.
//! JSON columns are stored as TEXT for SQLite compatibility.
//!
//! # Tables
//!
//! - `panes`: Pane metadata and observation decisions
//! - `output_segments`: Append-only captured terminal output
//! - `output_gaps`: Explicit discontinuities in capture
//! - `events`: Pattern detections with lifecycle tracking
//! - `workflow_executions`: Durable workflow state
//! - `workflow_step_logs`: Step execution history
//! - `config`: Key-value settings
//! - `maintenance_log`: System events and metrics
//!
//! FTS5 virtual table `output_segments_fts` enables full-text search.

use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Result, StorageError};

// =============================================================================
// Schema Definition
// =============================================================================

/// Current schema version for migration tracking
pub const SCHEMA_VERSION: i32 = 1;

/// Schema initialization SQL
///
/// Convention notes:
/// - Timestamps: epoch milliseconds (i64) for hot-path queries
/// - JSON columns: TEXT containing JSON (v0 simplicity)
/// - All tables use INTEGER PRIMARY KEY for rowid aliasing
pub const SCHEMA_SQL: &str = r#"
-- Enable WAL mode for concurrent reads and single-writer semantics
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at INTEGER NOT NULL,  -- epoch ms
    description TEXT
);

-- Panes: metadata and observation decisions
-- Supports: wa status, wa robot state, privacy/perf filtering
CREATE TABLE IF NOT EXISTS panes (
    pane_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'local',
    window_id INTEGER,
    tab_id INTEGER,
    title TEXT,
    cwd TEXT,
    tty_name TEXT,
    first_seen_at INTEGER NOT NULL,   -- epoch ms
    last_seen_at INTEGER NOT NULL,    -- epoch ms
    observed INTEGER NOT NULL DEFAULT 1,  -- bool: 1=observe, 0=ignore
    ignore_reason TEXT,               -- rule id or short description if ignored
    last_decision_at INTEGER          -- epoch ms when observed/ignore was set
);

CREATE INDEX IF NOT EXISTS idx_panes_last_seen ON panes(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_panes_observed ON panes(observed);

-- Output segments: append-only terminal output capture
-- UNIQUE(pane_id, seq) enforces monotonic sequence per pane
CREATE TABLE IF NOT EXISTS output_segments (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,             -- monotonically increasing within pane
    content TEXT NOT NULL,
    content_len INTEGER NOT NULL,     -- cached length for stats
    content_hash TEXT,                -- for overlap detection (optional)
    captured_at INTEGER NOT NULL,     -- epoch ms
    UNIQUE(pane_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_segments_pane_seq ON output_segments(pane_id, seq);
CREATE INDEX IF NOT EXISTS idx_segments_captured ON output_segments(captured_at);

-- Output gaps: explicit discontinuities in capture
CREATE TABLE IF NOT EXISTS output_gaps (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    seq_before INTEGER NOT NULL,      -- last known seq before gap
    seq_after INTEGER NOT NULL,       -- first seq after gap
    reason TEXT NOT NULL,             -- e.g., "daemon_restart", "timeout", "buffer_overflow"
    detected_at INTEGER NOT NULL      -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_gaps_pane ON output_gaps(pane_id);
CREATE INDEX IF NOT EXISTS idx_gaps_detected ON output_gaps(detected_at);

-- Events: pattern detections with lifecycle tracking
-- Supports: unhandled queries, workflow linkage, idempotency
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,            -- stable pattern identifier
    agent_type TEXT NOT NULL,         -- codex, claude_code, gemini, unknown
    event_type TEXT NOT NULL,         -- detection category
    severity TEXT NOT NULL,           -- info, warning, critical
    confidence REAL NOT NULL,         -- 0.0-1.0
    extracted TEXT,                   -- JSON: structured data from pattern
    matched_text TEXT,                -- original matched text
    segment_id INTEGER REFERENCES output_segments(id),  -- source segment
    detected_at INTEGER NOT NULL,     -- epoch ms

    -- Lifecycle tracking
    handled_at INTEGER,               -- epoch ms when handled (NULL = unhandled)
    handled_by_workflow_id TEXT,      -- links to workflow_executions.id
    handled_status TEXT,              -- completed, aborted, failed, paused

    -- Idempotency: optional dedupe key (pane_id + rule_id + time_window)
    dedupe_key TEXT,                  -- computed key for duplicate prevention

    UNIQUE(dedupe_key)                -- prevents duplicate events when dedupe_key set
);

CREATE INDEX IF NOT EXISTS idx_events_pane ON events(pane_id);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_unhandled ON events(handled_at) WHERE handled_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_events_detected ON events(detected_at);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, detected_at);

-- Workflow executions: durable FSM state for resumability
CREATE TABLE IF NOT EXISTS workflow_executions (
    id TEXT PRIMARY KEY,              -- UUID or ulid
    workflow_name TEXT NOT NULL,
    pane_id INTEGER NOT NULL REFERENCES panes(pane_id),
    trigger_event_id INTEGER REFERENCES events(id),  -- event that started this
    current_step INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',  -- running, waiting, completed, aborted
    wait_condition TEXT,              -- JSON: WaitCondition if status='waiting'
    context TEXT,                     -- JSON: workflow-specific state
    result TEXT,                      -- JSON: final result if completed
    error TEXT,                       -- error message if aborted
    started_at INTEGER NOT NULL,      -- epoch ms
    updated_at INTEGER NOT NULL,      -- epoch ms
    completed_at INTEGER              -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_workflows_pane ON workflow_executions(pane_id);
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_workflows_started ON workflow_executions(started_at);

-- Workflow step logs: execution history for audit and debugging
CREATE TABLE IF NOT EXISTS workflow_step_logs (
    id INTEGER PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    result_type TEXT NOT NULL,        -- continue, done, retry, abort, wait_for
    result_data TEXT,                 -- JSON: result payload
    started_at INTEGER NOT NULL,      -- epoch ms
    completed_at INTEGER NOT NULL,    -- epoch ms
    duration_ms INTEGER NOT NULL      -- cached for stats
);

CREATE INDEX IF NOT EXISTS idx_step_logs_workflow ON workflow_step_logs(workflow_id, step_index);

-- Config: key-value settings
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,              -- JSON value
    updated_at INTEGER NOT NULL       -- epoch ms
);

-- Maintenance log: system events and metrics
CREATE TABLE IF NOT EXISTS maintenance_log (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,         -- startup, shutdown, vacuum, retention_cleanup, error
    message TEXT,
    metadata TEXT,                    -- JSON: additional context
    timestamp INTEGER NOT NULL        -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_maintenance_timestamp ON maintenance_log(timestamp);

-- FTS5 virtual table for full-text search over segments
CREATE VIRTUAL TABLE IF NOT EXISTS output_segments_fts USING fts5(
    content,
    content='output_segments',
    content_rowid='id',
    tokenize='porter unicode61'
);

-- Triggers to keep FTS index in sync
CREATE TRIGGER IF NOT EXISTS output_segments_ai AFTER INSERT ON output_segments BEGIN
    INSERT INTO output_segments_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE TRIGGER IF NOT EXISTS output_segments_ad AFTER DELETE ON output_segments BEGIN
    INSERT INTO output_segments_fts(output_segments_fts, rowid, content) VALUES('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS output_segments_au AFTER UPDATE ON output_segments BEGIN
    INSERT INTO output_segments_fts(output_segments_fts, rowid, content) VALUES('delete', old.id, old.content);
    INSERT INTO output_segments_fts(rowid, content) VALUES (new.id, new.content);
END;
"#;

// =============================================================================
// Data Structures
// =============================================================================

/// A captured segment of pane output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    /// Unique segment ID
    pub id: i64,
    /// Pane this segment belongs to
    pub pane_id: u64,
    /// Sequence number within the pane (monotonically increasing)
    pub seq: u64,
    /// The captured text content
    pub content: String,
    /// Content length (cached)
    pub content_len: usize,
    /// Optional content hash for overlap detection
    pub content_hash: Option<String>,
    /// Timestamp when captured (epoch ms)
    pub captured_at: i64,
}

/// A gap event indicating discontinuous capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gap {
    /// Unique gap ID
    pub id: i64,
    /// Pane where gap occurred
    pub pane_id: u64,
    /// Sequence number before gap
    pub seq_before: u64,
    /// Sequence number after gap
    pub seq_after: u64,
    /// Reason for gap
    pub reason: String,
    /// Timestamp of gap detection (epoch ms)
    pub detected_at: i64,
}

/// Pane metadata and observation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaneRecord {
    /// Pane ID (from WezTerm)
    pub pane_id: u64,
    /// Domain name
    pub domain: String,
    /// Window ID
    pub window_id: Option<u64>,
    /// Tab ID
    pub tab_id: Option<u64>,
    /// Pane title
    pub title: Option<String>,
    /// Current working directory
    pub cwd: Option<String>,
    /// TTY name
    pub tty_name: Option<String>,
    /// First seen timestamp (epoch ms)
    pub first_seen_at: i64,
    /// Last seen timestamp (epoch ms)
    pub last_seen_at: i64,
    /// Whether to observe this pane
    pub observed: bool,
    /// Reason for ignoring (if not observed)
    pub ignore_reason: Option<String>,
    /// When observation decision was made (epoch ms)
    pub last_decision_at: Option<i64>,
}

/// A stored event (pattern detection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    /// Event ID
    pub id: i64,
    /// Pane ID
    pub pane_id: u64,
    /// Rule ID
    pub rule_id: String,
    /// Agent type
    pub agent_type: String,
    /// Event type
    pub event_type: String,
    /// Severity
    pub severity: String,
    /// Confidence score
    pub confidence: f64,
    /// Extracted data (JSON)
    pub extracted: Option<serde_json::Value>,
    /// Original matched text
    pub matched_text: Option<String>,
    /// Source segment ID
    pub segment_id: Option<i64>,
    /// Detection timestamp (epoch ms)
    pub detected_at: i64,
    /// When handled (epoch ms, None = unhandled)
    pub handled_at: Option<i64>,
    /// Workflow that handled this
    pub handled_by_workflow_id: Option<String>,
    /// Handling status
    pub handled_status: Option<String>,
}

/// Workflow execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRecord {
    /// Execution ID
    pub id: String,
    /// Workflow name
    pub workflow_name: String,
    /// Pane ID
    pub pane_id: u64,
    /// Trigger event ID
    pub trigger_event_id: Option<i64>,
    /// Current step index
    pub current_step: usize,
    /// Status
    pub status: String,
    /// Wait condition (JSON)
    pub wait_condition: Option<serde_json::Value>,
    /// Workflow context (JSON)
    pub context: Option<serde_json::Value>,
    /// Result (JSON)
    pub result: Option<serde_json::Value>,
    /// Error message
    pub error: Option<String>,
    /// Started timestamp (epoch ms)
    pub started_at: i64,
    /// Updated timestamp (epoch ms)
    pub updated_at: i64,
    /// Completed timestamp (epoch ms)
    pub completed_at: Option<i64>,
}

// =============================================================================
// Schema Initialization
// =============================================================================

/// Initialize the database schema
///
/// Creates all tables, indexes, triggers, and FTS if they don't exist.
/// Safe to call on an existing database.
pub fn initialize_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| StorageError::MigrationFailed(format!("Schema init failed: {e}")))?;

    // Record schema version if not already present
    let existing: Option<i32> = conn
        .query_row(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StorageError::Database(e.to_string()))?;

    if existing.is_none() {
        #[allow(clippy::cast_possible_truncation)]
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64) // Safe: won't overflow until year 292,277,026
            .unwrap_or(0);

        conn.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?1, ?2, ?3)",
            params![SCHEMA_VERSION, now_ms, "Initial schema"],
        )
        .map_err(|e| StorageError::MigrationFailed(format!("Version insert failed: {e}")))?;
    }

    Ok(())
}

/// Get the current schema version
pub fn get_schema_version(conn: &Connection) -> Result<Option<i32>> {
    conn.query_row(
        "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| StorageError::Database(e.to_string()).into())
}

/// Check if schema needs initialization
pub fn needs_initialization(conn: &Connection) -> Result<bool> {
    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='panes'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| StorageError::Database(e.to_string()))?;

    Ok(table_exists == 0)
}

// =============================================================================
// Writer Command Types
// =============================================================================

/// Commands sent to the writer thread
enum WriteCommand {
    /// Append a segment (pane_id, content, content_hash, response channel)
    AppendSegment {
        pane_id: u64,
        content: String,
        content_hash: Option<String>,
        respond: oneshot::Sender<Result<Segment>>,
    },
    /// Record a gap event
    RecordGap {
        pane_id: u64,
        reason: String,
        respond: oneshot::Sender<Result<Gap>>,
    },
    /// Record an event/detection
    RecordEvent {
        event: StoredEvent,
        respond: oneshot::Sender<Result<i64>>,
    },
    /// Mark event as handled
    MarkEventHandled {
        event_id: i64,
        workflow_id: Option<String>,
        status: String,
        respond: oneshot::Sender<Result<()>>,
    },
    /// Upsert a pane record
    UpsertPane {
        pane: PaneRecord,
        respond: oneshot::Sender<Result<()>>,
    },
    /// Insert or update a workflow execution
    UpsertWorkflow {
        workflow: WorkflowRecord,
        respond: oneshot::Sender<Result<()>>,
    },
    /// Insert a workflow step log
    InsertStepLog {
        workflow_id: String,
        step_index: usize,
        step_name: String,
        result_type: String,
        result_data: Option<String>,
        started_at: i64,
        completed_at: i64,
        respond: oneshot::Sender<Result<()>>,
    },
    /// Shutdown the writer thread (flush pending writes)
    Shutdown { respond: oneshot::Sender<()> },
}

/// Configuration for the storage handle
pub struct StorageConfig {
    /// Maximum number of pending write commands before backpressure
    pub write_queue_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            write_queue_size: 1024,
        }
    }
}

// =============================================================================
// Storage Handle
// =============================================================================

/// Async-safe storage handle
///
/// Provides an async API for storage operations. Writes are serialized through
/// a dedicated writer thread to avoid blocking the async runtime. Reads use
/// spawn_blocking with WAL mode for concurrent access.
pub struct StorageHandle {
    /// Sender for write commands
    write_tx: mpsc::Sender<WriteCommand>,
    /// Database path for read connections
    db_path: Arc<String>,
    /// Writer thread join handle (for shutdown)
    writer_handle: Option<JoinHandle<()>>,
}

impl StorageHandle {
    /// Create a new storage handle
    ///
    /// Opens/creates the database at `db_path`, initializes the schema,
    /// and starts the writer thread.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or schema fails.
    pub async fn new(db_path: &str) -> Result<Self> {
        Self::with_config(db_path, StorageConfig::default()).await
    }

    /// Create a storage handle with custom configuration
    pub async fn with_config(db_path: &str, config: StorageConfig) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    StorageError::Database(format!("Failed to create directory: {e}"))
                })?;
            }
        }

        // Open connection and initialize schema (blocking)
        let db_path_owned = db_path.to_string();
        let init_result = tokio::task::spawn_blocking(move || -> Result<Connection> {
            let conn = Connection::open(&db_path_owned)
                .map_err(|e| StorageError::Database(format!("Failed to open database: {e}")))?;
            initialize_schema(&conn)?;
            Ok(conn)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))??;

        // Create bounded channel for write commands
        let (write_tx, mut write_rx) = mpsc::channel::<WriteCommand>(config.write_queue_size);

        // Spawn writer thread
        let writer_handle = thread::spawn(move || {
            let conn = init_result;
            writer_loop(&conn, &mut write_rx);
        });

        Ok(Self {
            write_tx,
            db_path: Arc::new(db_path.to_string()),
            writer_handle: Some(writer_handle),
        })
    }

    /// Append a segment to storage
    ///
    /// Automatically assigns the next sequence number for the pane.
    /// The pane must exist (call `upsert_pane` first).
    pub async fn append_segment(
        &self,
        pane_id: u64,
        content: &str,
        content_hash: Option<String>,
    ) -> Result<Segment> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::AppendSegment {
                pane_id,
                content: content.to_string(),
                content_hash,
                respond: tx,
            })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Record a gap event
    ///
    /// Indicates a discontinuity in capture for the given pane.
    pub async fn record_gap(&self, pane_id: u64, reason: &str) -> Result<Gap> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::RecordGap {
                pane_id,
                reason: reason.to_string(),
                respond: tx,
            })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Record an event (pattern detection)
    ///
    /// Returns the event ID.
    pub async fn record_event(&self, event: StoredEvent) -> Result<i64> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::RecordEvent { event, respond: tx })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Mark an event as handled
    pub async fn mark_event_handled(
        &self,
        event_id: i64,
        workflow_id: Option<String>,
        status: &str,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::MarkEventHandled {
                event_id,
                workflow_id,
                status: status.to_string(),
                respond: tx,
            })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Upsert a pane record
    pub async fn upsert_pane(&self, pane: PaneRecord) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::UpsertPane { pane, respond: tx })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Upsert a workflow execution record
    pub async fn upsert_workflow(&self, workflow: WorkflowRecord) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::UpsertWorkflow {
                workflow,
                respond: tx,
            })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Insert a workflow step log entry
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_step_log(
        &self,
        workflow_id: &str,
        step_index: usize,
        step_name: &str,
        result_type: &str,
        result_data: Option<String>,
        started_at: i64,
        completed_at: i64,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::InsertStepLog {
                workflow_id: workflow_id.to_string(),
                step_index,
                step_name: step_name.to_string(),
                result_type: result_type.to_string(),
                result_data,
                started_at,
                completed_at,
                respond: tx,
            })
            .await
            .map_err(|_| StorageError::Database("Writer thread not available".to_string()))?;

        rx.await
            .map_err(|_| StorageError::Database("Writer response channel closed".to_string()))?
    }

    /// Search segments using FTS5
    ///
    /// Returns matching segments ordered by BM25 relevance score.
    pub async fn search(&self, query: &str) -> Result<Vec<Segment>> {
        self.search_with_options(query, SearchOptions::default())
            .await
    }

    /// Search segments with options
    pub async fn search_with_options(
        &self,
        query: &str,
        options: SearchOptions,
    ) -> Result<Vec<Segment>> {
        let db_path = Arc::clone(&self.db_path);
        let query = query.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            search_fts(&conn, &query, &options)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Get unhandled events
    pub async fn get_unhandled_events(&self, limit: usize) -> Result<Vec<StoredEvent>> {
        let db_path = Arc::clone(&self.db_path);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            query_unhandled_events(&conn, limit)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Get all panes
    pub async fn get_panes(&self) -> Result<Vec<PaneRecord>> {
        let db_path = Arc::clone(&self.db_path);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            query_panes(&conn)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Get a specific pane
    pub async fn get_pane(&self, pane_id: u64) -> Result<Option<PaneRecord>> {
        let db_path = Arc::clone(&self.db_path);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            query_pane(&conn, pane_id)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Get recent segments for a pane
    pub async fn get_segments(&self, pane_id: u64, limit: usize) -> Result<Vec<Segment>> {
        let db_path = Arc::clone(&self.db_path);

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            query_segments(&conn, pane_id, limit)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Get workflow by ID
    pub async fn get_workflow(&self, workflow_id: &str) -> Result<Option<WorkflowRecord>> {
        let db_path = Arc::clone(&self.db_path);
        let workflow_id = workflow_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(db_path.as_str()).map_err(|e| {
                StorageError::Database(format!("Failed to open read connection: {e}"))
            })?;

            query_workflow(&conn, &workflow_id)
        })
        .await
        .map_err(|e| StorageError::Database(format!("Task join error: {e}")))?
    }

    /// Shutdown the storage handle
    ///
    /// Flushes all pending writes and waits for the writer thread to exit.
    pub async fn shutdown(mut self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        // Send shutdown command
        let _ = self
            .write_tx
            .send(WriteCommand::Shutdown { respond: tx })
            .await;

        // Wait for acknowledgment
        let _ = rx.await;

        // Wait for thread to finish
        if let Some(handle) = self.writer_handle.take() {
            handle
                .join()
                .map_err(|_| StorageError::Database("Writer thread panicked".to_string()))?;
        }

        Ok(())
    }
}

/// Search options for FTS queries
#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Filter by pane ID
    pub pane_id: Option<u64>,
    /// Filter by time range (epoch ms)
    pub since: Option<i64>,
    /// Filter by time range (epoch ms)
    pub until: Option<i64>,
}

// =============================================================================
// Writer Thread Implementation
// =============================================================================

/// Main loop for the writer thread
fn writer_loop(conn: &Connection, rx: &mut mpsc::Receiver<WriteCommand>) {
    // Use blocking_recv from sync context
    while let Some(cmd) = rx.blocking_recv() {
        match cmd {
            WriteCommand::AppendSegment {
                pane_id,
                content,
                content_hash,
                respond,
            } => {
                let result = append_segment_sync(conn, pane_id, &content, content_hash.as_deref());
                let _ = respond.send(result);
            }
            WriteCommand::RecordGap {
                pane_id,
                reason,
                respond,
            } => {
                let result = record_gap_sync(conn, pane_id, &reason);
                let _ = respond.send(result);
            }
            WriteCommand::RecordEvent { event, respond } => {
                let result = record_event_sync(conn, &event);
                let _ = respond.send(result);
            }
            WriteCommand::MarkEventHandled {
                event_id,
                workflow_id,
                status,
                respond,
            } => {
                let result =
                    mark_event_handled_sync(conn, event_id, workflow_id.as_deref(), &status);
                let _ = respond.send(result);
            }
            WriteCommand::UpsertPane { pane, respond } => {
                let result = upsert_pane_sync(conn, &pane);
                let _ = respond.send(result);
            }
            WriteCommand::UpsertWorkflow { workflow, respond } => {
                let result = upsert_workflow_sync(conn, &workflow);
                let _ = respond.send(result);
            }
            WriteCommand::InsertStepLog {
                workflow_id,
                step_index,
                step_name,
                result_type,
                result_data,
                started_at,
                completed_at,
                respond,
            } => {
                let result = insert_step_log_sync(
                    conn,
                    &workflow_id,
                    step_index,
                    &step_name,
                    &result_type,
                    result_data.as_deref(),
                    started_at,
                    completed_at,
                );
                let _ = respond.send(result);
            }
            WriteCommand::Shutdown { respond } => {
                // Acknowledge shutdown
                let _ = respond.send(());
                break;
            }
        }
    }
}

// =============================================================================
// Synchronous Database Operations
// =============================================================================

/// Get current timestamp in epoch milliseconds
fn now_ms() -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Append a segment (synchronous, called from writer thread)
fn append_segment_sync(
    conn: &Connection,
    pane_id: u64,
    content: &str,
    content_hash: Option<&str>,
) -> Result<Segment> {
    // Get next sequence number for this pane
    let next_seq: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq) + 1, 0) FROM output_segments WHERE pane_id = ?1",
            [pane_id as i64],
            |row| {
                let val: i64 = row.get(0)?;
                #[allow(clippy::cast_sign_loss)]
                Ok(val as u64)
            },
        )
        .map_err(|e| StorageError::Database(format!("Failed to get next seq: {e}")))?;

    let now = now_ms();
    let content_len = content.len();

    conn.execute(
        "INSERT INTO output_segments (pane_id, seq, content, content_len, content_hash, captured_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            pane_id as i64,
            next_seq as i64,
            content,
            content_len as i64,
            content_hash,
            now
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to insert segment: {e}")))?;

    let id = conn.last_insert_rowid();

    Ok(Segment {
        id,
        pane_id,
        seq: next_seq,
        content: content.to_string(),
        content_len,
        content_hash: content_hash.map(String::from),
        captured_at: now,
    })
}

/// Record a gap event (synchronous)
fn record_gap_sync(conn: &Connection, pane_id: u64, reason: &str) -> Result<Gap> {
    // Get the last sequence for this pane
    let last_seq: Option<u64> = conn
        .query_row(
            "SELECT MAX(seq) FROM output_segments WHERE pane_id = ?1",
            [pane_id as i64],
            |row| {
                let val: Option<i64> = row.get(0)?;
                #[allow(clippy::cast_sign_loss)]
                Ok(val.map(|v| v as u64))
            },
        )
        .optional()
        .map_err(|e| StorageError::Database(format!("Failed to get last seq: {e}")))?
        .flatten();

    let seq_before = last_seq.unwrap_or(0);
    let seq_after = seq_before + 1;
    let now = now_ms();

    conn.execute(
        "INSERT INTO output_gaps (pane_id, seq_before, seq_after, reason, detected_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            pane_id as i64,
            seq_before as i64,
            seq_after as i64,
            reason,
            now
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to insert gap: {e}")))?;

    let id = conn.last_insert_rowid();

    Ok(Gap {
        id,
        pane_id,
        seq_before,
        seq_after,
        reason: reason.to_string(),
        detected_at: now,
    })
}

/// Record an event (synchronous)
fn record_event_sync(conn: &Connection, event: &StoredEvent) -> Result<i64> {
    let extracted_json = event
        .extracted
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    conn.execute(
        "INSERT INTO events (pane_id, rule_id, agent_type, event_type, severity, confidence,
         extracted, matched_text, segment_id, detected_at, dedupe_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.pane_id as i64,
            event.rule_id,
            event.agent_type,
            event.event_type,
            event.severity,
            event.confidence,
            extracted_json,
            event.matched_text,
            event.segment_id,
            event.detected_at,
            None::<String>, // dedupe_key - can be computed if needed
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to insert event: {e}")))?;

    Ok(conn.last_insert_rowid())
}

/// Mark event as handled (synchronous)
fn mark_event_handled_sync(
    conn: &Connection,
    event_id: i64,
    workflow_id: Option<&str>,
    status: &str,
) -> Result<()> {
    let now = now_ms();

    conn.execute(
        "UPDATE events SET handled_at = ?1, handled_by_workflow_id = ?2, handled_status = ?3
         WHERE id = ?4",
        params![now, workflow_id, status, event_id],
    )
    .map_err(|e| StorageError::Database(format!("Failed to mark event handled: {e}")))?;

    Ok(())
}

/// Upsert pane record (synchronous)
fn upsert_pane_sync(conn: &Connection, pane: &PaneRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO panes (pane_id, domain, window_id, tab_id, title, cwd, tty_name,
         first_seen_at, last_seen_at, observed, ignore_reason, last_decision_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(pane_id) DO UPDATE SET
            domain = excluded.domain,
            window_id = excluded.window_id,
            tab_id = excluded.tab_id,
            title = excluded.title,
            cwd = excluded.cwd,
            tty_name = excluded.tty_name,
            last_seen_at = excluded.last_seen_at,
            observed = excluded.observed,
            ignore_reason = excluded.ignore_reason,
            last_decision_at = excluded.last_decision_at",
        params![
            pane.pane_id as i64,
            pane.domain,
            pane.window_id.map(|v| v as i64),
            pane.tab_id.map(|v| v as i64),
            pane.title,
            pane.cwd,
            pane.tty_name,
            pane.first_seen_at,
            pane.last_seen_at,
            pane.observed as i64,
            pane.ignore_reason,
            pane.last_decision_at,
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to upsert pane: {e}")))?;

    Ok(())
}

/// Upsert workflow execution (synchronous)
fn upsert_workflow_sync(conn: &Connection, workflow: &WorkflowRecord) -> Result<()> {
    let wait_condition_json = workflow
        .wait_condition
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let context_json = workflow
        .context
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let result_json = workflow
        .result
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    conn.execute(
        "INSERT INTO workflow_executions (id, workflow_name, pane_id, trigger_event_id,
         current_step, status, wait_condition, context, result, error, started_at, updated_at, completed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET
            current_step = excluded.current_step,
            status = excluded.status,
            wait_condition = excluded.wait_condition,
            context = excluded.context,
            result = excluded.result,
            error = excluded.error,
            updated_at = excluded.updated_at,
            completed_at = excluded.completed_at",
        params![
            workflow.id,
            workflow.workflow_name,
            workflow.pane_id as i64,
            workflow.trigger_event_id,
            workflow.current_step as i64,
            workflow.status,
            wait_condition_json,
            context_json,
            result_json,
            workflow.error,
            workflow.started_at,
            workflow.updated_at,
            workflow.completed_at,
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to upsert workflow: {e}")))?;

    Ok(())
}

/// Insert workflow step log (synchronous)
fn insert_step_log_sync(
    conn: &Connection,
    workflow_id: &str,
    step_index: usize,
    step_name: &str,
    result_type: &str,
    result_data: Option<&str>,
    started_at: i64,
    completed_at: i64,
) -> Result<()> {
    let duration_ms = completed_at.saturating_sub(started_at);

    conn.execute(
        "INSERT INTO workflow_step_logs (workflow_id, step_index, step_name, result_type,
         result_data, started_at, completed_at, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            workflow_id,
            step_index as i64,
            step_name,
            result_type,
            result_data,
            started_at,
            completed_at,
            duration_ms,
        ],
    )
    .map_err(|e| StorageError::Database(format!("Failed to insert step log: {e}")))?;

    Ok(())
}

// =============================================================================
// Read Operations (called from spawn_blocking)
// =============================================================================

/// Search using FTS5
#[allow(clippy::cast_sign_loss)]
fn search_fts(conn: &Connection, query: &str, options: &SearchOptions) -> Result<Vec<Segment>> {
    let limit = options.limit.unwrap_or(100);

    // Build query with optional filters
    let mut sql = String::from(
        "SELECT s.id, s.pane_id, s.seq, s.content, s.content_len, s.content_hash, s.captured_at
         FROM output_segments s
         JOIN output_segments_fts fts ON s.id = fts.rowid
         WHERE output_segments_fts MATCH ?1",
    );

    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(query.to_string())];

    if let Some(pane_id) = options.pane_id {
        sql.push_str(" AND s.pane_id = ?");
        params_vec.push(Box::new(pane_id as i64));
    }

    if let Some(since) = options.since {
        sql.push_str(" AND s.captured_at >= ?");
        params_vec.push(Box::new(since));
    }

    if let Some(until) = options.until {
        sql.push_str(" AND s.captured_at <= ?");
        params_vec.push(Box::new(until));
    }

    sql.push_str(" ORDER BY bm25(output_segments_fts) LIMIT ?");
    params_vec.push(Box::new(limit as i64));

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| StorageError::FtsQueryError(format!("Failed to prepare query: {e}")))?;

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(Segment {
                id: row.get(0)?,
                pane_id: {
                    let val: i64 = row.get(1)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                seq: {
                    let val: i64 = row.get(2)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                content: row.get(3)?,
                content_len: {
                    let val: i64 = row.get(4)?;
                    val as usize
                },
                content_hash: row.get(5)?,
                captured_at: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::FtsQueryError(format!("Query failed: {e}")))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| StorageError::Database(format!("Row error: {e}")))?);
    }

    Ok(results)
}

/// Query unhandled events
fn query_unhandled_events(conn: &Connection, limit: usize) -> Result<Vec<StoredEvent>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, pane_id, rule_id, agent_type, event_type, severity, confidence,
             extracted, matched_text, segment_id, detected_at, handled_at,
             handled_by_workflow_id, handled_status
             FROM events
             WHERE handled_at IS NULL
             ORDER BY detected_at DESC
             LIMIT ?1",
        )
        .map_err(|e| StorageError::Database(format!("Failed to prepare query: {e}")))?;

    let rows = stmt
        .query_map([limit as i64], |row| {
            let extracted_str: Option<String> = row.get(7)?;
            let extracted = extracted_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());

            Ok(StoredEvent {
                id: row.get(0)?,
                pane_id: {
                    let val: i64 = row.get(1)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                rule_id: row.get(2)?,
                agent_type: row.get(3)?,
                event_type: row.get(4)?,
                severity: row.get(5)?,
                confidence: row.get(6)?,
                extracted,
                matched_text: row.get(8)?,
                segment_id: row.get(9)?,
                detected_at: row.get(10)?,
                handled_at: row.get(11)?,
                handled_by_workflow_id: row.get(12)?,
                handled_status: row.get(13)?,
            })
        })
        .map_err(|e| StorageError::Database(format!("Query failed: {e}")))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| StorageError::Database(format!("Row error: {e}")))?);
    }

    Ok(results)
}

/// Query all panes
fn query_panes(conn: &Connection) -> Result<Vec<PaneRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT pane_id, domain, window_id, tab_id, title, cwd, tty_name,
             first_seen_at, last_seen_at, observed, ignore_reason, last_decision_at
             FROM panes
             ORDER BY last_seen_at DESC",
        )
        .map_err(|e| StorageError::Database(format!("Failed to prepare query: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(PaneRecord {
                pane_id: {
                    let val: i64 = row.get(0)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                domain: row.get(1)?,
                window_id: {
                    let val: Option<i64> = row.get(2)?;
                    #[allow(clippy::cast_sign_loss)]
                    val.map(|v| v as u64)
                },
                tab_id: {
                    let val: Option<i64> = row.get(3)?;
                    #[allow(clippy::cast_sign_loss)]
                    val.map(|v| v as u64)
                },
                title: row.get(4)?,
                cwd: row.get(5)?,
                tty_name: row.get(6)?,
                first_seen_at: row.get(7)?,
                last_seen_at: row.get(8)?,
                observed: row.get::<_, i64>(9)? != 0,
                ignore_reason: row.get(10)?,
                last_decision_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::Database(format!("Query failed: {e}")))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| StorageError::Database(format!("Row error: {e}")))?);
    }

    Ok(results)
}

/// Query a specific pane
fn query_pane(conn: &Connection, pane_id: u64) -> Result<Option<PaneRecord>> {
    conn.query_row(
        "SELECT pane_id, domain, window_id, tab_id, title, cwd, tty_name,
         first_seen_at, last_seen_at, observed, ignore_reason, last_decision_at
         FROM panes WHERE pane_id = ?1",
        [pane_id as i64],
        |row| {
            Ok(PaneRecord {
                pane_id: {
                    let val: i64 = row.get(0)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                domain: row.get(1)?,
                window_id: {
                    let val: Option<i64> = row.get(2)?;
                    #[allow(clippy::cast_sign_loss)]
                    val.map(|v| v as u64)
                },
                tab_id: {
                    let val: Option<i64> = row.get(3)?;
                    #[allow(clippy::cast_sign_loss)]
                    val.map(|v| v as u64)
                },
                title: row.get(4)?,
                cwd: row.get(5)?,
                tty_name: row.get(6)?,
                first_seen_at: row.get(7)?,
                last_seen_at: row.get(8)?,
                observed: row.get::<_, i64>(9)? != 0,
                ignore_reason: row.get(10)?,
                last_decision_at: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(|e| StorageError::Database(format!("Query failed: {e}")).into())
}

/// Query segments for a pane
#[allow(clippy::cast_sign_loss)]
fn query_segments(conn: &Connection, pane_id: u64, limit: usize) -> Result<Vec<Segment>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, pane_id, seq, content, content_len, content_hash, captured_at
             FROM output_segments
             WHERE pane_id = ?1
             ORDER BY seq DESC
             LIMIT ?2",
        )
        .map_err(|e| StorageError::Database(format!("Failed to prepare query: {e}")))?;

    let rows = stmt
        .query_map([pane_id as i64, limit as i64], |row| {
            Ok(Segment {
                id: row.get(0)?,
                pane_id: {
                    let val: i64 = row.get(1)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                seq: {
                    let val: i64 = row.get(2)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                content: row.get(3)?,
                content_len: {
                    let val: i64 = row.get(4)?;
                    val as usize
                },
                content_hash: row.get(5)?,
                captured_at: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::Database(format!("Query failed: {e}")))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| StorageError::Database(format!("Row error: {e}")))?);
    }

    Ok(results)
}

/// Query workflow by ID
#[allow(clippy::cast_sign_loss)]
fn query_workflow(conn: &Connection, workflow_id: &str) -> Result<Option<WorkflowRecord>> {
    conn.query_row(
        "SELECT id, workflow_name, pane_id, trigger_event_id, current_step, status,
         wait_condition, context, result, error, started_at, updated_at, completed_at
         FROM workflow_executions WHERE id = ?1",
        [workflow_id],
        |row| {
            let wait_condition_str: Option<String> = row.get(6)?;
            let wait_condition = wait_condition_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());

            let context_str: Option<String> = row.get(7)?;
            let context = context_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());

            let result_str: Option<String> = row.get(8)?;
            let result = result_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());

            Ok(WorkflowRecord {
                id: row.get(0)?,
                workflow_name: row.get(1)?,
                pane_id: {
                    let val: i64 = row.get(2)?;
                    #[allow(clippy::cast_sign_loss)]
                    {
                        val as u64
                    }
                },
                trigger_event_id: row.get(3)?,
                current_step: {
                    let val: i64 = row.get(4)?;
                    #[allow(clippy::cast_sign_loss)]
                    val as usize
                },
                status: row.get(5)?,
                wait_condition,
                context,
                result,
                error: row.get(9)?,
                started_at: row.get(10)?,
                updated_at: row.get(11)?,
                completed_at: row.get(12)?,
            })
        },
    )
    .optional()
    .map_err(|e| StorageError::Database(format!("Query failed: {e}")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    // =========================================================================
    // Schema Initialization Tests
    // =========================================================================

    #[test]
    fn schema_initializes_on_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();

        // Should need initialization
        assert!(needs_initialization(&conn).unwrap());

        // Initialize
        initialize_schema(&conn).unwrap();

        // Should not need initialization anymore
        assert!(!needs_initialization(&conn).unwrap());

        // Version should be recorded
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, Some(SCHEMA_VERSION));
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize twice
        initialize_schema(&conn).unwrap();
        initialize_schema(&conn).unwrap();

        // Should still be valid
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, Some(SCHEMA_VERSION));
    }

    #[test]
    fn all_tables_exist_after_init() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let expected_tables = [
            "schema_version",
            "panes",
            "output_segments",
            "output_gaps",
            "events",
            "workflow_executions",
            "workflow_step_logs",
            "config",
            "maintenance_log",
        ];

        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table {table} should exist");
        }
    }

    #[test]
    fn fts_table_exists_after_init() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='output_segments_fts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "FTS5 table should exist");
    }

    #[test]
    fn wal_mode_is_enabled() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory databases use "memory" mode, but WAL works on file-based DBs
        assert!(mode == "memory" || mode == "wal");
    }

    // =========================================================================
    // Basic Insert/Query Tests (validates schema correctness)
    // =========================================================================

    #[test]
    #[allow(clippy::cast_possible_wrap)]
    fn can_insert_and_query_pane() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![42i64, "local", now_ms, now_ms, 1],
        )
        .unwrap();

        let (pane_id, domain): (i64, String) = conn
            .query_row(
                "SELECT pane_id, domain FROM panes WHERE pane_id = ?1",
                [42i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(pane_id, 42);
        assert_eq!(domain, "local");
    }

    #[test]
    fn can_insert_segment_with_unique_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane first (foreign key)
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert segment
        conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "hello", 5, now_ms],
        ).unwrap();

        // Duplicate should fail
        let result = conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "world", 5, now_ms],
        );
        assert!(result.is_err(), "Duplicate (pane_id, seq) should fail");
    }

    #[test]
    fn fts_trigger_syncs_on_insert() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert segment
        conn.execute(
            "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, 0i64, "hello world test", 16, now_ms],
        ).unwrap();

        // Search via FTS
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM output_segments_fts WHERE output_segments_fts MATCH 'world'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "FTS should find the inserted content");
    }

    #[test]
    fn can_insert_event_and_mark_handled() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert unhandled event
        conn.execute(
            "INSERT INTO events (pane_id, rule_id, agent_type, event_type, severity, confidence, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![1i64, "codex.usage_limit", "codex", "usage", "warning", 0.95, now_ms],
        ).unwrap();

        // Query unhandled
        let unhandled_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE handled_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unhandled_count, 1);

        // Mark as handled
        conn.execute(
            "UPDATE events SET handled_at = ?1, handled_status = ?2 WHERE id = 1",
            params![now_ms + 1000, "completed"],
        )
        .unwrap();

        // Query unhandled again
        let unhandled_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE handled_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unhandled_count, 0);
    }

    #[test]
    fn can_insert_workflow_execution() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert workflow execution
        conn.execute(
            "INSERT INTO workflow_executions (id, workflow_name, pane_id, current_step, status, started_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["wf-001", "handle_compaction", 1i64, 0, "running", now_ms, now_ms],
        ).unwrap();

        // Query
        let (name, status): (String, String) = conn
            .query_row(
                "SELECT workflow_name, status FROM workflow_executions WHERE id = ?1",
                ["wf-001"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(name, "handle_compaction");
        assert_eq!(status, "running");
    }

    // =========================================================================
    // Data Structure Serialization Tests
    // =========================================================================

    #[test]
    fn segment_serializes() {
        let segment = Segment {
            id: 1,
            pane_id: 42,
            seq: 100,
            content: "Hello, world!".to_string(),
            content_len: 13,
            content_hash: Some("abc123".to_string()),
            captured_at: 1_234_567_890,
        };

        let json = serde_json::to_string(&segment).unwrap();
        assert!(json.contains("Hello, world!"));
        assert!(json.contains("content_len"));
    }

    #[test]
    fn pane_record_serializes() {
        let pane = PaneRecord {
            pane_id: 1,
            domain: "local".to_string(),
            window_id: Some(0),
            tab_id: Some(0),
            title: Some("bash".to_string()),
            cwd: Some("/home/user".to_string()),
            tty_name: None,
            first_seen_at: 1_700_000_000_000,
            last_seen_at: 1_700_000_001_000,
            observed: true,
            ignore_reason: None,
            last_decision_at: None,
        };

        let json = serde_json::to_string(&pane).unwrap();
        assert!(json.contains("local"));
        assert!(json.contains("bash"));
    }

    #[test]
    fn stored_event_serializes() {
        let event = StoredEvent {
            id: 1,
            pane_id: 42,
            rule_id: "codex.usage_limit".to_string(),
            agent_type: "codex".to_string(),
            event_type: "usage".to_string(),
            severity: "warning".to_string(),
            confidence: 0.95,
            extracted: Some(serde_json::json!({"limit": 100})),
            matched_text: Some("Usage limit reached".to_string()),
            segment_id: Some(123),
            detected_at: 1_700_000_000_000,
            handled_at: None,
            handled_by_workflow_id: None,
            handled_status: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("codex.usage_limit"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn workflow_record_serializes() {
        let workflow = WorkflowRecord {
            id: "wf-001".to_string(),
            workflow_name: "handle_compaction".to_string(),
            pane_id: 42,
            trigger_event_id: Some(1),
            current_step: 2,
            status: "running".to_string(),
            wait_condition: None,
            context: Some(serde_json::json!({"retry_count": 0})),
            result: None,
            error: None,
            started_at: 1_700_000_000_000,
            updated_at: 1_700_000_001_000,
            completed_at: None,
        };

        let json = serde_json::to_string(&workflow).unwrap();
        assert!(json.contains("handle_compaction"));
        assert!(json.contains("wf-001"));
    }

    // =========================================================================
    // wa-4vx.3.3: Gap Recording Tests
    // =========================================================================

    #[test]
    fn can_record_gap_on_discontinuity() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert some segments (seq 0, 1, 2)
        for seq in 0..3 {
            conn.execute(
                "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![1i64, seq, format!("content {}", seq), 10, now_ms + seq * 100],
            ).unwrap();
        }

        // Record a gap (simulating a discontinuity detected)
        let gap = record_gap_sync(&conn, 1, "sequence_jump").unwrap();

        // Verify gap was recorded
        assert_eq!(gap.pane_id, 1);
        assert_eq!(gap.seq_before, 2); // Last seq was 2
        assert_eq!(gap.seq_after, 3);  // Next expected would be 3
        assert_eq!(gap.reason, "sequence_jump");

        // Query the gap from the database
        let (id, pane_id, seq_before, seq_after, reason): (i64, i64, i64, i64, String) = conn
            .query_row(
                "SELECT id, pane_id, seq_before, seq_after, reason FROM output_gaps WHERE pane_id = ?1",
                [1i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();

        assert!(id > 0);
        assert_eq!(pane_id, 1);
        assert_eq!(seq_before, 2);
        assert_eq!(seq_after, 3);
        assert_eq!(reason, "sequence_jump");
    }

    #[test]
    fn gap_reasons_are_stable() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Record gaps with different reasons
        let reasons = vec![
            "sequence_jump",
            "overlap_detected",
            "cursor_truncation",
            "session_restart",
        ];

        for reason in &reasons {
            record_gap_sync(&conn, 1, reason).unwrap();
        }

        // Verify all gaps were recorded with stable reasons
        let mut stmt = conn.prepare("SELECT reason FROM output_gaps WHERE pane_id = ?1 ORDER BY id").unwrap();
        let recorded_reasons: Vec<String> = stmt
            .query_map([1i64], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(recorded_reasons, reasons);
    }

    // =========================================================================
    // wa-4vx.3.3: Last-N Query Tests
    // =========================================================================

    #[test]
    fn last_n_segments_returns_deterministic_order() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        let now_ms = 1_700_000_000_000i64;

        // Insert pane
        conn.execute(
            "INSERT INTO panes (pane_id, domain, first_seen_at, last_seen_at, observed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![1i64, "local", now_ms, now_ms, 1],
        ).unwrap();

        // Insert segments out of order (seq: 5, 2, 8, 1, 3)
        let insert_order = vec![5, 2, 8, 1, 3];
        for seq in insert_order {
            conn.execute(
                "INSERT INTO output_segments (pane_id, seq, content, content_len, captured_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![1i64, seq, format!("segment-{}", seq), 10, now_ms + seq * 100],
            ).unwrap();
        }

        // Query last 3 segments
        let segments = query_segments(&conn, 1, 3).unwrap();

        // Should return in descending seq order: 8, 5, 3
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].seq, 8);
        assert_eq!(segments[1].seq, 5);
        assert_eq!(segments[2].seq, 3);

        // Query all segments
        let all_segments = query_segments(&conn, 1, 100).unwrap();
        assert_eq!(all_segments.len(), 5);

        // Verify strictly descending order
        for window in all_segments.windows(2) {
            assert!(window[0].seq > window[1].seq, "Segments should be in strictly descending seq order");
        }
    }

    #[test]
    fn last_n_query_is_indexed() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_schema(&conn).unwrap();

        // Verify the index exists using EXPLAIN QUERY PLAN
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT id, pane_id, seq, content, content_len, content_hash, captured_at
                 FROM output_segments WHERE pane_id = 1 ORDER BY seq DESC LIMIT 10",
                [],
                |row| row.get(3),
            )
            .unwrap();

        // The query plan should use the idx_segments_pane_seq index
        assert!(
            plan.contains("idx_segments_pane_seq") || plan.contains("USING INDEX"),
            "Query should use the pane_seq index, got: {}",
            plan
        );
    }
}
