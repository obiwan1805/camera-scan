#   JobManager Implementation Plan - Detailed Task-by-Task

# Current State

Existing Scanner Components:
- src/layers/layer1_port_scanner/ - masscan-based port scanner
- src/layers/layer2_fingerprinter/ - camera fingerprinting modules
- src/storage/sqlite_backend.py - SQLite persistence
- src/storage/schemas.py - Pydantic models (PortScanResult, CameraFingerprint)
- main.py - one-shot execution entry point

Current Limitations:
- No job queue or state management
- No progress tracking
- No isolation between concurrent scans
- No pause/resume capability
- Event loop blocking (subprocess waits)
- In-memory only state

---
# Task 1: Create Job Schemas and Database Schema

<details>
<summary>1.1 Create JobStatus Enum</summary>

- File: src/jobs/schemas.py (new)
- Enum values: pending, queued, running, paused, completed, failed, cancelled, timeout
- Add can_transition_to() method for state validation
</details>

<details>
<summary>1.2 Create Job Pydantic Schema</summary>

- Fields:
- id: UUID - Unique job identifier
- name: str - Optional job name
- status: JobStatus
- cidrs: List[str] - CIDR ranges to scan
- ports: List[int] - Ports to scan (optional, defaults to [80, 554, 443, 8080, 8443, 8888])
- priority: int - Job priority (default: 50, lower = higher priority)
- progress: Dict[str, float] - Per-layer progress: {"layer1": 0.0, "layer2": 0.0}
- stats: Dict[str, int] - Statistics: {"discovered": 0, "processed": 0, "successful": 0, "failed": 0}
- created_at: datetime
- queued_at: Optional[datetime]
- started_at: Optional[datetime]
- completed_at: Optional[datetime]
- pid: Optional[int] - Scanner process PID
- exit_code: Optional[int] - Scanner exit code
- error: Optional[str] - Error message if failed
- timeout_seconds: Optional[int] - Max duration
- retry_count: int - Number of retries attempted
- max_retries: int - Max retry attempts
- result_count: int - Number of results generated
</details>

<details>
<summary>1.3 Create JobConfig Schema</summary>

- Fields:
- scan_rate: int = 10000 - Masscan rate
- max_concurrent: int = 50 - Fingerprinter concurrency
- pool_type: str = "multiprocessing" - Pool type
- timeout: int = 3600 - Default timeout (seconds)
- retry_delay: int = 30 - Delay between retries (seconds)
</details>

<details>
<summary>1.4 Create JobResult Schema</summary>

- Fields:
- id: UUID
- job_id: UUID - Link to job
- result_type: str - "port_scan" or "fingerprint"
- data: Dict[str, Any] - Serialized result
- layer: int - Which layer produced it
- created_at: datetime
</details>

<details>
<summary>1.5 Create SQLite Migration</summary>

- File: src/jobs/migrations/001_create_jobs.py (new)
- Create tables:
- jobs - Job records
- job_results - Result records
- Indexes:
- idx_jobs_status - For querying by status
- idx_jobs_created - For sorting by creation time
- idx_job_results_job_id - For fetching results by job
</details>

<details>
<summary>1.6 Update Storage Backend</summary>

- File: src/storage/sqlite_backend.py
- Add methods:
- create_job(job: Job) -> Job
- get_job(job_id: UUID) -> Optional[Job]
- update_job(job_id: UUID, **updates) -> bool
- list_jobs(status: Optional[JobStatus] = None, limit: int = 100) -> List[Job]
- delete_job(job_id: UUID) -> bool
- add_result(job_result: JobResult) -> JobResult
- get_job_results(job_id: UUID, limit: int = 1000) -> List[JobResult]
- delete_job_results(job_id: UUID) -> bool
</details>

---
# Task 2: Create Job Manager Core

<details>
<summary>2.1 Create JobManager Base Class</summary>

- File: src/jobs/manager.py (new)
- Class: JobManager
- __init__ parameters:
- storage: StorageBackend
- max_concurrent_jobs: int = 2
- max_queue_size: int = 10
- default_timeout: int = 3600
- default_max_retries: int = 2
</details>

<details>
<summary>2.2 Implement Job Queue</summary>

- Internal queue: PriorityQueue[Tuple[int, int, UUID]] - (priority, timestamp, job_id)
- Priority: lower number = higher priority
- Timestamp: for FIFO ordering within same priority
- Methods:
- async _queue_worker() - Background task processing queue
- async _start_job(job_id: UUID) - Execute a job
- async _job_runner(job_id: UUID) - Run job and handle completion
</details>

<details>
<summary>2.3 Implement Job Lifecycle Methods</summary>

- async submit_job(cidrs: List[str], config: JobConfig, priority: int = 50) -> UUID
- Create Job record with status pending
- Add to queue if running count < max_concurrent_jobs
- Else queue for later
- Return job_id
- async cancel_job(job_id: UUID) -> bool
- Check if job can be cancelled (pending or running)
- Update status to cancelled
- If running, terminate process
- Return success
- async pause_job(job_id: UUID) -> bool
- Check if running
- Update status to paused
- Signal scanner to pause
- Return success
- async resume_job(job_id: UUID) -> bool
- Check if paused
- Update status to running
- Resume scanner
- Return success
</details>

<details>
<summary>2.4 Implement Job Query Methods</summary>

- async get_job(job_id: UUID) -> Optional[Job]
- Fetch from storage
- async list_jobs(status: Optional[JobStatus] = None, limit: int = 50) -> List[Job]
- Fetch from storage with filters
- async get_queue_status() -> QueueStatus
- Return structure:
QueueStatus:
    pending: int
    queued: int
    running: int
    paused: int
    completed: int
    failed: int
    max_concurrent: int
</details>

<details>
<summary>2.5 Implement Job Progress Tracking</summary>

- async update_job_progress(job_id: UUID, layer: str, progress: float) -> bool
- Update progress dict in job
- Persist to storage
- Trigger progress callbacks
- async update_job_stats(job_id: UUID, stats: Dict[str, int]) -> bool
- Update stats dict in job
- Persist to storage
- Trigger callbacks
</details>

<details>
<summary>2.6 Implement Callback System</summary>

- register_progress_callback(callback: Callable[[UUID, Dict[str, Any]], None]) -> None
- Add callback function to registry
- register_completion_callback(callback: Callable[[UUID, Job], None]) -> None
- Add completion callback
- _trigger_progress_callbacks(job_id: UUID, progress: Dict[str, Any]) -> None
- Call all registered progress callbacks
</details>

<details>
<summary>2.7 Implement Start/Stop Methods</summary>

- async start() -> None
- Start queue worker task
- Start recovery process
- async stop() -> None
- Signal shutdown
- Wait for running jobs (with timeout)
- Cancel queued jobs
- Stop queue worker
</details>

<details>
<summary>2.8 Add State Validation</summary>

- _validate_state_transition(from_status: JobStatus, to_status: JobStatus) -> bool
- Ensure valid state transitions
</details>

---
# Task 3: Create Resource Manager

<details>
<summary>3.1 Create ResourceManager Class</summary>

- File: src/jobs/resources.py (new)
- Class: ResourceManager
</details>

<details>
<summary>3.2 Track File Descriptors</summary>

- Methods:
- async acquire_fds(count: int, job_id: UUID) -> bool
    - Check if available FDs >= count
    - Allocate and track
    - Return success
- async release_fds(count: int, job_id: UUID) -> None
    - Release allocated FDs
    - Clean up tracking
- async wait_for_fds(count: int, job_id: UUID, timeout: int = 30) -> bool
    - Wait until FDs available
    - Timeout after N seconds
</details>

<details>
<summary>3.3 Track Concurrent Jobs</summary>

- Methods:
- async start_job(job_id: UUID) -> bool
    - Check if under max_concurrent_jobs
    - Track job
- async end_job(job_id: UUID) -> None
    - Remove from tracking
    - Trigger any waiting jobs
- get_active_jobs() -> List[UUID]
    - Return list of running job IDs
</details>

<details>
<summary>3.4 Implement Job-Level Resource Limits</summary>

- Config:
resources:
max_concurrent_jobs: 2
max_fds_per_job: 1000
max_fds_total: 10000
queue_timeout: 30
- Resource allocation strategy:
- Total FDs must fit within OS limits
- Per-job FDs tracked per job
- Block queue when limits reached
</details>

<details>
<summary>3.5 Add Resource Monitoring</summary>

- async monitor_resources() -> None
- Background task
- Log resource usage periodically
- Alert on nearing limits
- get_resource_status() -> ResourceStatus
- Return current FD usage
- Return active job count
</details>

---
# Task 4: Create Scanner Service for Job Isolation

<details>
<summary>4.1 Create ScannerService Class</summary>

- File: src/jobs/scanner_service.py (new)
- Class: ScannerService
</details>

<details>
<summary>4.2 Implement Job Directory Isolation</summary>

- async prepare_job_directory(job_id: UUID) -> Path
- Create data/jobs/{job_id}/
- Create subdirectories: scans/, logs/, temp/
- Return path
- async cleanup_job_directory(job_id: UUID) -> bool
- Remove job directory
- Return success
</details>

<details>
<summary>4.3 Implement Scanner Process Management</summary>

- async start_scanner(job: Job, job_dir: Path) -> int
- Write CIDRs to job_dir/cidrs.txt
- Write config to job_dir/config.yaml
- Start masscan subprocess
- Return PID
- async stop_scanner(pid: int) -> bool
- Send SIGTERM
- Wait for graceful shutdown (10s timeout)
- Send SIGKILL if needed
- Return success
- async is_scanner_running(pid: int) -> bool
- Check if process exists
</details>

<details>
<summary>4.4 Implement Output Monitoring</summary>

- async monitor_scanner_output(job_id: UUID, job_dir: Path) -> None
- Watch job_dir/logs/scanner.log
- Parse output for progress
- Extract discovered count
- Update job stats
- async monitor_fingerprinter_output(job_id: UUID, job_dir: Path) -> None
- Watch job_dir/logs/fingerprinter.log
- Parse for processed/successful counts
- Update job stats
</details>

<details>
<summary>4.5 Implement Scanner Wrapper</summary>

- async run_job(job: Job, job_manager: JobManager) -> JobResult
- Prepare job directory
- Start scanner process
- Start output monitoring tasks
- Wait for completion
- Collect results
- Cleanup
- Return final job status
</details>

<details>
<summary>4.6 Adapt Existing Scanner Code</summary>

- Refactor main.py:
- Extract run_scan(cidrs_file, config) function
- Make paths configurable
- Add progress callbacks
- Create src/scanner/orchestrator.py (new):
- async run_isolated_scan(job_id: UUID, job_dir: Path, config: dict) -> ScanResult
- Instantiate pipeline
- Run scan
- Return results
</details>

<details>
<summary>4.7 Add Pause/Resume Support</summary>

- async pause_scanner(job_id: UUID) -> bool
- Signal scanner to pause (Unix signal or file marker)
- Wait for acknowledgment
- async resume_scanner(job_id: UUID) -> bool
- Signal scanner to resume
- Continue processing
</details>

---
# Task 5: Create Progress Tracking System

<details>
<summary>5.1 Create ProgressTracker Class</summary>

- File: src/jobs/progress.py (new)
- Class: ProgressTracker
</details>

<details>
<summary>5.2 Track Layer Progress</summary>

- Methods:
- update_layer_progress(layer: str, current: int, total: Optional[int] = None) -> None
    - Update progress for specific layer
    - Calculate percentage if total provided
- get_layer_progress(layer: str) -> LayerProgress
    - Return progress structure:
LayerProgress:
    current: int
    total: Optional[int]
    percentage: float
    rate: float  # items per second
    eta: Optional[float]  # estimated time remaining
- get_overall_progress() -> float
    - Calculate weighted average across layers
</details>

<details>
<summary>5.3 Implement Progress Callbacks</summary>

- register_callback(callback: Callable[[Dict[str, Any]], None]) -> None
- Add callback to registry
- _notify_callbacks() -> None
- Rate-limited notification
- Minimum 1 second between callbacks
- Debounce rapid updates
</details>

<details>
<summary>5.4 Add Progress Serialization</summary>

- to_dict() -> Dict[str, Any]
- Serialize progress for storage/DB
- from_dict(data: Dict[str, Any]) -> ProgressTracker
- Deserialize from storage
</details>

<details>
<summary>5.5 Hook Progress into Scanner Layers</summary>

- Modify src/layers/layer1_port_scanner/scanner.py:
- Add progress_callback: Optional[Callable] parameter
- Call callback on discovered count changes
- Emit every N discoveries or on timer
- Modify src/layers/layer2_fingerprinter/fingerprinter.py:
- Add progress_callback: Optional[Callable] parameter
- Call callback on processed count changes
- Emit status report as progress
</details>

<details>
<summary>5.6 Create Progress Display Formatters</summary>

- format_progress_for_discord(progress: Dict[str, Any]) -> discord.Embed
- Create Discord embed with progress bars
- Show per-layer progress
- Include timestamps
- format_progress_text(progress: Dict[str, Any]) -> str
- ASCII-based progress display for CLI
</details>

---
# Task 6: Create Timeout and Retry Handler

<details>
<summary>6.1 Create TimeoutHandler Class</summary>

- File: src/jobs/timeout.py (new)
- Class: TimeoutHandler
</details>

<details>
<summary>6.2 Implement Job Timeout</summary>

- Methods:
- async monitor_job(job_id: UUID, timeout: int) -> None
    - Background task
    - Sleep for timeout duration
    - If job still running, mark as timeout
- async cancel_timeout(job_id: UUID) -> None
    - Cancel timeout task for job
</details>

<details>
<summary>6.3 Implement Retry Logic</summary>

- Methods:
- async should_retry(job: Job) -> bool
    - Check error type
    - Check retry count vs max_retries
    - Return whether to retry
- async schedule_retry(job: Job, delay: int) -> None
    - Wait for delay
    - Requeue job
- async calculate_backoff(retry_count: int) -> int
    - Exponential backoff: min(30 * (2 ** retry_count), 300)
</details>

<details>
<summary>6.4 Define Retryable Errors</summary>

- Create RetryableError exceptions:
- NetworkError - Connection issues
- TemporaryError - Transient failures
- ProcessError - Scanner crashed unexpectedly
- Non-retryable:
- ValidationError - Invalid CIDR/config
- PermissionError - Insufficient permissions
- ResourceLimitError - FD limit exceeded
</details>

<details>
<summary>6.5 Implement Watchdog</summary>

- async watchdog_check(job_id: UUID, job_manager: JobManager) -> None
- Periodic check (every 30s)
- Verify process still running
- Verify progress is advancing
- Mark as failed if stuck
</details>

<details>
<summary>6.6 Add Timeout Configuration</summary>

- Config:
timeout:
default: 3600  # 1 hour
max_retries: 2
retry_delay: 30
backoff_multiplier: 2
watchdog_interval: 30
stale_timeout: 300  # 5 minutes of no progress
</details>

---
# Task 7: Create Job Recovery System

<details>
<summary>7.1 Create RecoveryManager Class</summary>

- File: src/jobs/recovery.py (new)
- Class: RecoveryManager
</details>

<details>
<summary>7.2 Implement Startup Recovery</summary>

- async recover_jobs(job_manager: JobManager) -> None
- Query all running and paused jobs
- For each job:
    - Check if PID still exists
    - If not: update to failed with error "Process died"
    - If exists: check last progress timestamp
    - If stale (> 5 min): mark as failed
</details>

<details>
<summary>7.3 Implement Orphan Cleanup</summary>

- async cleanup_orphaned_results() -> None
- Find results without valid job_id
- Delete after 7 days
- async cleanup_old_jobs() -> None
- Archive jobs older than 30 days
- Move to separate table or delete
</details>

<details>
<summary>7.4 Implement Job Persistence Checkpointing</summary>

- async checkpoint_job(job_id: UUID) -> None
- Save current state to file
- Enable resume after crash
- async restore_checkpoint(job_id: UUID) -> bool
- Load state from checkpoint
- Resume processing
</details>

<details>
<summary>7.5 Add Recovery Metrics</summary>

- get_recovery_stats() -> RecoveryStats
- Return:
    - jobs_recovered
    - jobs_failed
    - jobs_cleaned
</details>

---
# Task 8: Create Discord Bot Integration

<details>
<summary>8.1 Create Discord Bot Class</summary>

- File: src/bot/discord_bot.py (new)
- Class: CameraScanBot
</details>

<details>
<summary>8.2 Implement Bot Initialization</summary>

- __init__ parameters:
- token: str - Discord bot token
- job_manager: JobManager
- storage: StorageBackend
- async setup_hook() -> None
- Setup command tree
- Register slash commands
- Start job manager
</details>

<details>
<summary>8.3 Implement /scan start Command</summary>

- Parameters: cidrs: str, name: Optional[str], priority: int
- Actions:
- Parse CIDR input (comma-separated)
- Validate CIDRs
- Create JobConfig
- Submit job via JobManager
- Create Discord embed with job ID
- Return embed to user
- Create follow-up message for progress updates
</details>

<details>
<summary>8.4 Implement /scan stop Command</summary>

- Parameters: job_id: str
- Actions:
- Parse job_id
- Call JobManager.cancel_job()
- Update embed with cancellation status
</details>

<details>
<summary>8.5 Implement /scan status Command</summary>

- Parameters: None
- Actions:
- Get queue status from JobManager
- Format as Discord embed
- Show: pending, queued, running, paused, completed counts
</details>

<details>
<summary>8.6 Implement /scan progress Command</summary>

- Parameters: job_id: str
- Actions:
- Get job from storage
- Get progress data
- Format progress bars
- Include stats (discovered, processed, successful, failed)
- Include ETA if available
</details>

<details>
<summary>8.7 Implement /results Commands</summary>

- /results recent [limit: int]
- Fetch recent results from storage
- Paginate if > 25 results
- Format as table or list
- /results search ip: str
- Query by IP address
- Show matching results
- /results export job_id: str format: str
- Export results to JSON or CSV
- Upload as Discord file
</details>

<details>
<summary>8.8 Implement /cidr Commands</summary>

- /cidr add cidr: str
- Validate CIDR format
- Add to global CIDR list
- Return confirmation
- /cidr list
- Show all CIDRs
- Paginate if > 25
- /cidr remove id: int
- Remove CIDR by index
- Return confirmation
</details>

<details>
<summary>8.9 Implement /signature Commands</summary>

- /signature add type: str pattern: str
- Add custom fingerprint signature
- Validate pattern
- Store in DB
- /signature list
- Show all signatures
- Paginate if > 25
- /signature remove id: int
- Remove signature
- Return confirmation
</details>

<details>
<summary>8.10 Implement Background Progress Updates</summary>

- async progress_updater() -> None
- Background task
- Every 30 seconds:
    - Check running jobs
    - Update progress embeds
    - Edit follow-up messages
- Rate limiting:
- Discord API rate limits (50 edits per minute)
- Update job progress every 30s minimum
- Limit to 10 concurrent updates
</details>

<details>
<summary>8.11 Implement Event Handlers</summary>

- on_ready() - Log startup
- on_command_error() - Handle errors gracefully
- on_app_command_completion() - Log command usage
</details>

---
# Task 9: Create CLI for Testing

<details>
<summary>9.1 Create CLI Entry Point</summary>

- File: src/cli/job_cli.py (new)
- Use click or argparse
</details>

<details>
<summary>9.2 Implement CLI Commands</summary>

- job-cli submit --cidrs 10.0.0.0/8
- Submit job via JobManager
- Return job_id
- job-cli list
- List all jobs
- Show status
- job-cli status <job_id>
- Show detailed job status
- Show progress
- job-cli cancel <job_id>
- Cancel job
- job-cli results <job_id>
- Show job results
</details>

<details>
<summary>9.3 Implement Interactive Monitor</summary>

- job-cli monitor
- Real-time terminal UI
- Show running jobs
- Show progress bars
- Auto-refresh every 1s
</details>

---
# Task 10: Testing

<details>
<summary>10.1 Unit Tests</summary>

- File: tests/unit/test_job_manager.py
- Test job submission
- Test job cancellation
- Test state transitions
- Test queue operations
- File: tests/unit/test_resource_manager.py
- Test FD allocation
- Test concurrent job limits
- Test resource cleanup
- File: tests/unit/test_progress_tracker.py
- Test progress updates
- Test callback registration
- Test serialization
</details>

<details>
<summary>10.2 Integration Tests</summary>

- File: tests/integration/test_job_flow.py
- Test: submit → run → complete flow
- Test: pause → resume flow
- Test: cancel running job
- Test: multiple concurrent jobs
- Test: timeout handling
- Test: retry logic
</details>

<details>
<summary>10.3 Discord Integration Tests</summary>

- Manual testing with test bot
- Test all commands
- Test rate limiting
- Test embed formatting
</details>

---
# Task 11: Documentation

<details>
<summary>11.1 Update README.md</summary>

- Add Discord bot setup instructions
- Add JobManager architecture diagram
- Add configuration reference
</details>

<details>
<summary>11.2 Create Bot Setup Guide</summary>

- File: docs/bot_setup.md
- Discord app creation steps
- Bot token generation
- Required permissions
- Invite link generation
</details>

<details>
<summary>11.3 Create Configuration Reference</summary>

- File: docs/config_reference.md
- All configuration options
- Default values
- Tuning recommendations
</details>

<details>
<summary>11.4 Create API Documentation</summary>

- File: docs/job_manager_api.md
- All JobManager methods
- Parameter descriptions
- Return values
</details>

---
# Task 12: Deployment

<details>
<summary>12.1 Create Systemd Service</summary>

- File: deploy/camera-scan-bot.service
- Service definition
- Environment variables
- Restart policy
- Logging configuration
</details>

<details>
<summary>12.2 Create Docker Image (Optional)</summary>

- File: Dockerfile
- Multi-stage build
- Include masscan
- Include Python dependencies
</details>

<details>
<summary>12.3 Create Deployment Script</summary>

- File: deploy/deploy.sh
- Install dependencies
- Setup database
- Configure bot
- Start service
</details>

---
Summary

┌──────┬────────────────────┬──────────────────────────────────────────────────────────┐
│ Task │    Description     │                      Files Created                       │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 1    │ Job schemas and DB │ src/jobs/schemas.py, migration                           │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 2    │ JobManager core    │ src/jobs/manager.py                                      │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 3    │ Resource manager   │ src/jobs/resources.py                                    │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 4    │ Scanner service    │ src/jobs/scanner_service.py, src/scanner/orchestrator.py │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 5    │ Progress tracking  │ src/jobs/progress.py                                     │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 6    │ Timeout/retry      │ src/jobs/timeout.py                                      │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 7    │ Recovery           │ src/jobs/recovery.py                                     │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 8    │ Discord bot        │ src/bot/discord_bot.py                                   │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 9    │ CLI                │ src/cli/job_cli.py                                       │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 10   │ Testing            │ tests/unit/, tests/integration/                          │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 11   │ Documentation      │ docs/, updated README.md                                 │
├──────┼────────────────────┼──────────────────────────────────────────────────────────┤
│ 12   │ Deployment         │ deploy/                                                  │
└──────┴────────────────────┴──────────────────────────────────────────────────────────┘
