# NFQUEUE-Based OpenVPN Packet Filtering — Implementation Plan

## 1. Objective

Implement the NFQUEUE-based packet filtering system on the OpenVPN server.

The system will:

- Monitor NEW traffic from **DM IN** and **Controls IN**.
- Send monitored traffic from the Linux kernel to an NFQUEUE.
- Process queued packets in a Python userspace service.
- Extract the destination IP and check it against an in-memory whitelist.
- `NF_ACCEPT` whitelisted destinations.
- `NF_DROP` non-whitelisted destinations.
- Keep **DM EU management/API traffic always reachable** through kernel-level rules.
- Persist whitelist entries in SQLite using WAL mode.
- Dynamically reload the in-memory cache when whitelist entries change.
- Fail closed when the filtering service is unavailable or overloaded.
- Provide authentication, authorization, logging, metrics, monitoring, and recovery.

---

# 2. High-Level Architecture

```text
                         MANAGEMENT PLANE
                              |
                              v
                         DM EU / REST API
                              |
                              v
                        SQLite Database
                              |
                       Cache Reload Signal
                              |
                              v

DM IN / Controls IN
        |
        v
+-----------------------+
| Linux Kernel          |
|                       |
| iptables FORWARD      |
|                       |
| ESTABLISHED/RELATED --> ACCEPT
| DM EU API -----------> ACCEPT
| DM IN NEW ------------\
| Controls IN NEW -------+--> NFQUEUE #5
+-----------------------+
                              |
                              v
                    +----------------------+
                    | Python Userspace     |
                    |                      |
                    | NFQUEUE Reader       |
                    | Async Workers        |
                    | IP Classifier        |
                    | Whitelist Cache      |
                    | Verdict Manager      |
                    +----------------------+
                       |              |
                   ACCEPT            DROP
                       |              |
                       v              X
                  Forwarded        Blocked
                   Traffic
```

---

# 3. Work Breakdown

The implementation is intentionally divided into **10 major subtasks** rather than many small tickets. Each subtask represents a meaningful development phase and can contain internal engineering tasks as needed.

---

## TASK-01 — Environment & Technical Prerequisites

### Description

Prepare and validate the OpenVPN server environment required for the implementation.

This includes:

- Understanding the existing OpenVPN interfaces and routes.
- Identifying DM IN, Controls IN, and DM EU addresses.
- Verifying Linux IP forwarding.
- Verifying iptables/netfilter availability.
- Verifying conntrack support.
- Verifying NFQUEUE kernel support.
- Verifying Python and asyncio runtime.
- Identifying required Linux capabilities.
- Documenting existing firewall rules before making changes.

### Deliverables

- Environment/prerequisite document.
- Current network and firewall configuration.
- Required configuration values.
- Rollback approach for firewall changes.

### Acceptance Criteria

- NFQUEUE functionality is confirmed on the target host.
- OpenVPN traffic paths are understood.
- Existing firewall configuration is captured.
- Required dependencies are identified.

---

# TASK-02 — Linux Kernel Space / iptables & NFQUEUE

### Description

Implement the complete kernel-side packet classification and NFQUEUE integration.

The `FORWARD` chain should follow this logical order:

```text
1. ESTABLISHED,RELATED
       |
       +--> ACCEPT

2. DM EU → API
       |
       +--> ACCEPT

3. DM IN → NEW
       |
       +--> NFQUEUE #5

4. Controls IN → NEW
       |
       +--> NFQUEUE #5

5. Other traffic
       |
       +--> Normal/default handling
```

The implementation must intentionally **not use `--queue-bypass`**, because the design requires fail-closed behavior.

Also include kernel-level protection against excessive traffic where required:

- NFQUEUE queue sizing.
- Per-source packet-rate limiting.
- New-connection limiting.
- Appropriate socket/buffer configuration.

### Deliverables

- iptables configuration.
- Firewall setup script.
- Firewall teardown/rollback script.
- NFQUEUE configuration.
- Kernel-level rate/connection limiting.

### Acceptance Criteria

- DM IN NEW traffic reaches NFQUEUE.
- Controls IN NEW traffic reaches NFQUEUE.
- ESTABLISHED/RELATED traffic bypasses NFQUEUE.
- DM EU API traffic bypasses NFQUEUE.
- Monitored traffic is dropped when NFQUEUE userspace processing is unavailable.
- Existing unrelated traffic is not unintentionally affected.

---

# TASK-03 — Python Userspace Packet Filtering Engine

### Description

Implement the Python service responsible for processing packets received from NFQUEUE.

The userspace flow should be:

```text
NFQUEUE
   |
   v
Queue Reader
   |
   v
Bounded asyncio Queue
   |
   v
Async Worker Pool
   |
   v
Extract destination IP
   |
   v
Check whitelist cache
   |
   +------ YES ------> NF_ACCEPT
   |
   +------ NO -------> NF_DROP
```

The service should contain:

- NFQUEUE listener.
- Non-blocking packet ingestion.
- Bounded internal queue.
- Configurable async worker pool.
- IPv4 destination extraction.
- Verdict manager.
- Processing counters.

The packet path must not query SQLite for every packet.

### Deliverables

- Python NFQUEUE service.
- Async queue/worker implementation.
- Packet classifier.
- Verdict manager.
- Basic service configuration.

### Acceptance Criteria

- Packets are successfully received from NFQUEUE.
- Destination IP is extracted correctly.
- Whitelisted destinations receive `NF_ACCEPT`.
- Non-whitelisted destinations receive `NF_DROP`.
- Each packet receives a verdict.
- Packet processing does not perform database queries.

---

# TASK-04 — SQLite Database, Whitelist Cache & Cache Reload

### Description

Implement persistent whitelist storage and the in-memory cache used by the packet filter.

### Database

Create the whitelist storage containing information such as:

- ID.
- Destination IP.
- Label.
- Active/disabled state.
- Created/updated timestamps.

Also maintain an append-only audit history for whitelist changes.

Configure SQLite for the expected access pattern:

- WAL mode.
- Appropriate busy timeout.
- `synchronous=NORMAL`.
- Safe transaction handling.
- Application-level write serialization where required.

### Cache

Maintain:

```python
allowed_ips = set(...)
```

The packet-processing path performs:

```python
if dst_ip in allowed_ips:
    ACCEPT
else:
    DROP
```

Cache behavior:

```text
Application startup
       |
       v
Load active IPs from DB
       |
       v
Create new Python set
       |
       v
Atomically replace current cache
```

Whitelist changes must trigger a reload **only after the database transaction succeeds**.

### Deliverables

- SQLite schema.
- Database access layer.
- WAL configuration.
- In-memory whitelist cache.
- Startup cache loading.
- Atomic cache reload.
- Cache reload mechanism.

### Acceptance Criteria

- Whitelist entries persist across service restarts.
- Duplicate destination IPs are prevented.
- Packet processing uses the in-memory set.
- Cache reload does not expose a partially loaded whitelist.
- Failed reload keeps the previous valid cache.
- Whitelist changes trigger reload after successful DB commit.

---

# TASK-05 — Whitelist Management REST APIs

### Description

Implement the management API used by DM EU to maintain the destination whitelist.

Required endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/whitelist` | Add destination IP |
| DELETE | `/api/v1/whitelist/{id}` | Remove destination |
| GET | `/api/v1/whitelist` | List whitelist |
| PUT | `/api/v1/whitelist/{id}` | Enable/disable entry |
| GET | `/api/v1/health` | Service health |
| GET | `/api/v1/stats` | Processing statistics |
| POST | `/api/v1/cache/reload` | Force cache reload |

The API should update the database first and then signal the filtering service to reload its cache.

### Deliverables

- REST endpoints.
- Request/response models.
- IP validation.
- Database integration.
- Cache reload integration.
- API error handling.

### Acceptance Criteria

- DM EU can add/remove/update whitelist entries.
- Invalid IP addresses are rejected.
- Database state is updated correctly.
- Audit records are generated.
- Cache reload happens after successful changes.
- Health and statistics endpoints work.

---

# TASK-06 — API Security, Authorization & Audit

### Description

Secure the management plane so only authorized DM EU requests can modify the whitelist.

Implement:

- DM EU source-IP allowlisting.
- API authentication.
- Authorization for management operations.
- Input validation.
- Request correlation IDs.
- Security audit logging.
- Protection against unauthorized whitelist changes.

The security model should ensure that knowing the API endpoint alone is insufficient to modify the whitelist.

### Deliverables

- Authentication mechanism.
- DM EU IP restriction.
- Authorization checks.
- Security event logging.
- Audit trail.

### Acceptance Criteria

- Unauthorized IPs cannot modify the whitelist.
- Invalid credentials are rejected.
- Successful mutations are auditable.
- Security failures are logged.
- Secrets are not exposed in source code or logs.

---

# TASK-07 — Backpressure, DoS Protection & Fail-Closed Handling

### Description

Implement overload protection at both kernel and userspace levels.

The system should handle:

```text
Normal traffic
     |
     v
Normal processing

High traffic
     |
     v
Rate limiting / warning

Userspace queue full
     |
     v
Drop new packets

Filter process unavailable
     |
     v
Monitored traffic dropped
```

Implement/configure:

- Kernel packet rate limiting.
- New connection limiting.
- NFQUEUE sizing.
- Userspace bounded queue.
- Queue high-watermark monitoring.
- Userspace per-source rate limiting where required.
- Overload statistics.

### Deliverables

- Kernel rate limits.
- Userspace backpressure handling.
- Queue monitoring.
- Overload counters/logs.
- Fail-closed behavior.

### Acceptance Criteria

- Queue cannot grow without limit.
- Memory usage remains bounded.
- Excess traffic does not bring down the filtering service.
- New monitored traffic is dropped when the filter cannot process it.
- DM EU management traffic remains available.

---

# TASK-08 — systemd, Process Management & Least Privilege

### Description

Package the filter service as a managed Linux service.

Configure:

- Automatic restart.
- Restart delay.
- Watchdog.
- CPU limits.
- Memory limits.
- Required network capabilities.
- Startup ordering.
- Firewall initialization.
- Clean shutdown behavior.

The service should run with the minimum Linux capabilities required for NFQUEUE operation rather than unrestricted root privileges.

### Deliverables

- systemd service file.
- Service startup configuration.
- Resource limits.
- Watchdog configuration.
- Linux capability configuration.
- Startup/shutdown ordering.

### Acceptance Criteria

- Service starts automatically.
- Service restarts after failure.
- Watchdog detects an unhealthy process.
- CPU/memory limits are enforced.
- Required NFQUEUE functionality works with configured capabilities.
- Firewall rules are initialized correctly during startup.

---

# TASK-09 — Logging, Metrics & Operational Monitoring

### Description

Implement observability for both the packet filtering path and management plane.

Capture important events such as:

- Accepted packets.
- Dropped packets.
- Queue depth.
- Queue overflow.
- Rate limiting.
- Cache reloads.
- Cache reload failures.
- API requests.
- Authentication failures.
- Database failures.
- Service restarts.
- Filter health.

Prefer structured JSON logs so they can be consumed by the existing logging/monitoring stack.

### Deliverables

- Structured JSON logs.
- Packet-processing metrics.
- Queue metrics.
- Cache metrics.
- API metrics.
- Health endpoint.
- Operational alerts.

### Acceptance Criteria

- Operators can determine whether the filter is healthy.
- Packet drops can be investigated.
- Queue saturation can be detected.
- Cache reload failures can be detected.
- Service crashes/restarts are observable.

---

# TASK-10 — End-to-End Testing, Performance & Failure Validation

### Description

Perform the complete functional, security, failure-recovery, and performance validation of the implementation.

### Functional scenarios

```text
DM IN
  |
  +--> Whitelisted destination       ACCEPT
  |
  +--> Non-whitelisted destination   DROP

Controls IN
  |
  +--> Whitelisted destination       ACCEPT
  |
  +--> Non-whitelisted destination   DROP

DM EU
  |
  +--> Management API                ALWAYS ACCESSIBLE
```

### Failure scenarios

Test:

- Python filter process crash.
- NFQUEUE unavailable.
- Userspace queue overflow.
- Kernel queue overflow.
- SQLite lock contention.
- Cache reload failure.
- Database failure.
- Service restart.
- Unauthorized API access.
- Invalid whitelist entries.

### Performance scenarios

Measure:

- Packet verdict throughput.
- p99 packet-processing latency.
- Queue utilization.
- CPU usage.
- Memory usage.
- Cache reload duration.
- Service startup/recovery time.
- Sustained traffic for at least one hour.

The performance targets from the design should be validated rather than assumed:

| Metric | Target |
|---|---:|
| Packet verdict throughput | > 50,000/sec |
| Throughput during cache reload | > 10,000/sec |
| Verdict latency | < 1 ms p99 |
| Startup to first verdict | < 2 sec |
| Crash recovery | < 3 sec |
| Reload of 1,000 IPs | < 100 ms |

### Deliverables

- Test plan.
- Test execution results.
- Performance results.
- Failure/recovery results.
- Security test results.
- Defect list and remediation.
- Final acceptance report.

### Acceptance Criteria

- All critical traffic-flow scenarios pass.
- Fail-closed behavior is verified.
- DM EU remains reachable during filter failure/overload.
- Performance targets are measured.
- No critical security or reliability issues remain.

---

# 4. Recommended Implementation Sequence

The work should be executed in this order:

```text
TASK-01
Environment & Prerequisites
        |
        v
TASK-02
Kernel Space / iptables / NFQUEUE
        |
        v
TASK-03
Python Userspace Filtering
        |
        v
TASK-04
SQLite + Cache
        |
        v
TASK-05
REST APIs
        |
        v
TASK-06
Security & Authorization
        |
        v
TASK-07
DoS / Backpressure / Fail-Closed
        |
        v
TASK-08
systemd & Least Privilege
        |
        v
TASK-09
Logging & Monitoring
        |
        v
TASK-10
Testing / Performance / Failure Validation
```

This ordering is intentional: first prove the **Linux kernel → NFQUEUE → Python → ACCEPT/DROP** path, then add persistence and management APIs, and finally add production hardening and validation.

---

# 5. Suggested Jira Epics

If you want to represent these as Jira work items, the 10 tasks can be grouped into approximately **5 epics**:

### Epic 1 — Packet Filtering Infrastructure

- TASK-01 — Environment & Technical Prerequisites
- TASK-02 — Linux Kernel Space / iptables & NFQUEUE
- TASK-03 — Python Userspace Packet Filtering Engine

### Epic 2 — Whitelist Management

- TASK-04 — SQLite Database, Whitelist Cache & Cache Reload
- TASK-05 — Whitelist Management REST APIs
- TASK-06 — API Security, Authorization & Audit

### Epic 3 — Production Hardening

- TASK-07 — Backpressure, DoS Protection & Fail-Closed Handling
- TASK-08 — systemd, Process Management & Least Privilege

### Epic 4 — Observability

- TASK-09 — Logging, Metrics & Operational Monitoring

### Epic 5 — Validation

- TASK-10 — End-to-End Testing, Performance & Failure Validation

---

# 6. Definition of Done

The project is complete when:

- [ ] Kernel rules correctly classify monitored traffic.
- [ ] DM IN and Controls IN NEW traffic reaches NFQUEUE.
- [ ] ESTABLISHED/RELATED traffic bypasses NFQUEUE.
- [ ] DM EU API traffic always bypasses NFQUEUE.
- [ ] Python service correctly extracts destination IPs.
- [ ] Whitelisted destinations are accepted.
- [ ] Non-whitelisted destinations are dropped.
- [ ] SQLite persistence works with WAL mode.
- [ ] In-memory cache is used for packet decisions.
- [ ] Cache reload is atomic.
- [ ] REST APIs can manage the whitelist.
- [ ] API is restricted to authorized DM EU access.
- [ ] Audit history is maintained.
- [ ] Backpressure and DoS protection are implemented.
- [ ] Filter failure results in fail-closed behavior.
- [ ] systemd automatically recovers the service.
- [ ] Required Linux capabilities are configured.
- [ ] Logs and metrics are available.
- [ ] Functional, security, failure, and performance testing is completed.
- [ ] Deployment and rollback procedures are documented.
