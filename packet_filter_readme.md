# Linux Firewall & NFQUEUE Script

This project contains a single Bash script (`packet_filter.sh`) that configures Linux `iptables` to forward selected packets to a Python application through **NFQUEUE**.

The script provides the following commands:

```bash
sudo ./packet_filter.sh setup
sudo ./packet_filter.sh status
sudo ./packet_filter.sh remove
sudo ./packet_filter.sh restore <backup-file>
```

---

# Prerequisites

- Linux with `iptables`
- Root or sudo access
- `nf_conntrack` kernel module
- `nfnetlink_queue` kernel module
- Python packet filtering application (to consume NFQUEUE packets)

---

# Script Overview

The script performs the following tasks:

- Enables IPv4 forwarding
- Loads required kernel modules
- Creates a dedicated `PACKET_FILTER` chain and attaches it to `FORWARD`
- Creates a dedicated `PACKET_FILTER_INPUT` chain and attaches it to `INPUT`
- Configures firewall rules, including DoS protection (hashlimit + connlimit)
- Detects the local OpenVPN server IP from `/etc/openvpn/server.conf`
- Restricts the whitelist API manager (port 8000) so only DM EU and the
  local OpenVPN server can reach it
- Sends selected packets to NFQUEUE
- Creates firewall backups
- Allows restoring previous firewall configurations
- Displays firewall status
- Removes only the rules created by this script

---

# Commands

## 1. Setup Firewall

Command

```bash
sudo ./packet_filter.sh setup
```

### Purpose

Configures the firewall for packet filtering.

### What it does

1. Checks if the script is running as root.
2. Detects the OpenVPN server IP from `/etc/openvpn/server.conf`.
3. Prompts for configuration (DM IN, Controls IN, DM EU, OpenVPN server, API port, NFQUEUE number).
4. Verifies required commands are installed.
5. Loads required kernel modules.
6. Enables IPv4 forwarding.
7. Creates a firewall backup.
8. Creates the `PACKET_FILTER` chain and attaches it to `FORWARD`.
9. Creates the `PACKET_FILTER_INPUT` chain and attaches it to `INPUT`.
10. Clears any existing rules in both custom chains.
11. Adds all `FORWARD`-side packet filtering rules (established/related, DM EU API, DM IN → DM EU, DoS protection, NFQUEUE, logging, return).
12. Adds `INPUT`-side rules restricting the whitelist API manager (port 8000) to DM EU and the local OpenVPN server.
13. Displays the final firewall configuration.

---

## 2. Check Firewall Status

Command

```bash
sudo ./packet_filter.sh status
```

### Purpose

Displays the current firewall configuration.

### Output includes

- PACKET_FILTER chain
- FORWARD chain
- PACKET_FILTER_INPUT chain
- INPUT chain
- Packet counters
- Loaded kernel modules
- IPv4 forwarding status

Useful while debugging.

---

## 3. Remove Firewall

Command

```bash
sudo ./packet_filter.sh remove
```

### Purpose

Safely removes all firewall rules added by this project.

### What it removes

- Jump from FORWARD
- All PACKET_FILTER rules
- PACKET_FILTER chain
- Jump from INPUT
- All PACKET_FILTER_INPUT rules
- PACKET_FILTER_INPUT chain

### What it does NOT remove

- Docker rules
- Kubernetes rules
- OpenVPN rules
- Any other system firewall rules

---

## 4. Restore Previous Firewall

Command

```bash
sudo ./packet_filter.sh restore /var/backups/iptables-YYYYMMDD-HHMMSS.rules
```

### Purpose

Restores the firewall to a previously backed-up state.

Useful if something goes wrong during testing.

---

# Firewall Rule Flow

```
FORWARD
    │
    ▼
PACKET_FILTER
    │
    ├── ACCEPT ESTABLISHED,RELATED
    │
    ├── ACCEPT DM EU API
    │
    ├── ACCEPT DM IN → DM EU (always)
    │
    ├── DROP  (hashlimit: NEW connections above rate)
    │
    ├── DROP  (connlimit: too many concurrent TCP connections)
    │
    ├── NFQUEUE DM IN
    │
    ├── NFQUEUE Controls IN
    │
    ├── LOG (rate limited)
    │
    └── RETURN
```

```
INPUT
    │
    ▼
PACKET_FILTER_INPUT   (restricts whitelist API manager, port 8000)
    │
    ├── ACCEPT  DM EU → API_PORT
    │
    ├── ACCEPT  OpenVPN server → API_PORT
    │
    ├── DROP    everyone else → API_PORT
    │
    └── RETURN
```

---

# Rule Explanation

## Rule 1

```
ESTABLISHED,RELATED → ACCEPT
```

### Purpose

Allows packets belonging to already approved connections.

Example

```
PC -----> Server
      SYN

Approved

↓

All future packets bypass NFQUEUE
```

Benefits

- Faster
- Lower CPU usage
- Less latency

---

## Rule 2

```
DM EU API → ACCEPT
```

Allows the management server to communicate with the whitelist API.

These packets never enter NFQUEUE.

---

## Rule 2b

```
DM IN → DM EU → ACCEPT
```

Always allows DM IN to reach DM EU, on any protocol/port, so DM is never
locked out of reaching its own management API by the whitelist/NFQUEUE
rules below.

---

## DoS Protection: Hashlimit

```
NEW connections above rate → DROP
```

Limits NEW connections per source IP using `hashlimit` (default: 100/second,
burst 200). Only traffic exceeding the rate is dropped here; traffic within
the limit falls through to the NFQUEUE rules below.

---

## DoS Protection: Connlimit

```
Too many concurrent TCP connections → DROP
```

Limits the number of simultaneous TCP connections per source IP (default:
500).

---

## Rule 3

```
DM IN → NFQUEUE
```

Every NEW connection from DM IN is sent to Python.

Python decides

```
ACCEPT

or

DROP
```

---

## Rule 4

```
Controls IN → NFQUEUE
```

Same behavior as DM IN.

---

## Logging

```
LOG (rate limited)
```

Logs packets that reach the end of the `PACKET_FILTER` chain, prefixed with
`[PACKET_FILTER]`. Limited to 10/minute (burst 20) to avoid flooding kernel
logs.

---

## RETURN

```
RETURN
```

Returns packet processing to the original FORWARD chain.

This prevents interference with other firewall rules.

---

## INPUT Rule 1

```
DM EU → API_PORT → ACCEPT
```

Allows DM EU to reach the whitelist API manager (port 8000) running on this
host.

---

## INPUT Rule 1b

```
OpenVPN server → API_PORT → ACCEPT
```

Allows the local OpenVPN server (its tun0 IP, detected from the `server`
directive in `/etc/openvpn/server.conf`, or entered manually if not found)
to reach the whitelist API manager. Skipped if no server IP is available.

---

## INPUT Rule 2

```
Any client → API_PORT → DROP
```

Blocks every other client from reaching the whitelist API manager. This
rule must come after INPUT Rule 1 and 1b so DM EU's and the OpenVPN
server's traffic matches first.

---

## INPUT RETURN

```
RETURN
```

Returns packet processing to the original INPUT chain for all other
traffic/ports.

---

# Why Use a Custom Chain?

Instead of placing rules directly into FORWARD

```
FORWARD

Rule 1
Rule 2
Rule 3
Rule 4
```

we create

```
FORWARD
      │
      ▼
PACKET_FILTER
```

Benefits

- Easier maintenance
- Easier removal
- Cleaner firewall
- Doesn't interfere with Docker/Kubernetes/OpenVPN rules

---

# Kernel Modules

The script loads:

## nf_conntrack

Tracks network connections.

Allows rules like

```
ESTABLISHED

RELATED
```

---

## nfnetlink_queue

Provides communication between

```
Linux Kernel

↓

NFQUEUE

↓

Python Userspace
```

Without this module,

```
-j NFQUEUE
```

will not work.

---

# Firewall Backup

Every execution of

```bash
setup
```

creates a backup

Example

```
/var/backups/iptables-20260812-101530.rules
```

Restore using

```bash
sudo ./packet_filter.sh restore <backup-file>
```

---

# Packet Flow

```
Incoming Packet

↓

FORWARD

↓

PACKET_FILTER

↓

Already established?

YES
↓

ACCEPT

NO

↓

DM EU API?

YES
↓

ACCEPT

NO

↓

DM IN → DM EU?

YES
↓

ACCEPT

NO

↓

Above rate/connection limit?

YES
↓

DROP

NO

↓

DM IN or Controls?

↓

NFQUEUE

↓

Python Application

↓

ACCEPT
or
DROP
```

---

# Whitelist API Manager Access (INPUT chain)

```
Incoming Packet (destined to this host)

↓

INPUT

↓

PACKET_FILTER_INPUT

↓

Destination port = API_PORT (8000)?

NO
↓

RETURN → normal INPUT processing

YES

↓

Source = DM EU or OpenVPN server?

YES
↓

ACCEPT

NO

↓

DROP
```

---

# Useful iptables Commands

## List Rules

```bash
sudo iptables -L -n -v
```

Shows

- packet counters
- byte counters
- chain order

---

## List FORWARD Chain

```bash
sudo iptables -L FORWARD -n -v --line-numbers
```

---

## List Custom Chain

```bash
sudo iptables -L PACKET_FILTER -n -v --line-numbers
```

---

## Save Firewall

```bash
sudo iptables-save
```

---

## Restore Firewall

```bash
sudo iptables-restore < backup.rules
```

---

# Troubleshooting

## Permission denied

Run using

```bash
sudo ./packet_filter.sh setup
```

---

## NFQUEUE not working

Check modules

```bash
lsmod | grep nf
```

Expected

```
nf_conntrack

nfnetlink_queue
```

---

## Verify IP forwarding

```bash
sysctl net.ipv4.ip_forward
```

Expected

```
net.ipv4.ip_forward = 1
```

---

## View packet counters

```bash
sudo iptables -L PACKET_FILTER -n -v
```

If counters increase, packets are reaching the firewall rules.

---

# Cleanup

To completely remove the configuration

```bash
sudo ./packet_filter.sh remove
```

To restore the previous firewall

```bash
sudo ./packet_filter.sh restore /path/to/backup.rules
```

---

# Notes

- The script is **idempotent**—running `setup` multiple times will not create duplicate rules.
- Firewall changes affect only the custom `PACKET_FILTER` chain and its jump from `FORWARD`.
- Existing firewall rules managed by Docker, Kubernetes, OpenVPN, or other applications remain untouched.
- This script configures the kernel side only. A userspace application must be running and attached to the configured NFQUEUE to inspect and return verdicts for queued packets.