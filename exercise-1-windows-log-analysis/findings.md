# Exercise 1 — Windows Failed Logon Analysis
## Detailed Findings

**Analyst:** Nida Nadeem  
**Date:** 28 August 2026  
**Tool:** Event Viewer (`eventvwr.msc`) → Windows Logs → Security  
**Environment:** Windows 11 Enterprise (Evaluation) in VirtualBox

---

## 1. How the Event Was Generated

The 4625 event was intentionally triggered in a controlled lab setting:
- VM was locked using `Win+L`
- An incorrect password was entered once
- The correct password was then entered to unlock

This simulates the most common real-world source of 4625 events — a user mistyping their own password — and provides a clean baseline for understanding what a non-malicious failed logon looks like before analysing suspicious ones.

---

## 2. Event Viewer Navigation

Path used to locate the events:
```
Event Viewer (Local)
  └── Windows Logs
        └── Security
```

Filter applied: **Filter Current Log → Event ID: 4625**

This narrows the Security log (which can contain thousands of events) down to only failed logon attempts, making triage faster. In a real environment with high log volume, this filter would be applied inside a SIEM rather than Event Viewer directly.

---

## 3. Full Field Breakdown — 4625 Event

### General Tab

| Field | Value | What It Means |
|-------|-------|---------------|
| Log Name | Security | Correct log — all logon events live here |
| Source | Microsoft Windows security auditing | Expected source for auth events |
| Event ID | 4625 | Failed logon |
| Level | Information | Windows logs all auth events as Information regardless of whether they indicate an attack |
| Task Category | Logon | Confirms this is a logon-related event |
| Keywords | Audit Failure | Distinguishes failed attempts from successful ones (Audit Success) |
| Logged | 8/28/2026 7:10:56 PM | Timestamp — used for correlation with other events |
| Computer | DESKTOP-7DNCR26 | The machine where the attempt occurred |

### Subject Fields (Who requested the logon)

| Field | Value | What It Means |
|-------|-------|---------------|
| Security ID | SYSTEM | The OS itself is logging this on behalf of the logon process |
| Account Name | DESKTOP-7DNCR26$ | The machine account, not a user — expected for local auth |
| Account Domain | WORKGROUP | Workgroup environment, not domain-joined |
| Logon ID | 0x3E7 | SYSTEM logon session — standard for local machine processes |

### Account For Which Logon Failed

| Field | Value | What It Means |
|-------|-------|---------------|
| Security ID | NULL SID | No SID assigned because authentication failed before account lookup completed |
| Account Name | Nida | The actual username that was attempted — a real local account |
| Account Domain | DESKTOP-7DNCR26 | Local machine domain — confirms this is a local account attempt |

### Failure Information

| Field | Value | What It Means |
|-------|-------|---------------|
| Failure Reason | Unknown user name or bad password | Most common value — wrong password entered |
| Status | 0xC000006D | NTSTATUS code for "wrong username or password" |
| Sub Status | 0xC000006A | Specifically means the password was wrong (username was valid) — useful for distinguishing "account doesn't exist" from "wrong password" |

> **Sub Status detail:** 0xC000006A confirms the account *Nida* exists but the password was incorrect. If the account didn't exist, Sub Status would be 0xC0000064. This distinction matters — targeting a non-existent account suggests enumeration; targeting a real account with wrong passwords suggests brute-force.

### Logon Type Breakdown

| Type Code | Meaning | Attack Relevance |
|-----------|---------|-----------------|
| 2 | Interactive (local, physical) | Low concern — user at the machine |
| 3 | Network | Medium — remote file share, lateral movement |
| 4 | Batch | Service accounts, scheduled tasks |
| 5 | Service | Windows services logging on |
| 7 | Unlock | Screen unlock — same as this event |
| 10 | RemoteInteractive (RDP) | **High concern** — RDP is a common attack vector |

This event: **Type 2** — lowest concern category.

### Network Information

| Field | Value | What It Means |
|-------|-------|---------------|
| Workstation Name | DESKTOP-7DNCR26 | Same machine as the target — local attempt |
| Source Network Address | 127.0.0.1 | Loopback — definitively confirms local origin |
| Source Port | 0 | No network port involved — local auth process |

### Process Information

| Field | Value | What It Means |
|-------|-------|---------------|
| Caller Process ID | 0x59c | Process that initiated the logon request |
| Caller Process Name | `C:\Windows\System32\svchost.exe` | Windows host process — expected for local authentication |

---

## 4. Verdict and Reasoning

**Classification: Routine human error — no incident**

Three fields together close the case:
1. **Logon Type 2** — physical/local attempt, not remote
2. **Source Address 127.0.0.1** — loopback, same machine
3. **Sub Status 0xC000006A** — correct account, wrong password (not enumeration)

All three point in the same direction. A single 4625 event with these values, from a known user account on their own machine, requires no further action.

---

## 5. When This Same Event Would Be an Incident

The identical event structure becomes suspicious when any of these change:

| Change | Why It Matters |
|--------|---------------|
| Logon Type → 10 (RDP) | External RDP brute-force is one of the most common initial access methods |
| Source Address → external IP | Confirms the attempt originates outside the network |
| Account Name → "admin", "administrator", "root" | Suggests automated enumeration, not a real user mistyping |
| Multiple 4625s within seconds | Automated brute-force — humans can't type that fast |
| Same source IP targeting multiple accounts | Password spraying — one password tried across many accounts to avoid lockout |
| 4625 spike followed by a 4624 | Brute-force succeeded — highest priority alert |

---

## 6. Detection Logic (How a SIEM Would Alert on This)

A basic Splunk search to catch brute-force patterns from this data:

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address, Logon_Type
| where count > 5
| sort -count
```

This surfaces any account with more than 5 failed logons grouped by source — the starting point for a brute-force investigation.

---

## 7. Screenshots Reference

| Screenshot | What It Shows |
|-----------|---------------|
| `event-viewer-overview.png` | Security log open, list of events visible |
| `event-4624-details.png` | Successful logon properties — Account Name, Logon Type, timestamp |
| `event-4625-overview.png` | Failed logon Subject fields and Account For Which Logon Failed |
| `event-4625-failure-info.png` | Failure Reason, Status, Sub Status, Network Information |
| `event-4625-auth-details.png` | Detailed Authentication Information — Logon Process, Auth Package |
