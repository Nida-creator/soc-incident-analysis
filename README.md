# Log & Incident Analysis — SOC Analyst Portfolio

**Author:** Nida Nadeem  
**Tools:** Windows Event Viewer, VirusTotal  
**Environment:** Windows 11 Enterprise (VirtualBox lab)  
**Completed:** August–September 2026

---

## Overview

Two independent incident analysis exercises completed as part of a structured SOC Analyst internship. Each exercise follows the triage workflow an L1 analyst would apply in a real environment: identify the event, pull the relevant fields, interpret what they mean, and reach a verdict.

---

## Exercise 1 — Windows Failed Logon Analysis (Event ID 4625)

### Objective
Analyse Windows Security event logs to distinguish routine logon errors from indicators of brute-force or credential-stuffing activity.

### Environment
- Windows 11 Enterprise (Evaluation) running in VirtualBox
- Tool: Event Viewer (`eventvwr.msc`) → Windows Logs → Security

### Key Event IDs Referenced

| Event ID | Name | SOC Relevance |
|----------|------|---------------|
| 4624 | Successful logon | Baseline for normal access; unusual logon types or times are red flags |
| 4625 | Failed logon | Core signal for brute-force and password guessing; spikes from one account or source are classic attack indicators |
| 4688 | Process created | Reveals exactly what ran on a machine; critical for spotting malware or suspicious command-line activity |
| 4720 | User account created | Unexpected new accounts are a common attacker persistence technique |
| 4732 | Member added to security group | Privilege escalation often appears here first |

### What Was Done
1. Filtered the Security log for Event ID 4624 (successful logon) and confirmed the account name, logon type, and timestamp matched an actual interactive login on the VM.
2. Generated a controlled 4625 event by locking the VM (`Win+L`) and entering an incorrect password once before unlocking correctly.
3. Located the resulting 4625 event and reviewed it field by field.

### Field-by-Field Analysis of the 4625 Event

| Field | Value Observed | Interpretation |
|-------|---------------|----------------|
| Account Name | Nida | Real local account targeted — not a guess at a default name like "admin" |
| Failure Reason | Unknown user name or bad password | Simple wrong-password attempt; no lockout or policy restriction involved |
| Logon Type | 2 (Interactive) | Physical/local attempt — lower concern than Type 3 (network) or Type 10 (RDP) |
| Source Network Address | 127.0.0.1 | Local machine origin — confirms user error, not an external attacker |
| Workstation Name | DESKTOP-7DNCR26 | Matches the local machine — consistent with the local source address |
| Caller Process | `C:\Windows\System32\svchost.exe` | Expected for a local authentication request |

### Verdict
**Routine human error — no incident.** The logon type (2 = interactive/local) and source address (127.0.0.1 = same machine) together confirm this was the user mistyping their own password, not an external attacker. 

In a real environment, the same event would warrant investigation if:
- Logon Type were **3 (network)** or **10 (RDP)** with an unknown source IP
- Multiple 4625 events occurred in rapid succession from one source (brute-force signature)
- The targeted account name were a generic default (`admin`, `administrator`) suggesting enumeration

### Key Takeaways
- **Logon Type is the single most important triage field.** Local (2) is low concern by default; network (3) or RDP (10) from an unknown source warrants immediate investigation.
- A spike in 4625 events for one account, or one account attempted across many source addresses, is the classic signature of brute-force or password-spraying activity.
- Event IDs 4688 (process creation) and 4720/4732 (account and group changes) extend visibility beyond logons into what an attacker did *after* gaining access.

---

## Exercise 2 — Phishing Email Header Analysis

### Objective
Triage a suspected phishing email using header analysis, authentication check results (SPF/DKIM), and safe URL investigation via VirusTotal — without clicking any link directly.

### Sample Email Analysed
```
Subject:   URGENT: Your account will be suspended in 24 hours
From:      "IT Support Desk" <support@paypa1-security.com>
Reply-To:  helpdesk-support@paypa1-security.com
Return-Path: bounce@mkt-relay03.ru-hosting.net
To:        employee@company.com
Body:      Urgency lure + "Verify Account" button → hxxp://bit[.]ly/3xAmpleLink
Attachment: Account_Statement.html
```

### Header Analysis

| Header Field | Value | Finding |
|-------------|-------|---------|
| From (display name) | "IT Support Desk" `<support@paypa1-security.com>` | Display name impersonates a trusted internal source; actual domain uses `1` instead of `l` — classic typosquat |
| Return-Path | `bounce@mkt-relay03.ru-hosting.net` | Completely different domain from the From address; legitimate IT mail would have a Return-Path matching the sending organisation's own domain |
| Reply-To | `helpdesk-support@paypa1-security.com` | Matches the spoofed From domain, not the Return-Path; attackers set this to whatever address they actually monitor |
| SPF | softfail | Sending server not authorised to send mail for the claimed domain — strong spoofing signal |
| DKIM | fail / not signed | Message authenticity cannot be verified; legitimate corporate mail almost always passes DKIM |

### URL Investigation (VirusTotal)
The embedded link was pasted directly into VirusTotal — the live page was never opened in a browser. VirusTotal flagged the URL as **malicious** across multiple vendor engines including BitDefender, Kaspersky, Sophos, Webroot, Google Safe Browsing, and others.

> Safe practice: always sandbox or submit URLs to VirusTotal rather than clicking directly. The analyst's machine should never touch a suspected phishing page.

### Red Flags Summary

| Red Flag | Where It Appears |
|----------|-----------------|
| Urgency / fear language | "Your account will be suspended in 24 hours; verify now" — pressures the recipient into acting before thinking |
| Lookalike / typosquat domain | `paypa1-security.com` — `1` substituted for `l` to impersonate a trusted brand |
| Generic greeting | "Dear Customer" — legitimate account notices address the user by name |
| Obfuscated embedded link | "Verify Account" button points to a shortened URL hiding the true destination |
| Suspicious attachment | `.html` file claiming to be an "account statement" — unusual and risky format |
| Authentication failures | SPF softfail + DKIM fail together technically confirm what the visual flags suggest |

### Verdict
**PHISHING — confirmed.** Six independent indicators converge: a typosquat sender domain, urgency-driven social engineering, a generic greeting, an obfuscated link confirmed malicious by VirusTotal, a suspicious attachment format, and failed SPF/DKIM authentication. No single indicator alone is conclusive, but the combination eliminates reasonable doubt. Recommended action: block sender domain, quarantine message, report to threat intel team.

### Key Takeaways
- **Header analysis (From vs. Return-Path vs. Reply-To) is the fastest spoofing check.** Legitimate mail has these fields consistently aligned with the sending organisation's real domain.
- SPF and DKIM failures are strong technical confirmation but should be read alongside content red flags — some legitimate mail has misconfigured authentication, and sophisticated phishing can pass both checks.
- VirusTotal lets an analyst safely investigate a suspicious link's reputation without ever exposing the organisation to the live page.
- **Verdict should rest on the combination of indicators, not any single one.** Urgency language alone could be legitimate; paired with a typosquat domain, obfuscated link, and auth failures, it becomes a confident call.

---

## Skills Demonstrated
- Windows Event Viewer navigation and log filtering
- Security event triage (logon analysis, field interpretation)
- Distinguishing routine errors from attack indicators
- Email header analysis (From / Return-Path / Reply-To / SPF / DKIM)
- Safe URL investigation using VirusTotal
- Structured incident writeup following SOC L1 triage workflow

---

## Related Work
This repository is part of a broader SOC analyst portfolio. Other projects cover network traffic analysis (Wireshark), SIEM setup and alerting (Splunk), and TryHackMe room walkthroughs (MITRE ATT&CK, Investigating Windows).
