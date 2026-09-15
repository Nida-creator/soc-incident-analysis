# Exercise 2 — Phishing Email Header Analysis
## Detailed Findings

**Analyst:** Nida Nadeem  
**Date:** 15 September 2026  
**Tools:** Manual header analysis, VirusTotal (virustotal.com)  
**Sample type:** Constructed phishing sample modeled on a credential-harvesting lure

---

## 1. Sample Email

```
Subject:    URGENT: Your account will be suspended in 24 hours
From:       "IT Support Desk" <support@paypa1-security.com>
Reply-To:   helpdesk-support@paypa1-security.com
Return-Path: bounce@mkt-relay03.ru-hosting.net
To:         employee@company.com

Dear Customer,

We detected unusual activity on your account. Your access will
be suspended in 24 hours unless you verify your identity now.

[Verify Account] → hxxp://bit[.]ly/3xAmpleLink

See attached statement for details.

Attachment: Account_Statement.html
```

> Note: URLs are defanged (`hxxp` and `[.]`) throughout this document — standard practice to prevent accidental clicks in writeups.

---

## 2. Header Analysis — Field by Field

### 2.1 From Address

**Value:** `"IT Support Desk" <support@paypa1-security.com>`

Two separate deception techniques in one field:

**Display name spoofing:** The name "IT Support Desk" is what most email clients show by default. Many users never see the actual sending address. Attackers rely on this — the display name can be set to anything without any technical restriction.

**Typosquatting:** `paypa1-security.com` uses the digit `1` in place of the letter `l`. At a glance, especially in certain fonts, `paypa1` reads as `paypal`. This is a deliberate lookalike domain registered specifically to deceive. Legitimate PayPal mail comes from `@paypal.com` only.

**How to check:** Hover over or expand the From field in your email client. If the displayed name and the actual domain don't match your expectations, treat it as a red flag immediately.

---

### 2.2 Return-Path

**Value:** `bounce@mkt-relay03.ru-hosting.net`

The Return-Path is where bounced/undeliverable mail gets sent. In legitimate corporate email, this is usually on the same domain as the From address, or a closely related sending infrastructure domain the organisation controls.

Here it is a completely unrelated domain (`ru-hosting.net`) with a relay subdomain naming convention (`mkt-relay03`) typical of bulk mail infrastructure — often rented or compromised by attackers for exactly this purpose.

**The mismatch between From domain and Return-Path domain is one of the clearest spoofing signals available in a header.**

---

### 2.3 Reply-To

**Value:** `helpdesk-support@paypa1-security.com`

The Reply-To header redirects any replies away from the sending address to a different address. Here it matches the spoofed From domain rather than the Return-Path.

Attackers use this to control where victim responses go — if someone replies to the email asking for more information, the attacker receives it rather than bouncing to the relay server. The Reply-To address is often the one the attacker actually monitors.

---

### 2.4 SPF — Sender Policy Framework

**Result:** softfail

**What SPF does:** The domain owner publishes a DNS record listing which servers are authorised to send email on their behalf. The receiving mail server checks whether the sending server's IP is on that list.

| SPF Result | Meaning |
|-----------|---------|
| pass | Sending server is authorised — legitimate signal |
| softfail (~all) | Server not authorised, but domain says treat softly — suspicious |
| fail (-all) | Server explicitly not authorised — strong spoofing signal |
| none | No SPF record exists for the domain |

A softfail means the message likely did not come from an authorised server for the claimed domain. Combined with the other header mismatches, this technically confirms what the visual inspection already suggested.

---

### 2.5 DKIM — DomainKeys Identified Mail

**Result:** fail / not signed

**What DKIM does:** The sending mail server cryptographically signs the message using a private key. The receiving server retrieves the corresponding public key from DNS and verifies the signature, confirming the message came from the claimed domain and was not altered in transit.

A failed or missing DKIM signature means:
- The message authenticity cannot be verified
- The message may have been altered after sending
- The claimed domain did not sign it — consistent with a spoofed sender

Legitimate corporate mail almost universally passes DKIM. A missing signature on a message claiming to be from a company's IT support desk is a strong indicator the From address is forged.

---

## 3. Authentication Summary

| Check | Result | Interpretation |
|-------|--------|---------------|
| SPF | softfail | Sending server not authorised for claimed domain |
| DKIM | fail | Message not cryptographically verified |
| DMARC | would fail | SPF + DKIM both failing means DMARC policy would reject/quarantine |

All three authentication mechanisms fail. A legitimate email from a real organisation's IT department passes all three.

---

## 4. URL Investigation

**Embedded link:** `hxxp://bit[.]ly/3xAmpleLink` (defanged)

### Process
1. The URL was copied from the email body
2. Pasted directly into VirusTotal (virustotal.com/gui/url)
3. The live page was **never opened in a browser** at any point

This is standard safe practice. VirusTotal resolves the URL and checks it against 70+ security vendor engines and reputation databases server-side — the analyst's machine never makes contact with the destination.

### VirusTotal Results
The URL was flagged as **malicious** by multiple vendors including:
- BitDefender — Malware
- Kaspersky — Malware  
- Sophos — Malware
- Webroot — Malicious
- Google Safe Browsing — Malware
- Lionic — Malware
- VIPRE — Malware
- alphaMount.ai — Malicious

A small number of vendors returned Clean or Suspicious — this is normal. No URL check returns 100% consensus. The threshold for treating a URL as malicious in triage is typically 3+ vendor detections; 8+ detections here is a clear positive.

---

## 5. Red Flags — Full Catalogue

| # | Red Flag | Category | Where It Appears |
|---|----------|----------|-----------------|
| 1 | Urgency / fear language | Social engineering | Subject: "suspended in 24 hours"; body: "verify now" |
| 2 | Lookalike / typosquat domain | Technical | `paypa1-security.com` — digit 1 substituted for letter l |
| 3 | Display name spoofing | Technical | "IT Support Desk" masks the actual sending domain |
| 4 | Return-Path mismatch | Technical | Completely different domain from From address |
| 5 | Generic greeting | Social engineering | "Dear Customer" — not personalised |
| 6 | Obfuscated embedded link | Technical | Shortened URL hides true destination |
| 7 | Suspicious attachment | Content | `.html` file claiming to be an account statement |
| 8 | SPF softfail | Authentication | Sending server not authorised |
| 9 | DKIM fail | Authentication | Message authenticity unverifiable |
| 10 | VirusTotal detections | Reputation | 8+ vendor engines flagged the URL as malicious |

---

## 6. Verdict

**PHISHING — High Confidence**

Ten independent indicators across four categories (social engineering, technical header analysis, authentication, and reputation) all point in the same direction. No single indicator alone makes the verdict — urgency language can appear in legitimate mail, SPF can be misconfigured on legitimate domains — but the convergence of all ten removes any reasonable doubt.

**Recommended SOC actions:**
1. Quarantine the message across all mailboxes that received it
2. Block the sender domain (`paypa1-security.com`) and the Return-Path domain at the mail gateway
3. Submit the URL and attachment hash to threat intel platform
4. Check mail gateway logs for other messages from `mkt-relay03.ru-hosting.net`
5. If any user clicked the link, escalate to IR: pull browser history, check for credential submission, reset credentials

---

## 7. Key Takeaways

**On header analysis:**
From → Return-Path → Reply-To mismatches are the fastest spoofing check. In legitimate mail these fields are consistently aligned with the organisation's real domain. Any mismatch warrants deeper inspection.

**On SPF/DKIM:**
Authentication failures are strong technical confirmation but not infallible. Some legitimate mail has misconfigured SPF or DKIM. Some sophisticated phishing passes both. Always read authentication results alongside content analysis — they confirm each other, not replace each other.

**On URL investigation:**
Never click a suspected phishing link. Paste into VirusTotal, URLScan.io, or a sandbox. The goal is to understand the destination without the analyst's machine ever touching it.

**On verdict confidence:**
The more independent indicators stacking in the same direction, the higher the confidence. One odd header field could be a misconfiguration. Ten indicators all pointing to phishing is a call you can make without hesitation.

---

## 8. Screenshots Reference

| Screenshot | What It Shows |
|-----------|---------------|
| `virustotal-scan-result.png` | VirusTotal detection results — vendor breakdown, community score |
| `thm-phishing-completion.png` | TryHackMe "Phishing Emails in Action" room completion proof |
