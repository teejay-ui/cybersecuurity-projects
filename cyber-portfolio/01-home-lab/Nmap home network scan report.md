# Home Network Reconnaissance Report

**Author:** Teejay Kongolo
**Date:** July 5, 2026
**Tools used:** Nmap 7.99, Kali Linux
**Scope:** My own home network (192.168.0.0/24) — scanned with authorization as the network owner

---

## 1. Objective

To practice network reconnaissance fundamentals by identifying live hosts on my home network, then performing a deeper scan on the router to enumerate open ports, running services, and the operating system — and to evaluate whether any of the findings represent a security risk.

## 2. Methodology

Two scans were performed from a Kali Linux VM connected to the home network:

**Step 1 — Host discovery (ping sweep)**
```
nmap -sn 192.168.0.205/24
```
This scans the entire subnet without port-scanning each host, simply to identify which devices are currently online.

**Step 2 — Service and OS detection on the router**
```
nmap -sV -O 192.168.0.1
```
This performs a version scan (`-sV`) to identify what service is running on each open port, and OS detection (`-O`) to fingerprint the operating system.

## 3. Findings

### 3.1 Host Discovery

| IP Address | MAC Vendor | Status |
|---|---|---|
| 192.168.0.1 | TP-Link Technologies | Up (router) |
| 192.168.0.100 | TP-Link Systems | Up |
| 192.168.0.203 | Intel Corporate | Up |
| 192.168.0.205 | — | Up (scanning host) |

4 hosts responded out of 256 possible addresses in the /24 range, scanned in 2.59 seconds.

### 3.2 Router Deep Scan (192.168.0.1)

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | ssh | Dropbear sshd 2012.55 (protocol 2.0) |
| 53/tcp | open | domain | ISC BIND |
| 80/tcp | open | http | TP-LINK WAP http config |
| 1900/tcp | open | upnp | Portable SDK for UPnP devices 1.6.19 |

**OS Detection:** Linux 2.6.23 – 2.6.38 (TP-Link embedded device)

## 4. Analysis

Two findings stood out as worth flagging, even on a home network:

**Outdated kernel.** The router is running a Linux 2.6.x kernel, a branch that reached end-of-life over a decade ago and no longer receives security patches. Embedded devices like consumer routers often run old, unpatched kernels for years because manufacturers stop pushing firmware updates — this is a common real-world pattern, not unique to this device.

**UPnP exposed (port 1900).** UPnP (Universal Plug and Play) allows devices on the network to automatically open ports on the router without manual configuration. It's convenient, but it's also a well-documented attack surface — malware on any device on the network can potentially use UPnP to open ports to the outside internet without the user's knowledge. Most security guidance recommends disabling UPnP unless it's specifically needed.

Ports 22 (SSH) and 80 (HTTP admin panel) being open is expected for a router — that's how it's managed — but it does mean the admin login is a meaningful target if the default credentials were never changed.

## 5. Recommendations

1. **Update or replace the router firmware** if a newer version is available from TP-Link; if not, this is a strong argument for replacing an EOL device.
2. **Disable UPnP** in the router's admin settings unless a specific device on the network requires it.
3. **Verify SSH and admin panel credentials** are not left at factory defaults.
4. **Restrict the admin panel** to LAN-only access if an option exists, rather than leaving it reachable from any device on the network.

## 6. What I'd do differently next time

Run a full port range scan (`-p-`) rather than the default top 1000 ports, to rule out anything listening on a non-standard port. I'd also want to scan from outside the network (if legally and ethically possible on infrastructure I control) to see what an external attacker would actually see versus what's only visible internally.

---
*This scan was performed on a network I own and control, for educational purposes as part of my cybersecurity home lab practice.*
