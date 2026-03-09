"""
vuln_scanner.py
---------------
DOT Sentinel AI – Comprehensive Vulnerability & Posture Assessment Engine

Performs rule-based, MITRE ATT&CK-aligned vulnerability checks across four pillars:
  ⚙️  System & Software Configuration
      - Patch Level & EOL Status (OS, runtimes, web servers, databases, known CVEs)
      - Default Credentials (systems, applications, databases, IoT & network devices, secret keys)
      - Unnecessary Services & Ports (FTP, Telnet, SMBv1, RDP, VNC, unauth datastores)
      - Encryption Standards (data-in-transit TLS & ciphers, data-at-rest disk/db/backup encryption)
  🔑  Identity & Access Controls
      - Authentication Strength (MFA enforcement globally, phishing resistance, NIST password standards)
      - Least Privilege Enforcement (excessive admins, over-privileged service accounts, wildcard API keys)
      - Orphaned & Inactive Accounts (stale employee accounts, decommissioned service principals)
  🌐  Network & Border Defenses
      - Firewall & ACL Configurations (Any-to-Any rules, management ports exposed to 0.0.0.0/0, external-to-internal PCAP flows)
      - Missing Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
      - Information Disclosure (server banners, X-Powered-By, stack traces, internal IP leakage)
  📝  Monitoring & Resilience
      - Logging and Audit Trails (centralized SIEM, ingestion of 4 critical log sources, tamper resistance, retention)
      - Backup Integrity (3-2-1 rule, ransomware immutability/WORM/offline, scheduled restoration drills)

Optional AI Integration:
  - Generates MITRE ATT&CK tactical mappings
  - Synthesizes an AI SOC Executive Summary & Prioritized Triage Playbook (Google Gemini or heuristic fallback)
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants & Knowledge Base
# ---------------------------------------------------------------------------

LEGACY_PORTS: Dict[int, tuple[str, str, str]] = {
    21:    ("FTP",           "File Transfer Protocol (cleartext) – replace with SFTP/SCP", "T1040"),
    23:    ("Telnet",        "Telnet (unencrypted terminal) – replace with SSH", "T1040"),
    69:    ("TFTP",          "Trivial FTP (unauthenticated cleartext UDP) – disable service", "T1040"),
    79:    ("Finger",        "Finger service – legacy user enumeration vector", "T1087"),
    80:    ("HTTP",          "Unencrypted HTTP – enforce HTTPS and redirect all traffic", "T1040"),
    110:   ("POP3",          "POP3 (cleartext mail) – migrate to POP3S (port 995)", "T1040"),
    135:   ("MS-RPC",        "Windows RPC endpoint mapper exposed – block at perimeter", "T1021"),
    137:   ("NetBIOS-NS",    "NetBIOS Name Service – broadcast name spoofing risk", "T1557"),
    139:   ("NetBIOS-SSN",   "NetBIOS Session – legacy SMB transport risk", "T1021"),
    143:   ("IMAP",          "IMAP (cleartext mail) – migrate to IMAPS (port 993)", "T1040"),
    445:   ("SMBv1/v2",      "SMB file sharing exposed – disable SMBv1, enforce SMBv3 signing", "T1021.002"),
    512:   ("rexec",         "Remote Execution service (cleartext) – disable immediately", "T1021"),
    513:   ("rlogin",        "Remote Login service (cleartext) – disable immediately", "T1021"),
    514:   ("rsh",           "Remote Shell service (cleartext) – disable immediately", "T1021"),
    3389:  ("RDP",           "Remote Desktop Protocol directly exposed – require VPN + MFA", "T1021.001"),
    5900:  ("VNC",           "VNC remote desktop exposed – tunnel over SSH or disable", "T1021.005"),
    6379:  ("Redis",         "Redis in-memory store exposed – bind to 127.0.0.1, requirepass", "T1190"),
    9200:  ("Elasticsearch", "Elasticsearch cluster REST API exposed – enable TLS & auth", "T1190"),
    11211: ("Memcached",     "Memcached exposed – UDP amplification & unauthenticated access", "T1498"),
    27017: ("MongoDB",       "MongoDB default database port exposed – bind localhost, auth", "T1190"),
}

DEFAULT_CRED_TARGETS: Dict[int, tuple[str, str, str]] = {
    21:    ("FTP Server",             "Anonymous login or vendor default credentials", "T1078"),
    22:    ("SSH Server",             "Factory root credentials or default distro keys (e.g. pi/raspberry)", "T1078"),
    23:    ("Telnet Appliance",       "Hardcoded factory administrative credentials (admin/admin, admin/1234)", "T1078"),
    80:    ("Web Admin / Router",     "Router or IoT web console default logins (admin/admin, admin/password)", "T1078"),
    443:   ("Web Admin / Firewall",   "Appliance web UI with default administrative passwords", "T1078"),
    161:   ("SNMP Agent",             "Default SNMP community strings ('public', 'private')", "T1078"),
    554:   ("RTSP Camera / IoT",      "IP surveillance camera streaming with factory credentials", "T1078"),
    1883:  ("MQTT Broker",            "IoT message broker operating without client authentication", "T1078"),
    8080:  ("Tomcat / Web Gateway",   "Apache Tomcat /dev gateway default credentials (tomcat/s3cret)", "T1078"),
    8443:  ("Management Portal",      "Administrative web interface with vendor defaults", "T1078"),
    9000:  ("Portainer / DevOps",     "Container management console with initial setup bypass", "T1078"),
}

KNOWN_EOL_SOFTWARE: Dict[str, tuple[str, str]] = {
    "windows xp":            ("2014-04-08", "Critical remote execution vulnerabilities (EternalBlue / WannaCry risk)."),
    "windows 7":             ("2020-01-14", "Unpatched OS susceptible to BlueKeep (CVE-2019-0708) and local privilege escalation."),
    "windows 8":             ("2023-01-10", "No longer receives monthly security updates or driver patches."),
    "windows server 2003":   ("2015-07-14", "Legacy Windows Server running unsupported SMBv1 and RPC stack."),
    "windows server 2008":   ("2020-01-14", "Server 2008 / 2008 R2 reached end of extended support."),
    "windows server 2012":   ("2023-10-10", "Server 2012 / 2012 R2 end of extended security updates."),
    "centos 6":              ("2020-11-30", "Repository archived, zero patches for critical Linux kernel CVEs."),
    "centos 7":              ("2024-06-30", "CentOS 7 reached official EOL; migration to Rocky/AlmaLinux or RHEL required."),
    "centos 8":              ("2021-12-31", "CentOS Linux 8 discontinued; switch to CentOS Stream or Rocky Linux."),
    "ubuntu 14.04":          ("2019-04-30", "Ubuntu Trusty Tahr standard security support ended."),
    "ubuntu 16.04":          ("2021-04-30", "Ubuntu Xenial Xerus standard support concluded."),
    "ubuntu 18.04":          ("2023-05-31", "Ubuntu Bionic Beaver reached end of standard 5-year maintenance."),
    "debian 7":              ("2018-05-31", "Debian Wheezy LTS support concluded."),
    "debian 8":              ("2020-06-30", "Debian Jessie LTS support concluded."),
    "debian 9":              ("2022-06-30", "Debian Stretch LTS support concluded."),
    "python 2":              ("2020-01-01", "Python 2.7 runtime reached EOL; vulnerable to unpatched interpreter flaws."),
    "python 3.6":            ("2021-12-23", "Python 3.6 end-of-life; unsupported standard library SSL and hashing."),
    "python 3.7":            ("2023-06-27", "Python 3.7 reached end of security maintenance."),
    "php 5":                 ("2018-12-31", "PHP 5.x end-of-life with numerous arbitrary code execution CVEs."),
    "php 7.0":               ("2018-12-03", "PHP 7.0 end-of-life."),
    "php 7.4":               ("2022-11-28", "PHP 7.4 reached end of security updates."),
    "php 8.0":               ("2023-11-26", "PHP 8.0 reached end of security maintenance."),
    "openssl 0.9.8":         ("2015-12-31", "Severely vulnerable to historical SSL bugs (Heartbleed, POODLE)."),
    "openssl 1.0.1":         ("2016-12-31", "Vulnerable to CVE-2014-0160 (Heartbleed memory disclosure)."),
    "openssl 1.0.2":         ("2019-12-31", "Reached EOL; missing modern TLS 1.3 cipher protections."),
    "openssl 1.1.0":         ("2019-09-11", "OpenSSL 1.1.0 series discontinued."),
    "apache 2.2":            ("2017-07-11", "Legacy Apache HTTP Server branch without modern TLS and HTTP/2 support."),
    "nodejs 12":             ("2022-04-30", "Node.js 12 LTS reached EOL."),
    "nodejs 14":             ("2023-04-30", "Node.js 14 LTS reached EOL."),
    "nodejs 16":             ("2023-09-11", "Node.js 16 LTS reached EOL due to OpenSSL 1.1.1 EOL."),
}

KNOWN_HIGH_IMPACT_CVES: List[Dict[str, Any]] = [
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "component": "log4j",
        "affected_versions": ["2.0", "2.14", "2.15", "2.16"],
        "severity": "CRITICAL",
        "cvss": 10.0,
        "detail": "Apache Log4j JNDI injection allows unauthenticated remote code execution via LDAP/RMI lookup.",
        "remediation": "Upgrade Log4j to >= 2.17.1 or set log4j2.formatMsgNoLookups=true.",
        "mitre": "T1190",
    },
    {
        "id": "CVE-2014-0160",
        "name": "Heartbleed",
        "component": "openssl",
        "affected_versions": ["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "detail": "OpenSSL TLS heartbeat extension memory bounds error permits arbitrary memory reading.",
        "remediation": "Upgrade OpenSSL to >= 1.0.1g or compile with -DOPENSSL_NO_HEARTBEATS.",
        "mitre": "T1190",
    },
    {
        "id": "CVE-2017-0144",
        "name": "EternalBlue",
        "component": "smbv1",
        "affected_versions": ["windows 7", "windows xp", "windows server 2008", "windows server 2003"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "detail": "Microsoft SMBv1 buffer overflow enables remote code execution over port 445.",
        "remediation": "Apply Microsoft patch MS17-010 and disable SMBv1 across all hosts.",
        "mitre": "T1210",
    },
    {
        "id": "CVE-2021-34527",
        "name": "PrintNightmare",
        "component": "spooler",
        "affected_versions": ["windows server 2012", "windows server 2016", "windows 10"],
        "severity": "HIGH",
        "cvss": 8.8,
        "detail": "Windows Print Spooler service fails to restrict access to RpcAddPrinterDriverEx().",
        "remediation": "Disable Print Spooler on domain controllers and apply cumulative security patches.",
        "mitre": "T1068",
    },
    {
        "id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "component": "spring",
        "affected_versions": ["spring framework 5.3.0", "5.3.17", "5.2.0", "5.2.19"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "detail": "Spring MVC / WebFlux data binding flaw allows RCE when deployed on Apache Tomcat.",
        "remediation": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+ and upgrade Tomcat.",
        "mitre": "T1190",
    },
    {
        "id": "CVE-2021-41773",
        "name": "Apache Path Traversal & RCE",
        "component": "apache",
        "affected_versions": ["2.4.49", "2.4.50"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "detail": "Path traversal flaw allows attackers to map URLs to files outside expected document root.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
        "mitre": "T1190",
    },
]

WEAK_CIPHERS: List[str] = [
    "RC4", "3DES", "DES", "NULL", "EXPORT", "anon", "ADH", "AECDH",
    "MD5", "SHA1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "CBC"
]

REQUIRED_HTTP_HEADERS: Dict[str, tuple[str, str]] = {
    "Content-Security-Policy": (
        "Restricts loading of malicious scripts, stylesheets, and prevents Cross-Site Scripting (XSS).",
        "T1189"
    ),
    "Strict-Transport-Security": (
        "Enforces HTTPS connections (HSTS), defeating SSL stripping and MITM attacks.",
        "T1557"
    ),
    "X-Frame-Options": (
        "Defends against clickjacking by disallowing framing (DENY or SAMEORIGIN).",
        "T1189"
    ),
    "X-Content-Type-Options": (
        "Prevents MIME-sniffing by browsers (nosniff), mitigating drive-by download attacks.",
        "T1189"
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is sent with requests, avoiding credential leakage.",
        "T1592"
    ),
    "Permissions-Policy": (
        "Disables sensitive browser capabilities (camera, microphone, geolocation) by default.",
        "T1189"
    ),
}

# ---------------------------------------------------------------------------
# Finding Data Structure
# ---------------------------------------------------------------------------

def _create_finding(
    pillar: str,
    check_name: str,
    severity: str,          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    status: str,            # FAIL | WARN | PASS | INFO
    detail: str,
    remediation: str,
    evidence: Optional[List[str]] = None,
    mitre_technique: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "category": pillar,
        "check": check_name,
        "severity": severity,
        "status": status,
        "detail": detail,
        "remediation": remediation,
        "evidence": evidence or [],
        "mitre_technique": mitre_technique or "T1000",
    }


# ---------------------------------------------------------------------------
# Pillar 1: ⚙️ System & Software Configuration
# ---------------------------------------------------------------------------

def audit_system_and_software(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1.1 Patch Level and EOL Status (Operating System)
    os_name = str(payload.get("os_name", "")).strip()
    if os_name:
        eol_match = None
        for sw_key, (eol_date, eol_desc) in KNOWN_EOL_SOFTWARE.items():
            if sw_key in os_name.lower():
                eol_match = (sw_key, eol_date, eol_desc)
                break

        if eol_match:
            findings.append(_create_finding(
                pillar="⚙️ System & Software Configuration",
                check_name="Patch Level & EOL Status – Operating System",
                severity="CRITICAL",
                status="FAIL",
                detail=f"The host operating system '{os_name}' reached End-of-Life on {eol_match[1]}. {eol_match[2]}",
                remediation="Upgrade to a actively supported OS version immediately (e.g. Windows Server 2022/2025, Ubuntu 22.04/24.04 LTS, Rocky Linux 9). EOL systems receive zero security patches.",
                evidence=[f"Reported OS: {os_name}", f"End-of-Life Date: {eol_match[1]}"],
                mitre_technique="T1190",
            ))
        else:
            findings.append(_create_finding(
                pillar="⚙️ System & Software Configuration",
                check_name="Patch Level & EOL Status – Operating System",
                severity="LOW",
                status="PASS",
                detail=f"Operating system '{os_name}' appears to be within an active vendor support lifecycle.",
                remediation="Continue tracking vendor patch cycles and apply monthly kernel/security rollups.",
                evidence=[f"Reported OS: {os_name}"],
                mitre_technique="T1082",
            ))

    # 1.2 Installed Applications EOL & Known CVE Auditing
    installed_apps = payload.get("installed_applications") or []
    unpatched_cves_flag = payload.get("has_unpatched_cves", None)
    cve_findings_list: List[str] = []

    for app in installed_apps:
        app_name = str(app.get("name", "")).lower()
        app_ver = str(app.get("version", "")).lower()
        full_str = f"{app_name} {app_ver}"

        # Check EOL runtimes
        for sw_key, (eol_date, eol_desc) in KNOWN_EOL_SOFTWARE.items():
            if sw_key in full_str:
                cve_findings_list.append(f"EOL Software: '{app_name} {app_ver}' (EOL: {eol_date})")

        # Check against high-impact CVEs database
        for cve in KNOWN_HIGH_IMPACT_CVES:
            if cve["component"] in app_name:
                for bad_v in cve["affected_versions"]:
                    if bad_v in app_ver:
                        cve_findings_list.append(
                            f"Known Exploit: {cve['id']} ({cve['name']}) in {app_name} {app_ver} - CVSS {cve['cvss']}"
                        )

    if cve_findings_list:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Application Patch Level & CVE Vulnerabilities",
            severity="CRITICAL",
            status="FAIL",
            detail=f"Detected {len(cve_findings_list)} vulnerable or end-of-life application packages running on the host.",
            remediation="Patch or decommission vulnerable dependencies immediately. Integrate an automated Software Composition Analysis (SCA) tool in your CI/CD pipeline.",
            evidence=cve_findings_list,
            mitre_technique="T1190",
        ))
    elif unpatched_cves_flag is True:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Application Patch Level & CVE Vulnerabilities",
            severity="HIGH",
            status="FAIL",
            detail="System reported having unpatched CVE vulnerabilities pending installation.",
            remediation="Execute vulnerability remediation cycle and apply outstanding security updates.",
            mitre_technique="T1190",
        ))
    elif installed_apps:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Application Patch Level & CVE Vulnerabilities",
            severity="LOW",
            status="PASS",
            detail=f"Audited {len(installed_apps)} installed application(s); no high-impact CVE or EOL signatures detected.",
            remediation="Maintain regular dependency vulnerability scanning using tools like Trivy or Grype.",
            mitre_technique="T1190",
        ))

    # 1.3 Default Credentials Check (Systems, Applications, IoT & Secret Keys)
    observed_ports: List[int] = payload.get("observed_ports") or []
    default_creds_present = payload.get("default_credentials_present", None)
    default_cred_evidence: List[str] = []

    for port in observed_ports:
        if port in DEFAULT_CRED_TARGETS:
            srv, desc, _ = DEFAULT_CRED_TARGETS[port]
            default_cred_evidence.append(f"Port {port} ({srv}): {desc}")

    # Check secret keys
    default_secret_keys = payload.get("default_secret_keys_detected") or []
    if default_secret_keys:
        default_cred_evidence.extend([f"Default Secret Key exposed: {k}" for k in default_secret_keys])

    if default_creds_present is True or (default_creds_present is None and len(default_cred_evidence) >= 2):
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Default Credentials & Factory Secret Keys",
            severity="CRITICAL",
            status="FAIL",
            detail="Active services or network appliances are operating with default factory credentials or well-known secrets.",
            remediation="Immediately rotate factory passwords, API tokens, and secret keys across all management interfaces, IoT appliances, and databases. Enforce password vaulting.",
            evidence=default_cred_evidence if default_cred_evidence else ["Unrotated default credentials reported."],
            mitre_technique="T1078.001",
        ))
    elif default_cred_evidence:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Default Credentials & Factory Secret Keys",
            severity="MEDIUM",
            status="WARN",
            detail=f"{len(default_cred_evidence)} service port(s) historically targeted by default-credential brute-force tools are reachable.",
            remediation="Verify that default logins (e.g. admin/admin, root/toor) have been changed and account lockout is active.",
            evidence=default_cred_evidence,
            mitre_technique="T1078",
        ))
    else:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Default Credentials & Factory Secret Keys",
            severity="LOW",
            status="PASS",
            detail="No default credentials or typical default-login attack surfaces detected.",
            remediation="Enforce unique credential generation for new system provisions.",
            mitre_technique="T1078",
        ))

    # 1.4 Unnecessary Services & Ports
    unnecessary_found: List[str] = []
    for port in observed_ports:
        if port in LEGACY_PORTS:
            name, desc, _ = LEGACY_PORTS[port]
            unnecessary_found.append(f"Port {port} ({name}): {desc}")

    if unnecessary_found:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Unnecessary & Legacy Services / Ports",
            severity="HIGH",
            status="FAIL",
            detail=f"Detected {len(unnecessary_found)} unnecessary, legacy, or high-risk open service port(s).",
            remediation="Disable or firewall all non-business-critical services to minimize the attack surface. Bind internal management services exclusively to localhost (127.0.0.1) or an isolated management VLAN.",
            evidence=unnecessary_found,
            mitre_technique="T1046",
        ))
    elif observed_ports:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Unnecessary & Legacy Services / Ports",
            severity="LOW",
            status="PASS",
            detail="No legacy or high-risk service ports observed in open port profile.",
            remediation="Conduct continuous attack surface mapping (e.g., nmap, Shodan) to verify no shadow services become exposed.",
            mitre_technique="T1046",
        ))

    # 1.5 Encryption Standards (Data-in-Transit)
    protocols_seen: List[str] = payload.get("protocols_seen") or []
    cleartext_protocols = [p.upper() for p in protocols_seen if p.lower() in ("http", "ftp", "telnet", "smtp", "pop3", "imap", "snmp", "tftp")]
    tls_ciphers: List[str] = payload.get("tls_ciphers") or []
    weak_ciphers_found = [c for c in tls_ciphers if any(w in c.upper() for w in WEAK_CIPHERS)]

    if cleartext_protocols or weak_ciphers_found:
        ev = []
        if cleartext_protocols:
            ev.append(f"Cleartext Protocols: {', '.join(cleartext_protocols)}")
        if weak_ciphers_found:
            ev.append(f"Weak Ciphers: {', '.join(weak_ciphers_found)}")

        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Encryption Standards – Data in Transit",
            severity="HIGH",
            status="FAIL",
            detail="Unencrypted communications or deprecated cipher suites detected in network traffic.",
            remediation="Enforce TLS 1.2 / TLS 1.3 exclusively. Disable legacy ciphers (RC4, 3DES, DES, CBC, MD5). Mandate forward secrecy (ECDHE-RSA / ECDHE-ECDSA).",
            evidence=ev,
            mitre_technique="T1040",
        ))
    else:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Encryption Standards – Data in Transit",
            severity="LOW",
            status="PASS",
            detail="Network protocols and TLS configurations adhere to current cryptographic security standards.",
            remediation="Periodically verify cipher configurations against Mozilla SSL Configuration Generator recommendations.",
            mitre_technique="T1040",
        ))

    # 1.6 Encryption Standards (Data-at-Rest)
    disk_encryption = payload.get("disk_encryption_enabled", None)
    db_encryption = payload.get("database_encryption_at_rest", None)
    backup_encryption = payload.get("backup_encryption_enabled", None)

    at_rest_issues: List[str] = []
    if disk_encryption is False:
        at_rest_issues.append("Host storage volumes lack full-disk encryption (BitLocker / LUKS / FileVault disabled)")
    if db_encryption is False:
        at_rest_issues.append("Databases operate without Transparent Data Encryption (TDE) or encrypted tablespaces")
    if backup_encryption is False:
        at_rest_issues.append("System backups are archived in unencrypted plain format")

    if at_rest_issues:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Encryption Standards – Data at Rest",
            severity="HIGH",
            status="FAIL",
            detail=f"Identified {len(at_rest_issues)} gap(s) in data-at-rest encryption controls.",
            remediation="Enable full-disk encryption on all endpoints/servers (BitLocker/LUKS with TPM 2.0). Enable TDE on database clusters and enforce AES-256 for backup archives.",
            evidence=at_rest_issues,
            mitre_technique="T1005",
        ))
    elif disk_encryption is True and db_encryption is not False:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Encryption Standards – Data at Rest",
            severity="LOW",
            status="PASS",
            detail="Host storage and critical database assets are protected with strong data-at-rest encryption.",
            remediation="Audit key management practices (KMS / HSM) and ensure keys are rotated at least annually.",
            mitre_technique="T1005",
        ))
    else:
        findings.append(_create_finding(
            pillar="⚙️ System & Software Configuration",
            check_name="Encryption Standards – Data at Rest",
            severity="MEDIUM",
            status="WARN",
            detail="Data-at-rest encryption settings not fully specified.",
            remediation="Audit storage infrastructure to ensure all PII and sensitive data partitions are encrypted with AES-256.",
            mitre_technique="T1005",
        ))

    return findings


# ---------------------------------------------------------------------------
# Pillar 2: 🔑 Identity & Access Controls
# ---------------------------------------------------------------------------

def audit_identity_and_access(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 2.1 Authentication Strength (MFA Enforcement)
    mfa_enabled = payload.get("mfa_enabled", None)
    mfa_enforced_for_admins = payload.get("mfa_enforced_for_admins", None)
    mfa_type = str(payload.get("mfa_type", "")).lower()

    if mfa_enabled is False:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Authentication Strength – Multi-Factor Authentication (MFA)",
            severity="CRITICAL",
            status="FAIL",
            detail="Multi-Factor Authentication is NOT enforced globally across user and administrative accounts.",
            remediation="Mandate MFA across all identity providers (IdP/SSO, Azure AD/Entra, Okta, Google Workspace). Prioritize remote access, VPNs, and administrative portals.",
            mitre_technique="T1078",
        ))
    elif mfa_enabled is True:
        if mfa_type in ("sms", "email", "telephony"):
            findings.append(_create_finding(
                pillar="🔑 Identity & Access Controls",
                check_name="Authentication Strength – Multi-Factor Authentication (MFA)",
                severity="MEDIUM",
                status="WARN",
                detail="MFA is enforced, but relies on SMS/telephony OTP, which is susceptible to SIM-swapping and interception.",
                remediation="Upgrade authentication methods to phishing-resistant MFA (FIDO2 / WebAuthn hardware security keys, or Microsoft/Google Authenticator with number matching).",
                evidence=[f"MFA Factor: {mfa_type.upper()}"],
                mitre_technique="T1111",
            ))
        else:
            findings.append(_create_finding(
                pillar="🔑 Identity & Access Controls",
                check_name="Authentication Strength – Multi-Factor Authentication (MFA)",
                severity="LOW",
                status="PASS",
                detail="MFA is enforced globally across all user and administrative accounts.",
                remediation="Regularly audit conditional access policies and review MFA exemption groups.",
                mitre_technique="T1078",
            ))
    elif mfa_enforced_for_admins is True:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Authentication Strength – Multi-Factor Authentication (MFA)",
            severity="MEDIUM",
            status="WARN",
            detail="MFA is enforced for administrators only, leaving standard employee mailboxes and VPN access vulnerable to credential stuffing.",
            remediation="Extend mandatory MFA policy to 100% of user accounts.",
            mitre_technique="T1078",
        ))
    else:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Authentication Strength – Multi-Factor Authentication (MFA)",
            severity="MEDIUM",
            status="WARN",
            detail="MFA configuration status was omitted from posture profile.",
            remediation="Verify identity provider policies to confirm MFA is enforced universally.",
            mitre_technique="T1078",
        ))

    # 2.2 Password Complexity Policies (NIST SP 800-63B Alignment)
    pw_policy: Dict[str, Any] = payload.get("password_policy") or {}
    pw_gaps: List[str] = []

    if pw_policy:
        min_len = pw_policy.get("min_length", 8)
        complexity = pw_policy.get("requires_complexity", False)
        max_age = pw_policy.get("max_age_days", 90)
        lockout_thresh = pw_policy.get("lockout_threshold", None)
        breached_check = pw_policy.get("check_breached_passwords", False)

        if min_len < 12:
            pw_gaps.append(f"Minimum length is {min_len} chars (NIST recommends >= 12-16 chars or passphrases)")
        if not complexity and min_len < 15:
            pw_gaps.append("Complexity requirements disabled while minimum length is under 15 characters")
        if lockout_thresh is None or lockout_thresh > 5:
            pw_gaps.append(f"Account lockout threshold is {lockout_thresh or 'disabled'} (should lock after <= 5 failed attempts)")
        if max_age > 180:
            pw_gaps.append(f"Password expiration age is {max_age} days without breached-credential screening")

        if pw_gaps:
            findings.append(_create_finding(
                pillar="🔑 Identity & Access Controls",
                check_name="Password Policy & Credential Hardening",
                severity="MEDIUM",
                status="FAIL",
                detail=f"Password configuration exhibits {len(pw_gaps)} gap(s) against NIST SP 800-63B guidelines.",
                remediation="Update password policy: minimum 12-16 characters, enforce account lockout after 5 consecutive failures, enable breached password screening (HaveIBeenPwned API), and allow passphrases.",
                evidence=pw_gaps,
                mitre_technique="T1110",
            ))
        else:
            findings.append(_create_finding(
                pillar="🔑 Identity & Access Controls",
                check_name="Password Policy & Credential Hardening",
                severity="LOW",
                status="PASS",
                detail="Password security policies meet or exceed industry minimum standards.",
                remediation="Encourage adoption of enterprise password managers (1Password, Bitwarden) for all employees.",
                mitre_technique="T1110",
            ))
    else:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Password Policy & Credential Hardening",
            severity="MEDIUM",
            status="WARN",
            detail="Password complexity and lockout policy was not provided.",
            remediation="Audit password configuration: mandate min 12-16 characters, account lockout after 5 attempts, and passphrases.",
            mitre_technique="T1110",
        ))

    # 2.3 Least Privilege Enforcement (Excessive Admins, Service Accounts, Wildcard API Keys)
    admin_accounts: List[str] = payload.get("admin_accounts") or []
    svc_admin_accounts: List[str] = payload.get("service_accounts_admin") or []
    wildcard_api_keys: List[str] = payload.get("wildcard_api_keys") or []
    privilege_issues: List[str] = []

    if len(admin_accounts) > 5:
        privilege_issues.append(f"Excessive administrative accounts: {len(admin_accounts)} users hold domain/root/admin privileges")
    if svc_admin_accounts:
        privilege_issues.append(f"Over-privileged service accounts: {len(svc_admin_accounts)} machine identity(s) granted full administrative rights")
    if wildcard_api_keys:
        privilege_issues.append(f"Wildcard / unrestricted API keys detected: {len(wildcard_api_keys)} key(s) with full administrative scope")

    if privilege_issues:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Least Privilege Enforcement & Administrative Exposure",
            severity="HIGH",
            status="FAIL",
            detail=f"Least-privilege auditing revealed {len(privilege_issues)} area(s) of excessive administrative access.",
            remediation="Enforce Principle of Least Privilege (PoLP). Demote permanent admin accounts; implement Just-In-Time (JIT) privileged access management (PAM). Restrict API key scopes to specific resources and endpoints.",
            evidence=privilege_issues,
            mitre_technique="T1078.004",
        ))
    else:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Least Privilege Enforcement & Administrative Exposure",
            severity="LOW",
            status="PASS",
            detail="Administrative privileges and service account permissions appear constrained and well-managed.",
            remediation="Conduct quarterly access reviews to re-certify administrative entitlements.",
            mitre_technique="T1078.004",
        ))

    # 2.4 Orphaned & Inactive Accounts
    stale_accounts: List[str] = payload.get("stale_accounts") or []
    dormant_service_principals: List[str] = payload.get("dormant_service_principals") or []
    all_stale = stale_accounts + dormant_service_principals

    if all_stale:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Orphaned & Inactive Accounts Auditing",
            severity="HIGH",
            status="FAIL",
            detail=f"Discovered {len(all_stale)} stale/orphaned account(s) or dormant credentials (>60-90 days inactive).",
            remediation="Immediately disable or delete all accounts belonging to former employees or decommissioned services. Implement automated HR-to-IdP lifecycle management (SCIM) to deprovision users within 24 hours of departure.",
            evidence=[f"Inactive account: {a}" for a in all_stale[:10]],
            mitre_technique="T1078.002",
        ))
    else:
        findings.append(_create_finding(
            pillar="🔑 Identity & Access Controls",
            check_name="Orphaned & Inactive Accounts Auditing",
            severity="LOW",
            status="PASS",
            detail="No orphaned or unmanaged dormant accounts detected.",
            remediation="Automate 90-day inactivity account suspension in Active Directory / Azure AD.",
            mitre_technique="T1078.002",
        ))

    return findings


# ---------------------------------------------------------------------------
# Pillar 3: 🌐 Network & Border Defenses
# ---------------------------------------------------------------------------

def audit_network_defenses(payload: Dict[str, Any], flow_data: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 3.1 Firewall & ACL Configurations (Any-to-Any Rules & Direct Internet Exposure)
    firewall_rules: List[Dict[str, Any]] = payload.get("firewall_rules") or []
    any_to_any_rules = [
        r for r in firewall_rules
        if str(r.get("src", "")).strip().lower() in ("any", "0.0.0.0/0", "*")
        and str(r.get("dst", "")).strip().lower() in ("any", "0.0.0.0/0", "*")
        and str(r.get("action", "allow")).strip().lower() == "allow"
    ]

    exposed_management_ports = [
        r for r in firewall_rules
        if str(r.get("src", "")).strip().lower() in ("any", "0.0.0.0/0", "*")
        and str(r.get("action", "allow")).strip().lower() == "allow"
        and int(r.get("port", 0)) in (22, 23, 3389, 445, 5985, 5986, 27017, 6379)
    ]

    fw_evidence: List[str] = []
    if any_to_any_rules:
        fw_evidence.extend([
            f"Any-to-Any Rule: '{r.get('name', 'Rule')}' (src:{r.get('src')} -> dst:{r.get('dst')}:{r.get('port','*')})"
            for r in any_to_any_rules
        ])
    if exposed_management_ports:
        fw_evidence.extend([
            f"Exposed Admin Port: '{r.get('name', 'Rule')}' allows 0.0.0.0/0 inbound to port {r.get('port')}"
            for r in exposed_management_ports
        ])

    if fw_evidence:
        findings.append(_create_finding(
            pillar="🌐 Network & Border Defenses",
            check_name="Firewall & Perimeter ACL Configuration",
            severity="CRITICAL",
            status="FAIL",
            detail=f"Identified {len(fw_evidence)} dangerously permissive firewall rule(s) permitting unrestricted external traffic.",
            remediation="Implement strict Default-Deny ingress and egress rules. Remove all Any-to-Any allow rules. Restrict administrative services (SSH, RDP, DBs) behind an IP-allowlisted bastion host or WireGuard/IPsec VPN.",
            evidence=fw_evidence,
            mitre_technique="T1562.004",
        ))
    elif firewall_rules:
        findings.append(_create_finding(
            pillar="🌐 Network & Border Defenses",
            check_name="Firewall & Perimeter ACL Configuration",
            severity="LOW",
            status="PASS",
            detail="Firewall rules follow restrictive principles; no unrestricted Any-to-Any allow rules found.",
            remediation="Perform regular firewall rule re-certification to eliminate obsolete rules.",
            mitre_technique="T1562.004",
        ))

    # 3.2 External-to-Internal Exposure (Correlated with PCAP Flow Data)
    if flow_data:
        private_subnets = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
        exposed_inbound: List[str] = []

        for f in flow_data:
            s_ip = str(f.get("src_ip", ""))
            d_ip = str(f.get("dst_ip", ""))
            dport = int(f.get("dport", 0))

            s_priv = any(s_ip.startswith(pfx) for pfx in private_subnets)
            d_priv = any(d_ip.startswith(pfx) for pfx in private_subnets)

            # Inbound flow from external to internal on sensitive port
            if not s_priv and d_priv and dport in LEGACY_PORTS:
                exposed_inbound.append(f"External {s_ip} -> Internal {d_ip}:{dport} ({LEGACY_PORTS[dport][0]})")

        if exposed_inbound:
            findings.append(_create_finding(
                pillar="🌐 Network & Border Defenses",
                check_name="Internal Service Exposure via Traffic Ingress",
                severity="CRITICAL",
                status="FAIL",
                detail=f"PCAP flow inspection confirmed {len(exposed_inbound)} active connection(s) from external IPs directly hitting internal private assets on sensitive service ports.",
                remediation="Block direct external access to internal subnets at the boundary gateway. Deploy a demilitarized zone (DMZ) with reverse proxies and Web Application Firewalls (WAF).",
                evidence=list(set(exposed_inbound))[:8],
                mitre_technique="T1190",
            ))

    # 3.3 Missing HTTP Security Headers
    http_headers: Dict[str, str] = payload.get("http_response_headers") or {}
    if http_headers:
        lowered_headers = {k.lower(): v for k, v in http_headers.items()}
        missing_hdr_evidence: List[str] = []

        for req_hdr, (hdr_desc, _) in REQUIRED_HTTP_HEADERS.items():
            if req_hdr.lower() not in lowered_headers:
                missing_hdr_evidence.append(f"Missing: {req_hdr} – {hdr_desc}")

        # Check HSTS attributes
        if "strict-transport-security" in lowered_headers:
            hsts_val = lowered_headers["strict-transport-security"]
            if "includesubdomains" not in hsts_val.lower() or "max-age" not in hsts_val.lower():
                missing_hdr_evidence.append(f"Suboptimal HSTS configuration: '{hsts_val}' (recommend max-age=31536000; includeSubDomains; preload)")

        if missing_hdr_evidence:
            findings.append(_create_finding(
                pillar="🌐 Network & Border Defenses",
                check_name="Missing Web Application Security Headers",
                severity="MEDIUM",
                status="FAIL",
                detail=f"{len(missing_hdr_evidence)} critical security header(s) absent or weakly configured on the web application.",
                remediation="Configure web server / CDN (Cloudflare, Nginx, Apache) to emit all recommended security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.",
                evidence=missing_hdr_evidence,
                mitre_technique="T1189",
            ))
        else:
            findings.append(_create_finding(
                pillar="🌐 Network & Border Defenses",
                check_name="Missing Web Application Security Headers",
                severity="LOW",
                status="PASS",
                detail="All recommended HTTP security headers are present and enforced.",
                remediation="Routinely test your domain against https://securityheaders.com for grade A+ maintenance.",
                mitre_technique="T1189",
            ))

    # 3.4 Information Disclosure (Banners, Stack Traces, Internal IP Leaks)
    server_banner = str(payload.get("server_banner", "")).strip()
    stack_trace_leak = payload.get("stack_trace_in_errors", False)
    internal_ip_leak = payload.get("internal_ip_disclosed", False)
    leak_evidence: List[str] = []

    if server_banner:
        leaky_tokens = ["apache/", "nginx/", "iis/", "openssl/", "php/", "python/", "microsoft-iis/", "tomcat/", "express/"]
        for tok in leaky_tokens:
            if tok in server_banner.lower():
                leak_evidence.append(f"Server Banner leaks version: '{server_banner}'")
                break

    if stack_trace_leak:
        leak_evidence.append("Error pages reveal detailed stack traces, file paths, and environment internals")
    if internal_ip_leak:
        leak_evidence.append("HTTP headers (e.g. X-Forwarded-Server) or response bodies reveal internal RFC1918 IP addresses")

    if leak_evidence:
        findings.append(_create_finding(
            pillar="🌐 Network & Border Defenses",
            check_name="Information Disclosure & Banner Leakage",
            severity="MEDIUM",
            status="FAIL",
            detail=f"Discovered {len(leak_evidence)} information disclosure vulnerability(s) aiding adversary reconnaissance.",
            remediation="Suppress server identification headers (e.g., 'ServerTokens Prod', 'server_tokens off', remove 'X-Powered-By'). Replace default exception pages with generic user-friendly error views.",
            evidence=leak_evidence,
            mitre_technique="T1592",
        ))
    else:
        findings.append(_create_finding(
            pillar="🌐 Network & Border Defenses",
            check_name="Information Disclosure & Banner Leakage",
            severity="LOW",
            status="PASS",
            detail="Server banners and error handling do not leak software versions or internal network topology.",
            remediation="Ensure custom error pages (404, 500) remain sanitized during future code deployments.",
            mitre_technique="T1592",
        ))

    return findings


# ---------------------------------------------------------------------------
# Pillar 4: 📝 Monitoring & Resilience
# ---------------------------------------------------------------------------

def audit_monitoring_and_resilience(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 4.1 Logging and Audit Trails (Centralized SIEM, Log Sources, Retention)
    siem_configured = payload.get("siem_configured", None)
    log_types_collected: List[str] = [str(l).lower().replace(" ", "_") for l in (payload.get("log_types_collected") or [])]
    log_retention_days = int(payload.get("log_retention_days") or 30)
    tamper_resistant_logging = payload.get("tamper_resistant_logging", False)

    critical_sources = {
        "authentication_failures": "Authentication failures & brute force telemetry",
        "privilege_escalation":   "Privilege escalation events (sudo, UAC, IAM role assumptions)",
        "system_changes":         "System configuration changes & File Integrity Monitoring (FIM)",
        "network_flows":          "Network perimeter flow logs & firewall deny records",
    }

    if siem_configured is False:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Logging & Centralized SIEM Aggregation",
            severity="HIGH",
            status="FAIL",
            detail="No Security Information and Event Management (SIEM) or centralized log aggregation platform is deployed.",
            remediation="Deploy a centralized SIEM (Splunk, Elastic SIEM, Microsoft Sentinel, Wazuh, or Datadog Security). Ensure logs from servers, firewalls, and cloud accounts forward to an immutable centralized store.",
            mitre_technique="T1562.002",
        ))
    elif siem_configured is True:
        missing_sources = [f"{desc} ('{k}')" for k, desc in critical_sources.items() if k not in log_types_collected]
        logging_evidence: List[str] = []

        if missing_sources:
            logging_evidence.extend([f"Missing Log Source: {s}" for s in missing_sources])
        if log_retention_days < 90:
            logging_evidence.append(f"Log retention is only {log_retention_days} days (PCI-DSS & SOC2 mandate >= 365 days)")
        if not tamper_resistant_logging:
            logging_evidence.append("Log repository lacks write-once / tamper-resistance protection against malicious wiping")

        if logging_evidence:
            findings.append(_create_finding(
                pillar="📝 Monitoring & Resilience",
                check_name="Logging & Centralized SIEM Aggregation",
                severity="MEDIUM",
                status="WARN",
                detail=f"SIEM is operating, but has {len(logging_evidence)} coverage or retention weakness(es).",
                remediation="Forward all authentication, privilege, and network flow logs to the SIEM. Extend hot/warm log retention to at least 365 days and enable AWS CloudTrail / WORM log immutability.",
                evidence=logging_evidence,
                mitre_technique="T1562.002",
            ))
        else:
            findings.append(_create_finding(
                pillar="📝 Monitoring & Resilience",
                check_name="Logging & Centralized SIEM Aggregation",
                severity="LOW",
                status="PASS",
                detail="SIEM collects all 4 critical security telemetry streams with adequate retention and tamper resistance.",
                remediation="Routinely simulate attack scenarios (e.g. Atomic Red Team) to validate detection rules and alerting pipelines.",
                mitre_technique="T1562.002",
            ))
    else:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Logging & Centralized SIEM Aggregation",
            severity="MEDIUM",
            status="WARN",
            detail="SIEM telemetry status was not specified in the assessment input.",
            remediation="Verify that system auditd, auth.log, Windows Security Events, and cloud audit logs forward to a dedicated log repository.",
            mitre_technique="T1562.002",
        ))

    # 4.2 Backup Integrity & Ransomware Resilience (3-2-1 Rule, Immutability, Restoration Drills)
    backup_configured = payload.get("backup_configured", None)
    backup_tested = payload.get("backup_restore_tested", None)
    backup_immutable = payload.get("backup_offsite_or_immutable", None)
    rpo_hours = payload.get("rpo_hours", None)

    backup_issues: List[str] = []
    if backup_configured is False:
        backup_issues.append("No system or database backup solution is currently configured")
    if backup_tested is False:
        backup_issues.append("Backups have never undergone recovery validation drills (unverified restore integrity)")
    if backup_immutable is False:
        backup_issues.append("Backups are stored online with identical credentials, leaving them vulnerable to ransomware encryption")
    if rpo_hours is not None and rpo_hours > 24:
        backup_issues.append(f"Recovery Point Objective is {rpo_hours} hours (exceeds recommended 24-hour limit)")

    if backup_issues:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Backup Integrity & Ransomware Resilience",
            severity="HIGH",
            status="FAIL",
            detail=f"Backup and business continuity architecture exhibits {len(backup_issues)} critical resilience vulnerability(s).",
            remediation="Implement the 3-2-1-1-0 backup rule: 3 copies, 2 different media, 1 offsite, 1 immutable (WORM / air-gapped), and 0 recovery errors. Schedule mandatory quarterly restore drills.",
            evidence=backup_issues,
            mitre_technique="T1486",
        ))
    elif backup_configured is True and backup_tested is True and backup_immutable is True:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Backup Integrity & Ransomware Resilience",
            severity="LOW",
            status="PASS",
            detail="Backups are actively configured, regularly tested for restoration, and stored with immutable/air-gapped ransomware protection.",
            remediation="Conduct an annual tabletop disaster recovery exercise simulating complete datacenter loss.",
            mitre_technique="T1486",
        ))
    else:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Backup Integrity & Ransomware Resilience",
            severity="MEDIUM",
            status="WARN",
            detail="Backup configuration partially documented; unable to conclusively verify immutable recovery capabilities.",
            remediation="Document Recovery Time Objectives (RTO), Recovery Point Objectives (RPO), and conduct a verified restore test.",
            mitre_technique="T1486",
        ))

    # Audit depth note if PCAP flows present
    flows_count = int(payload.get("total_flows_analysed", 0))
    if flows_count > 0:
        findings.append(_create_finding(
            pillar="📝 Monitoring & Resilience",
            check_name="Forensic Audit Trail (Packet Capture Depth)",
            severity="INFO",
            status="INFO",
            detail=f"Correlated {flows_count} packet flows into the vulnerability scan. Full PCAP / flow logging enables retrospective threat hunting.",
            remediation="Retain PCAP captures or NetFlow archives for at least 90 days for forensic investigation.",
            mitre_technique="T1040",
        ))

    return findings


# ---------------------------------------------------------------------------
# AI Threat Advisor & Heuristic Summary Generator
# ---------------------------------------------------------------------------

def generate_ai_soc_summary(findings: List[Dict[str, Any]], risk_band: str, risk_score: float) -> str:
    """
    Generate an executive-level AI SOC summary and action plan.
    Attempts to use Google Gemini if configured, otherwise falls back to a deterministic SOC expert engine.
    """
    critical_fails = [f for f in findings if f["severity"] == "CRITICAL" and f["status"] == "FAIL"]
    high_fails = [f for f in findings if f["severity"] == "HIGH" and f["status"] == "FAIL"]
    failed_count = len(critical_fails) + len(high_fails)

    # Check if Gemini is configured in the environment and online calls are explicitly enabled
    gemini_key = os.getenv("GEMINI_API_KEY")
    use_online_llm = os.getenv("ENABLE_GEMINI_ONLINE", "false").lower() in ("true", "1", "yes")

    if gemini_key and use_online_llm:
        try:
            import socket
            orig_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(4.0)
            try:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                model = genai.GenerativeModel("gemma-3-1b-it")

                prompt = f"""You are the Lead SOC Security Analyst for DOT Sentinel AI.
Analyze these vulnerability scan findings and provide a concise, professional 3-paragraph executive incident advisory:
Risk Band: {risk_band} ({risk_score}% overall risk score)
Critical Gaps: {[f['check'] for f in critical_fails]}
High Gaps: {[f['check'] for f in high_fails]}

Structure:
1. Executive Risk Assessment: What is the current threat posture?
2. Threat Vector Analysis: How can an adversary chain these vulnerabilities (e.g. via MITRE ATT&CK techniques)?
3. Immediate 72-Hour Triage Roadmap: 3 bullet points of highest priority fixes."""

                response = model.generate_content(prompt, generation_config={"temperature": 0.2, "max_output_tokens": 450})
                if response and response.text:
                    return response.text.strip()
            finally:
                socket.setdefaulttimeout(orig_timeout)
        except Exception:
            pass  # Fall back to heuristic engine

    # Deterministic SOC Expert Engine
    lines = [
        f"**DOT Sentinel SOC Advisory [Risk Band: {risk_band} | Posture Gap Index: {risk_score}%]**",
        "",
        f"**1. Threat Posture Analysis:**",
        f"The audited environment presents an overall **{risk_band}** risk level with {failed_count} high/critical vulnerabilities identified across the four security pillars. ",
    ]

    if critical_fails:
        lines.append(f"Immediate exposure is dominated by critical deficiencies in: {', '.join([c['check'] for c in critical_fails[:3]])}. These flaws expose the network to automated exploitation, ransomware lateral movement, and unauthorized credential abuse.")
    else:
        lines.append("No immediate critical perimeter breaches were detected, but defensive gaps exist that could be exploited in secondary stages of an attack chain.")

    lines.extend([
        "",
        "**2. MITRE ATT&CK Adversary Exploit Chain:**",
        "An adversary targeting this architecture would likely leverage public network discovery (`T1046`) against exposed legacy protocols, utilize valid/default accounts (`T1078`) to achieve initial access, bypass weakly enforced identity boundaries (`T1110`), and attempt data extortion or encryption (`T1486`) against non-immutable backups.",
        "",
        "**3. Immediate 72-Hour Remediation Actions:**",
    ])

    if critical_fails:
        for idx, cf in enumerate(critical_fails[:3], 1):
            lines.append(f"{idx}. **{cf['check']}**: {cf['remediation']}")
    elif high_fails:
        for idx, hf in enumerate(high_fails[:3], 1):
            lines.append(f"{idx}. **{hf['check']}**: {hf['remediation']}")
    else:
        lines.append("1. Maintain continuous network traffic inspection and port auditing.")
        lines.append("2. Implement automated dependency scanning in deployment pipelines.")
        lines.append("3. Execute quarterly disaster recovery and backup restoration simulations.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Master Scanner Entry Point
# ---------------------------------------------------------------------------

def run_vulnerability_scan(payload: Dict[str, Any], flow_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Execute end-to-end vulnerability scanning across all 4 pillars and return structured assessment results.
    """
    all_findings: List[Dict[str, Any]] = []

    # Run the 4 pillars
    all_findings.extend(audit_system_and_software(payload))
    all_findings.extend(audit_identity_and_access(payload))
    all_findings.extend(audit_network_defenses(payload, flow_data))
    all_findings.extend(audit_monitoring_and_resilience(payload))

    # Quantitative Risk Scoring
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    status_weights = {"FAIL": 1.0, "WARN": 0.5, "PASS": 0.0, "INFO": 0.0}

    actual_score = sum(severity_weights.get(f["severity"], 0) * status_weights.get(f["status"], 0) for f in all_findings)
    max_score = sum(severity_weights.get(f["severity"], 0) for f in all_findings)

    risk_score_pct = round((actual_score / max_score * 100), 1) if max_score > 0 else 0.0

    if risk_score_pct >= 55:
        risk_band = "CRITICAL"
    elif risk_score_pct >= 35:
        risk_band = "HIGH"
    elif risk_score_pct >= 15:
        risk_band = "MEDIUM"
    else:
        risk_band = "LOW"

    # Aggregated metrics
    severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    pillar_counts: Dict[str, Dict[str, int]] = {}

    for f in all_findings:
        cat = f["category"]
        if cat not in pillar_counts:
            pillar_counts[cat] = {"FAIL": 0, "WARN": 0, "PASS": 0, "INFO": 0}
        pillar_counts[cat][f["status"]] = pillar_counts[cat].get(f["status"], 0) + 1

        if f["status"] == "FAIL" and f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    # AI SOC Threat Advisory
    ai_soc_report = generate_ai_soc_summary(all_findings, risk_band, risk_score_pct)

    return {
        "status": "success",
        "total_checks": len(all_findings),
        "risk_score_pct": risk_score_pct,
        "risk_band": risk_band,
        "severity_counts": severity_counts,
        "pillar_summary": pillar_counts,
        "ai_soc_report": ai_soc_report,
        "findings": all_findings,
    }
