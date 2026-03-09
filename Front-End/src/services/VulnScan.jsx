import { useState, useRef } from "react"
import { API_BASE_URL } from "../config"

/* ============================================================
   Design Tokens & Color Palette (Harmonized with Dot-Sentinel)
   ============================================================ */
const SEVERITY_COLOR = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#10b981",
  INFO:     "#009dff",
}

const STATUS_ICON = {
  FAIL: "✗",
  WARN: "⚠",
  PASS: "✓",
  INFO: "ℹ",
}

const STATUS_COLOR = {
  FAIL: "#ef4444",
  WARN: "#eab308",
  PASS: "#10b981",
  INFO: "#009dff",
}

/* ============================================================
   Initial Audit Configuration
   ============================================================ */
const INITIAL_CONFIG = {
  os_name: "",
  installed_applications: [],
  has_unpatched_cves: false,
  observed_ports: [],
  protocols_seen: [],
  tls_ciphers: [],
  disk_encryption_enabled: false,
  database_encryption_at_rest: false,
  backup_encryption_enabled: false,
  default_credentials_present: false,
  default_secret_keys_detected: [],
  mfa_enabled: false,
  mfa_enforced_for_admins: false,
  mfa_type: "totp",
  password_policy: {
    min_length: 12,
    requires_complexity: true,
    max_age_days: 90,
    lockout_threshold: 5,
    check_breached_passwords: true
  },
  admin_accounts: [],
  service_accounts_admin: [],
  wildcard_api_keys: [],
  stale_accounts: [],
  dormant_service_principals: [],
  firewall_rules: [],
  http_response_headers: {},
  server_banner: "",
  stack_trace_in_errors: false,
  internal_ip_disclosed: false,
  siem_configured: false,
  log_types_collected: [],
  log_retention_days: 30,
  tamper_resistant_logging: false,
  backup_configured: false,
  backup_restore_tested: false,
  backup_offsite_or_immutable: false,
  rpo_hours: 24,
  total_flows_analysed: 0
}

/* ============================================================
   Semi-Circular SVG Risk Gauge
   ============================================================ */
function RiskGauge({ score, band }) {
  const clamp = Math.max(0, Math.min(100, score || 0))
  const color =
    band === "CRITICAL" ? SEVERITY_COLOR.CRITICAL :
    band === "HIGH"     ? SEVERITY_COLOR.HIGH :
    band === "MEDIUM"   ? SEVERITY_COLOR.MEDIUM : SEVERITY_COLOR.LOW

  const r = 50
  const circumference = Math.PI * r
  const dashOffset = circumference * (1 - clamp / 100)

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: "140px" }}>
      <svg width="140" height="85" viewBox="0 0 140 85">
        <path
          d="M 20,70 A 50,50 0 0,1 120,70"
          fill="none"
          stroke="rgba(255, 255, 255, 0.1)"
          strokeWidth="10"
          strokeLinecap="round"
        />
        <path
          d="M 20,70 A 50,50 0 0,1 120,70"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: "stroke-dashoffset 1s ease-in-out, stroke 0.5s ease" }}
        />
        <text
          x="70"
          y="62"
          textAnchor="middle"
          fill="#FFFFFF"
          fontSize="22"
          fontWeight="bold"
          fontFamily="system-ui, sans-serif"
        >
          {clamp}%
        </text>
        <text
          x="70"
          y="78"
          textAnchor="middle"
          fill={color}
          fontSize="11"
          fontWeight="700"
          letterSpacing="1.2px"
          fontFamily="system-ui, sans-serif"
        >
          {band}
        </text>
      </svg>
      <span style={{ fontSize: "0.75rem", color: "rgba(255, 255, 255, 0.6)", marginTop: "2px" }}>
        Posture Risk Index
      </span>
    </div>
  )
}

/* ============================================================
   Collapsible Finding Card Component
   ============================================================ */
function FindingItem({ finding }) {
  const [expanded, setExpanded] = useState(false)
  const { category, check, severity, status, detail, remediation, evidence, mitre_technique } = finding

  const sevColor = SEVERITY_COLOR[severity] || "#aaa"
  const statColor = STATUS_COLOR[status] || "#aaa"

  return (
    <div
      style={{
        borderRadius: "8px",
        border: `1px solid ${sevColor}33`,
        background: `linear-gradient(135deg, rgba(20, 20, 24, 0.85) 0%, ${sevColor}0a 100%)`,
        overflow: "hidden",
        marginBottom: "0.5rem",
        transition: "all 0.2s ease",
      }}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          width: "100%",
          padding: "0.75rem 1rem",
          background: "transparent",
          border: "none",
          color: "#fff",
          display: "flex",
          alignItems: "center",
          gap: "0.75rem",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span
          style={{
            width: "24px",
            height: "24px",
            borderRadius: "50%",
            background: `${statColor}22`,
            border: `1px solid ${statColor}`,
            color: statColor,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "0.85rem",
            fontWeight: "bold",
            flexShrink: 0,
          }}
        >
          {STATUS_ICON[status] || "?"}
        </span>

        <span style={{ flex: 1, fontSize: "0.9rem", fontWeight: "600", color: "#f3f4f6" }}>
          {check}
        </span>

        {mitre_technique && (
          <span
            style={{
              padding: "0.15rem 0.45rem",
              borderRadius: "4px",
              fontSize: "0.7rem",
              fontFamily: "monospace",
              background: "rgba(112, 0, 255, 0.2)",
              color: "#c084fc",
              border: "1px solid rgba(112, 0, 255, 0.4)",
            }}
          >
            {mitre_technique}
          </span>
        )}

        <span
          style={{
            padding: "0.15rem 0.5rem",
            borderRadius: "4px",
            fontSize: "0.7rem",
            fontWeight: "700",
            background: `${sevColor}22`,
            color: sevColor,
            border: `1px solid ${sevColor}44`,
            letterSpacing: "0.5px",
          }}
        >
          {severity}
        </span>

        <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.75rem", transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.2s" }}>
          ▶
        </span>
      </button>

      {expanded && (
        <div style={{ padding: "0.5rem 1rem 1rem 1rem", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", flexDirection: "column", gap: "0.6rem" }}>
          <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.45)" }}>
            Category: <strong style={{ color: "rgba(255,255,255,0.8)" }}>{category}</strong>
          </div>

          <div style={{ background: "rgba(0,0,0,0.3)", padding: "0.6rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem", lineHeight: "1.45" }}>
            <span style={{ color: "#a78bfa", fontWeight: "600" }}>Analysis: </span>{detail}
          </div>

          {evidence && evidence.length > 0 && (
            <div style={{ background: "rgba(0,0,0,0.2)", padding: "0.5rem 0.8rem", borderRadius: "6px" }}>
              <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginBottom: "0.3rem" }}>
                Identified Indicators & Evidence:
              </div>
              <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.8rem", color: "#fbbf24", fontFamily: "monospace" }}>
                {evidence.map((ev, idx) => (
                  <li key={idx} style={{ marginBottom: "0.2rem" }}>{ev}</li>
                ))}
              </ul>
            </div>
          )}

          <div style={{ background: "rgba(0, 157, 255, 0.08)", border: "1px solid rgba(0, 157, 255, 0.25)", padding: "0.6rem 0.8rem", borderRadius: "6px", fontSize: "0.82rem", lineHeight: "1.45" }}>
            <span style={{ color: "rgb(0, 157, 255)", fontWeight: "600" }}>Remediation: </span>{remediation}
          </div>
        </div>
      )}
    </div>
  )
}

/* ============================================================
   Main VulnScan Component
   ============================================================ */
export default function VulnScan() {
  const [activeTab, setActiveTab] = useState("system") // system | identity | network | monitoring
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [scanError, setScanError] = useState(null)
  const [sevFilter, setSevFilter] = useState("ALL")
  const [searchQuery, setSearchQuery] = useState("")

  // Form State
  const [formData, setFormData] = useState(INITIAL_CONFIG)

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handlePasswordPolicyChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      password_policy: { ...prev.password_policy, [field]: value }
    }))
  }

  const [auditMode, setAuditMode] = useState("form") // form | pcap
  const [pcapFile, setPcapFile] = useState(null)

  /* ============================================================
     Execute Scan: Call backend API (/vuln-scan or /vuln-scan-pcap)
     Strictly genuine reports - NO fake/simulated fallback
     ============================================================ */
  const runScan = async () => {
    const hasOs = Boolean(formData.os_name && formData.os_name.trim())
    const hasPorts = (formData.observed_ports || []).length > 0
    const hasProtocols = (formData.protocols_seen || []).length > 0
    const hasApps = (formData.installed_applications || []).length > 0
    const hasPcap = Boolean(pcapFile)

    if (auditMode === "form" && !hasOs && !hasPorts && !hasProtocols && !hasApps) {
      setScanError("Please configure at least one system parameter (Operating System, Observed Ports, or Protocols) before initiating an audit. Dot-Sentinel strictly assesses real target infrastructure; no simulated or fake reports will be generated.")
      return
    }

    if (auditMode === "pcap" && !hasPcap) {
      setScanError("Please select a .pcap or .pcapng network capture file to correlate for live posture audit. Dot-Sentinel strictly evaluates real packet captures; no simulated or fake reports will be generated.")
      return
    }

    setIsScanning(true)
    setScanError(null)

    try {
      let data
      if (auditMode === "pcap" && pcapFile) {
        const targetURL = window.location.hostname === "localhost"
          ? "/vuln-scan-pcap"
          : `${API_BASE_URL.replace(/\/$/, "")}/vuln-scan-pcap`

        const bodyFormData = new FormData()
        bodyFormData.append("file", pcapFile)
        bodyFormData.append("metadata", JSON.stringify(formData))

        const response = await fetch(targetURL, {
          method: "POST",
          body: bodyFormData,
        })

        if (!response.ok) {
          const errText = await response.text()
          let msg = `Backend error (${response.status})`
          try {
            const j = JSON.parse(errText)
            msg = j.detail || j.message || msg
          } catch {}
          throw new Error(msg)
        }

        data = await response.json()
      } else {
        const targetURL = window.location.hostname === "localhost"
          ? "/vuln-scan"
          : `${API_BASE_URL.replace(/\/$/, "")}/vuln-scan`

        const response = await fetch(targetURL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(formData),
        })

        if (!response.ok) {
          const errText = await response.text()
          let msg = `Backend error (${response.status})`
          try {
            const j = JSON.parse(errText)
            msg = j.detail || j.message || msg
          } catch {}
          throw new Error(msg)
        }

        data = await response.json()
      }

      setScanResult(data)

      // Archive genuine report into localStorage for historical analysis
      try {
        const existing = JSON.parse(localStorage.getItem("sentinel_reports") || "[]")
        const reportEntry = {
          id: `VULN-${Date.now().toString(36).toUpperCase()}`,
          name: auditMode === "pcap" && pcapFile ? pcapFile.name : (formData.os_name ? `Posture Audit (${formData.os_name})` : "Infrastructure Posture Audit"),
          date: new Date().toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          }),
          total_flows: data.total_flows_analysed || 0,
          campaigns: [
            {
              pattern: `Posture Audit: ${data.risk_band} (${data.risk_score_pct}% Risk Index)`,
              description: `Total checks audited: ${data.total_checks}. Critical findings: ${data.severity_counts?.CRITICAL || 0}, High: ${data.severity_counts?.HIGH || 0}.`,
              flows: (data.findings || []).filter(f => f.status === "FAIL").map(f => ({
                id: f.mitre_technique || "VULN",
                protocol: f.category || "Posture",
                sport: f.severity || "HIGH",
                dport: f.check || "Issue",
                anomaly_score: f.severity === "CRITICAL" ? 0.95 : f.severity === "HIGH" ? 0.8 : 0.5,
                features: {
                  remediation: f.remediation,
                  detail: f.detail
                }
              }))
            }
          ]
        }
        localStorage.setItem("sentinel_reports", JSON.stringify([reportEntry, ...existing]))
      } catch (saveErr) {
        console.warn("Could not save vulnerability report to localStorage", saveErr)
      }
    } catch (err) {
      console.error("Backend vulnerability scan failed:", err)
      setScanError(`Vulnerability Audit Failed: ${err.message}. Backend security engine is unreachable at ${API_BASE_URL}. Ensure the Python FastAPI service is running. No simulated or fake report will be generated.`)
      setScanResult(null)
    } finally {
      setIsScanning(false)
    }
  }

  /* ============================================================
     Export Handlers
     ============================================================ */
  const copyMarkdownReport = () => {
    if (!scanResult) return
    let md = `# DOT Sentinel AI — Security Vulnerability Audit Report\n`
    md += `**Risk Band:** ${scanResult.risk_band} (${scanResult.risk_score_pct}% Risk Index)\n`
    md += `**Total Checks Audited:** ${scanResult.total_checks}\n\n`
    md += `## AI SOC Executive Advisory\n${scanResult.ai_soc_report}\n\n`
    md += `## Detailed Findings\n`
    scanResult.findings.forEach(f => {
      md += `### [${f.status}] ${f.check} (${f.severity})\n`
      md += `- **Pillar:** ${f.category}\n`
      md += `- **Detail:** ${f.detail}\n`
      md += `- **Remediation:** ${f.remediation}\n`
      if (f.evidence && f.evidence.length > 0) {
        md += `- **Evidence:** ${f.evidence.join("; ")}\n`
      }
      md += `\n`
    })

    navigator.clipboard.writeText(md)
    alert("Vulnerability Assessment Report copied to clipboard as Markdown!")
  }

  const downloadJsonReport = () => {
    if (!scanResult) return
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `dot-sentinel-vuln-report-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Filtered findings
  const displayedFindings = (scanResult?.findings || []).filter(f => {
    if (sevFilter !== "ALL" && f.severity !== sevFilter && f.status !== sevFilter) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      const match = f.check.toLowerCase().includes(q) ||
                    f.detail.toLowerCase().includes(q) ||
                    f.remediation.toLowerCase().includes(q) ||
                    f.category.toLowerCase().includes(q)
      if (!match) return false
    }
    return true
  })

  return (
    <div
      style={{
        width: "100%",
        maxWidth: "100%",
        padding: "1rem 0",
        display: "flex",
        flexDirection: "column",
        gap: "1.2rem",
        color: "#EDEBDD",
        fontFamily: "Inter, system-ui, sans-serif",
      }}
    >
      {/* ───────────────── HEADER ───────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.8rem", borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: "0.8rem" }}>
        <div>
          <h2 style={{ margin: 0, fontSize: "1.3rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span>🛡️</span> Posture & Vulnerability Scanner
          </h2>
          <p style={{ margin: "0.2rem 0 0 0", fontSize: "0.8rem", color: "rgba(255,255,255,0.6)" }}>
            Four-Pillar Defensive Audit & MITRE ATT&CK Mapping
          </p>
        </div>
      </div>

      {/* ───────────────── SCAN ERROR BANNER ───────────────── */}
      {scanError && (
        <div
          style={{
            background: "rgba(239, 68, 68, 0.12)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
            borderRadius: "8px",
            padding: "0.85rem 1.1rem",
            color: "#fca5a5",
            fontSize: "0.85rem",
            display: "flex",
            alignItems: "flex-start",
            gap: "0.75rem",
            boxShadow: "0 4px 15px rgba(239, 68, 68, 0.15)",
          }}
        >
          <span style={{ fontSize: "1.2rem", lineHeight: 1 }}>⚠️</span>
          <div style={{ flex: 1, lineHeight: 1.5 }}>
            <strong style={{ display: "block", color: "#ef4444", marginBottom: "0.2rem", fontSize: "0.9rem" }}>
              Vulnerability Audit Stopped
            </strong>
            <span>{scanError}</span>
          </div>
          <button
            onClick={() => setScanError(null)}
            style={{
              background: "transparent",
              border: "none",
              color: "#fca5a5",
              cursor: "pointer",
              fontSize: "1rem",
              lineHeight: 1,
              padding: "0 0.2rem",
            }}
            title="Dismiss"
          >
            ✕
          </button>
        </div>
      )}

      {/* ───────────────── AUDIT MODE SELECTOR ───────────────── */}
      {!scanResult && (
        <div style={{ display: "flex", gap: "0.5rem", background: "rgba(0,0,0,0.4)", padding: "0.3rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <button
            onClick={() => setAuditMode("form")}
            style={{
              flex: 1,
              padding: "0.55rem 0.5rem",
              borderRadius: "6px",
              border: "none",
              cursor: "pointer",
              fontSize: "0.8rem",
              fontWeight: auditMode === "form" ? "700" : "500",
              background: auditMode === "form" ? "rgba(0, 157, 255, 0.22)" : "transparent",
              color: auditMode === "form" ? "#00f0ff" : "rgba(255,255,255,0.6)",
              transition: "all 0.2s",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.4rem"
            }}
          >
            <span>⚙️</span> System Posture Parameters
          </button>
          <button
            onClick={() => setAuditMode("pcap")}
            style={{
              flex: 1,
              padding: "0.55rem 0.5rem",
              borderRadius: "6px",
              border: "none",
              cursor: "pointer",
              fontSize: "0.8rem",
              fontWeight: auditMode === "pcap" ? "700" : "500",
              background: auditMode === "pcap" ? "rgba(0, 157, 255, 0.22)" : "transparent",
              color: auditMode === "pcap" ? "#00f0ff" : "rgba(255,255,255,0.6)",
              transition: "all 0.2s",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.4rem"
            }}
          >
            <span>📁</span> Correlate Live PCAP Capture
          </button>
        </div>
      )}

      {/* ───────────────── TAB NAVIGATION (FORM MODE) ───────────────── */}
      {!scanResult && auditMode === "form" && (
        <div style={{ display: "flex", gap: "0.3rem", background: "rgba(0,0,0,0.3)", padding: "0.3rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)" }}>
          {[
            { id: "system", label: "⚙️ System & Software" },
            { id: "identity", label: "🔑 Identity & Access" },
            { id: "network", label: "🌐 Network & Border" },
            { id: "monitoring", label: "📝 Monitoring & Resilience" },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                flex: 1,
                padding: "0.5rem 0.2rem",
                borderRadius: "6px",
                border: "none",
                cursor: "pointer",
                fontSize: "0.75rem",
                fontWeight: activeTab === tab.id ? "700" : "500",
                background: activeTab === tab.id ? "rgba(0, 157, 255, 0.2)" : "transparent",
                color: activeTab === tab.id ? "#00f0ff" : "rgba(255,255,255,0.6)",
                transition: "all 0.2s",
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* ───────────────── CONFIGURATION FORM TABS / PCAP UPLOAD ───────────────── */}
      {!scanResult && (
        <div style={{ background: "rgba(19, 19, 22, 0.7)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "10px", padding: "1rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          
          {/* AUDIT MODE: PCAP UPLOAD */}
          {auditMode === "pcap" && (
            <div
              onDragOver={e => e.preventDefault()}
              onDrop={e => {
                e.preventDefault()
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  setPcapFile(e.dataTransfer.files[0])
                  setScanError(null)
                }
              }}
              style={{
                border: "2px dashed rgba(0, 157, 255, 0.35)",
                borderRadius: "10px",
                padding: "2rem 1.5rem",
                textAlign: "center",
                background: "rgba(0, 157, 255, 0.03)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: "0.8rem",
              }}
            >
              <div style={{ fontSize: "2.4rem" }}>📦</div>
              <div>
                <p style={{ margin: 0, fontSize: "0.95rem", color: "#EDEBDD", fontWeight: "600" }}>
                  {pcapFile ? (
                    <span style={{ color: "#00f0ff" }}>Selected Capture: {pcapFile.name} ({(pcapFile.size / 1024).toFixed(1)} KB)</span>
                  ) : (
                    "Upload .pcap / .pcapng Network Trace"
                  )}
                </p>
                <p style={{ margin: "0.3rem 0 0 0", fontSize: "0.78rem", color: "rgba(255,255,255,0.5)" }}>
                  Extracts live active flows, discovers open ports and unencrypted protocols, and performs MITRE-aligned posture evaluation.
                </p>
              </div>

              <div style={{ display: "flex", gap: "0.8rem", alignItems: "center" }}>
                <label
                  style={{
                    padding: "0.5rem 1.2rem",
                    background: "rgba(0, 157, 255, 0.18)",
                    border: "1px solid rgba(0, 157, 255, 0.4)",
                    borderRadius: "6px",
                    fontSize: "0.82rem",
                    color: "#00f0ff",
                    cursor: "pointer",
                    fontWeight: "600",
                    transition: "all 0.2s"
                  }}
                >
                  {pcapFile ? "Choose Different File" : "Browse PCAP File"}
                  <input
                    type="file"
                    accept=".pcap,.pcapng"
                    style={{ display: "none" }}
                    onChange={e => {
                      if (e.target.files && e.target.files[0]) {
                        setPcapFile(e.target.files[0])
                        setScanError(null)
                      }
                    }}
                  />
                </label>
                {pcapFile && (
                  <button
                    onClick={() => setPcapFile(null)}
                    style={{
                      background: "transparent",
                      border: "none",
                      color: "#fca5a5",
                      fontSize: "0.8rem",
                      cursor: "pointer",
                      textDecoration: "underline"
                    }}
                  >
                    Clear selection
                  </button>
                )}
              </div>
            </div>
          )}

          {/* TAB 1: SYSTEM & SOFTWARE */}
          {auditMode === "form" && activeTab === "system" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                  Operating System & Version (EOL & Patch Check)
                </label>
                <input
                  type="text"
                  value={formData.os_name || ""}
                  onChange={e => handleInputChange("os_name", e.target.value)}
                  placeholder="e.g. Windows Server 2008 R2, Ubuntu 22.04 LTS"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Observed Open Ports (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={(formData.observed_ports || []).join(", ")}
                    onChange={e => handleInputChange("observed_ports", e.target.value.split(",").map(p => parseInt(p.trim())).filter(p => !isNaN(p)))}
                    placeholder="21, 23, 80, 443, 3389"
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Protocols in Transit
                  </label>
                  <input
                    type="text"
                    value={(formData.protocols_seen || []).join(", ")}
                    onChange={e => handleInputChange("protocols_seen", e.target.value.split(",").map(p => p.trim()).filter(Boolean))}
                    placeholder="HTTP, SSH, Telnet, FTP"
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Full Disk Encryption (BitLocker / LUKS)
                  </label>
                  <select
                    value={formData.disk_encryption_enabled === null ? "" : formData.disk_encryption_enabled ? "true" : "false"}
                    onChange={e => handleInputChange("disk_encryption_enabled", e.target.value === "" ? null : e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="true">Enabled (Encrypted)</option>
                    <option value="false">Disabled (Plaintext Disk)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Default Factory Credentials Active?
                  </label>
                  <select
                    value={formData.default_credentials_present ? "true" : "false"}
                    onChange={e => handleInputChange("default_credentials_present", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="false">No (Credentials Hardened)</option>
                    <option value="true">Yes (Unchanged Factory Defaults)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: IDENTITY & ACCESS */}
          {auditMode === "form" && activeTab === "identity" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Global Multi-Factor Authentication (MFA)
                  </label>
                  <select
                    value={formData.mfa_enabled ? "true" : "false"}
                    onChange={e => handleInputChange("mfa_enabled", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="true">Globally Enforced</option>
                    <option value="false">Disabled / Password Only</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    MFA Factor Type
                  </label>
                  <select
                    value={formData.mfa_type || "app"}
                    onChange={e => handleInputChange("mfa_type", e.target.value)}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="fido2">FIDO2 / Hardware Security Key</option>
                    <option value="app">TOTP App (Microsoft/Google)</option>
                    <option value="sms">SMS / Telephony (Legacy)</option>
                  </select>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Password Min Length (NIST recommends ≥12)
                  </label>
                  <input
                    type="number"
                    value={formData.password_policy?.min_length || 8}
                    onChange={e => handlePasswordPolicyChange("min_length", parseInt(e.target.value) || 8)}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Account Lockout After Failures
                  </label>
                  <input
                    type="number"
                    value={formData.password_policy?.lockout_threshold || 0}
                    onChange={e => handlePasswordPolicyChange("lockout_threshold", parseInt(e.target.value) || 0)}
                    placeholder="5"
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                  Administrative User Accounts (Least Privilege Audit)
                </label>
                <input
                  type="text"
                  value={(formData.admin_accounts || []).join(", ")}
                  onChange={e => handleInputChange("admin_accounts", e.target.value.split(",").map(a => a.trim()).filter(Boolean))}
                  placeholder="admin, root, sysadmin"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                  Orphaned & Stale Accounts (Departed staff / inactive)
                </label>
                <input
                  type="text"
                  value={(formData.stale_accounts || []).join(", ")}
                  onChange={e => handleInputChange("stale_accounts", e.target.value.split(",").map(a => a.trim()).filter(Boolean))}
                  placeholder="former_contractor, old_sysadmin"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                />
              </div>
            </div>
          )}

          {/* TAB 3: NETWORK & BORDER */}
          {auditMode === "form" && activeTab === "network" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                  Firewall Rules Configured (Review for Any-to-Any Exposure)
                </label>
                <textarea
                  rows="3"
                  value={JSON.stringify(formData.firewall_rules || [], null, 2)}
                  onChange={e => {
                    try {
                      handleInputChange("firewall_rules", JSON.parse(e.target.value))
                    } catch (_) {}
                  }}
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#a78bfa", fontFamily: "monospace", fontSize: "0.8rem" }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                  Server Identification Banner (Info Disclosure)
                </label>
                <input
                  type="text"
                  value={formData.server_banner || ""}
                  onChange={e => handleInputChange("server_banner", e.target.value)}
                  placeholder="e.g. Apache/2.4.29 (Ubuntu) OpenSSL/1.0.1f"
                  style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Stack Traces in Error Pages?
                  </label>
                  <select
                    value={formData.stack_trace_in_errors ? "true" : "false"}
                    onChange={e => handleInputChange("stack_trace_in_errors", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="false">Sanitized (Safe)</option>
                    <option value="true">Leaking Traces (Risk)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Internal IP Disclosure?
                  </label>
                  <select
                    value={formData.internal_ip_disclosed ? "true" : "false"}
                    onChange={e => handleInputChange("internal_ip_disclosed", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="false">Hidden</option>
                    <option value="true">Disclosed in Headers</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: MONITORING & RESILIENCE */}
          {auditMode === "form" && activeTab === "monitoring" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Centralized SIEM Configured
                  </label>
                  <select
                    value={formData.siem_configured ? "true" : "false"}
                    onChange={e => handleInputChange("siem_configured", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="true">Active SIEM (Splunk, Elastic, Sentinel)</option>
                    <option value="false">No SIEM Deployed</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Log Retention (Days)
                  </label>
                  <input
                    type="number"
                    value={formData.log_retention_days || 30}
                    onChange={e => handleInputChange("log_retention_days", parseInt(e.target.value) || 30)}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.8rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Backups Tested for Restoration?
                  </label>
                  <select
                    value={formData.backup_restore_tested ? "true" : "false"}
                    onChange={e => handleInputChange("backup_restore_tested", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="true">Yes (Quarterly Drill Verified)</option>
                    <option value="false">No (Untested Integrity)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "rgba(255,255,255,0.8)", marginBottom: "0.3rem" }}>
                    Immutable / Air-Gapped Backups?
                  </label>
                  <select
                    value={formData.backup_offsite_or_immutable ? "true" : "false"}
                    onChange={e => handleInputChange("backup_offsite_or_immutable", e.target.value === "true")}
                    style={{ width: "100%", padding: "0.5rem", borderRadius: "6px", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontSize: "0.85rem" }}
                  >
                    <option value="true">Yes (Ransomware-Proof WORM)</option>
                    <option value="false">No (Online Accessible)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* RUN AUDIT BUTTON */}
          <button
            onClick={runScan}
            disabled={isScanning}
            style={{
              marginTop: "0.5rem",
              padding: "0.75rem 1.5rem",
              background: isScanning ? "#374151" : "linear-gradient(90deg, #009dff 0%, #7000ff 100%)",
              border: "none",
              borderRadius: "8px",
              color: "#fff",
              fontWeight: "700",
              fontSize: "0.95rem",
              cursor: isScanning ? "not-allowed" : "pointer",
              boxShadow: "0 4px 15px rgba(0, 157, 255, 0.3)",
              transition: "all 0.2s",
            }}
          >
            {isScanning
              ? (auditMode === "pcap" ? "Ingesting PCAP & Correlating Posture..." : "Running Automated 4-Pillar Scan...")
              : (auditMode === "pcap" ? "🚀 Run PCAP Vulnerability Audit" : "🚀 Run Full Vulnerability Audit")}
          </button>
        </div>
      )}

      {/* ───────────────── RESULTS DASHBOARD ───────────────── */}
      {scanResult && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          
          {/* Top Metric Bar */}
          <div
            style={{
              background: "rgba(19, 19, 22, 0.85)",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: "10px",
              padding: "1rem",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "1rem",
            }}
          >
            <RiskGauge score={scanResult.risk_score_pct} band={scanResult.risk_band} />

            <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", flex: 1, minWidth: "220px" }}>
              <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "rgba(255,255,255,0.7)" }}>
                Audited Checks: <span style={{ color: "#fff" }}>{scanResult.total_checks}</span>
              </div>
              <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                {Object.entries(scanResult.severity_counts || {}).map(([sev, count]) => (
                  <span
                    key={sev}
                    style={{
                      padding: "0.2rem 0.5rem",
                      borderRadius: "4px",
                      fontSize: "0.7rem",
                      fontWeight: "700",
                      background: `${SEVERITY_COLOR[sev]}22`,
                      color: SEVERITY_COLOR[sev],
                      border: `1px solid ${SEVERITY_COLOR[sev]}44`,
                    }}
                  >
                    {count} {sev}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              <button
                onClick={copyMarkdownReport}
                title="Copy Markdown Report"
                style={{
                  background: "rgba(255,255,255,0.08)",
                  border: "1px solid rgba(255,255,255,0.15)",
                  color: "#fff",
                  padding: "0.4rem 0.7rem",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  cursor: "pointer",
                }}
              >
                📋 Copy MD
              </button>
              <button
                onClick={downloadJsonReport}
                title="Download JSON Report"
                style={{
                  background: "rgba(255,255,255,0.08)",
                  border: "1px solid rgba(255,255,255,0.15)",
                  color: "#fff",
                  padding: "0.4rem 0.7rem",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  cursor: "pointer",
                }}
              >
                💾 JSON
              </button>
              <button
                onClick={() => setScanResult(null)}
                style={{
                  background: "rgba(0, 157, 255, 0.2)",
                  border: "1px solid rgba(0, 157, 255, 0.4)",
                  color: "#00f0ff",
                  padding: "0.4rem 0.7rem",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  cursor: "pointer",
                  fontWeight: "600",
                }}
              >
                🔄 Re-configure
              </button>
            </div>
          </div>

          {/* AI SOC Executive Advisory Box */}
          {scanResult.ai_soc_report && (
            <div
              style={{
                background: "linear-gradient(135deg, rgba(112, 0, 255, 0.12) 0%, rgba(0, 157, 255, 0.08) 100%)",
                border: "1px solid rgba(112, 0, 255, 0.35)",
                borderRadius: "10px",
                padding: "1rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
                <span style={{ fontSize: "1.1rem" }}>🤖</span>
                <span style={{ fontSize: "0.85rem", fontWeight: "700", color: "#c084fc", letterSpacing: "0.5px" }}>
                  AI SOC Threat & Remediation Advisory (Gemini / Heuristic Engine)
                </span>
              </div>
              <div
                style={{
                  fontSize: "0.82rem",
                  lineHeight: "1.5",
                  color: "rgba(255,255,255,0.9)",
                  whiteSpace: "pre-line",
                  fontFamily: "system-ui, sans-serif",
                }}
              >
                {scanResult.ai_soc_report}
              </div>
            </div>
          )}

          {/* Filtering & Search Toolbar */}
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
            <input
              type="text"
              placeholder="Search findings (e.g. EOL, MFA, Firewall)..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                minWidth: "180px",
                padding: "0.4rem 0.75rem",
                borderRadius: "6px",
                background: "rgba(0,0,0,0.5)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                fontSize: "0.8rem",
              }}
            />

            <div style={{ display: "flex", gap: "0.2rem" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "PASS"].map(f => (
                <button
                  key={f}
                  onClick={() => setSevFilter(f)}
                  style={{
                    padding: "0.3rem 0.6rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.7rem",
                    fontWeight: sevFilter === f ? "700" : "500",
                    background: sevFilter === f ? "rgba(255,255,255,0.2)" : "rgba(0,0,0,0.4)",
                    color: sevFilter === f ? "#fff" : "rgba(255,255,255,0.5)",
                  }}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Findings List */}
          <div style={{ display: "flex", flexDirection: "column" }}>
            {displayedFindings.length === 0 ? (
              <div style={{ textAlign: "center", padding: "2rem", color: "rgba(255,255,255,0.4)", fontSize: "0.85rem" }}>
                No findings match the selected filters.
              </div>
            ) : (
              displayedFindings.map((finding, idx) => (
                <FindingItem key={idx} finding={finding} />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
