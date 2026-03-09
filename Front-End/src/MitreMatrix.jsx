import { useState } from "react"

export default function MitreMatrix() {
  const [selectedTactic, setSelectedTactic] = useState("Initial Access")

  const TACTICS_DATA = {
    "Initial Access": [
      { id: "T1190", name: "Exploit Public-Facing Application", desc: "Adversaries exploit unpatched software vulnerabilities (Log4Shell, Heartbleed, Spring4Shell) for remote code execution.", detection: "Payload regex inspection and 4-Pillar unpatched package checks." },
      { id: "T1566", name: "Phishing / Spearphishing", desc: "Malicious payloads or links transmitted via email attachments to gain initial network foothold.", detection: "Analyzes unusual outbound DNS requests and new process creations." }
    ],
    "Credential Access": [
      { id: "T1110", name: "Brute Force / Password Guessing", desc: "Automated credential stuffing against SSH, RDP, or web authentication endpoints.", detection: "Flagged by high-frequency failed authentications from single source IPs." },
      { id: "T1078", name: "Default Credentials & Secret Keys", desc: "Logging in using unchanged factory default passwords or well-known secrets on IoT or databases.", detection: "Audited across 11 management ports and hardcoded secret pattern matching." }
    ],
    "Lateral Movement": [
      { id: "T1021.002", name: "SMB / Windows Admin Shares", desc: "Adversaries traverse internal networks using SMBv1 transport and RPC named pipes.", detection: "Monitors internal port 445 sweeps and flags deprecated SMBv1 dialect negotiation." },
      { id: "T1021.001", name: "Remote Desktop Protocol (RDP)", desc: "Direct lateral logon via RDP port 3389 without bastion host isolation.", detection: "Flags internal RDP traffic crossing non-administrative subnet boundaries." }
    ],
    "Exfiltration & Impact": [
      { id: "T1041", name: "Exfiltration Over C2 Channel", desc: "Staged confidential data streamed out over existing encrypted tunnels.", detection: "Flagged by abnormal byte asymmetry (99%+ forward volume) and duration outliers." },
      { id: "T1498.001", name: "TCP SYN Flood Network DoS", desc: "Volumetric floods of TCP SYN packets exhausting host connection memory.", detection: "Identified via abnormal SYN flag ratio with zero completed handshakes." }
    ]
  }

  const tactics = Object.keys(TACTICS_DATA)

  return (
    <section id="mitre" className="mitre-section-wrap">
      <div className="AboutTitle">
        <h1>
          MITRE <span>ATT&CK</span> Enterprise Matrix
        </h1>
        <p className="section-description-text">
          Standardized enterprise threat categorization: mapping network anomalies and posture deficiencies directly to MITRE techniques.
        </p>
      </div>

      <div style={{ display: "flex", justifyContent: "center", gap: "0.8rem", flexWrap: "wrap", marginTop: "2.5rem" }}>
        {tactics.map(t => (
          <button
            key={t}
            onClick={() => setSelectedTactic(t)}
            className="card__btn"
            style={{
              padding: "0.55rem 1.25rem",
              background: selectedTactic === t ? "rgba(0, 157, 255, 0.25)" : "#141417",
              color: selectedTactic === t ? "rgb(0, 157, 255)" : "#fff",
              border: selectedTactic === t ? "1px solid rgb(0, 157, 255)" : "1px solid rgba(255,255,255,0.06)",
              fontSize: "0.95rem",
            }}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="mitre-grid">
        {TACTICS_DATA[selectedTactic].map(item => (
          <article key={item.id} className="card wide-card">
            <section className="card__hero">
              <div className="card-top-row">
                <span className="step-pill">
                  {item.id}
                </span>
                <span className="step-tech" style={{ color: "#34d399" }}>
                  VERIFIED RULE
                </span>
              </div>
              <h3 className="card-headline">
                {item.name}
              </h3>
              <p className="card-summary">
                {item.desc}
              </p>
              <div style={{ marginTop: "1rem", paddingTop: "0.8rem", borderTop: "1px solid rgba(255,255,255,0.08)", fontSize: "0.82rem", color: "#4ade80", lineHeight: "1.5" }}>
                <strong>Sentinel Detection:</strong> {item.detection}
              </div>
            </section>
          </article>
        ))}
      </div>
    </section>
  )
}
