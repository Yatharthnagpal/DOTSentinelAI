export default function Footer() {
  return (
    <footer>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", color: "#EDEBDD", fontWeight: "600", letterSpacing: "0.04em", fontSize: "0.95rem" }}>
          <span style={{ color: "#009dff" }}>●</span> DOT Sentinel AI
          <span style={{ color: "rgba(255,255,255,0.2)" }}>|</span>
          <span style={{ color: "rgba(255,255,255,0.7)", fontWeight: "400" }}>Autonomous Network Security Intelligence</span>
        </div>
        <div style={{ fontSize: "0.78rem", color: "rgba(255, 255, 255, 0.45)" }}>
          Zero-Day Intrusion Detection • MITRE ATT&CK Mapping • Continuous Defensive Posture Audit
        </div>
        <div style={{ fontSize: "0.72rem", color: "rgba(255, 255, 255, 0.3)", marginTop: "0.3rem" }}>
          © {new Date().getFullYear()} DOT Sentinel. Enterprise Cyber Defense & SOC Automation Platform.
        </div>
      </div>
    </footer>
  )
}
