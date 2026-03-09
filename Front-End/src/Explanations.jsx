import { useState } from "react"

export default function Explanations() {
  const [activeCard, setActiveCard] = useState(0)

  const TOPICS = [
    {
      id: 0,
      title: <>Zero-Day Detection: <span>Isolation Forest</span> vs Signatures</>,
      tag: "UNSUPERVISED ML",
      summary: "Why traditional signature rules fail on zero-day attacks, and how randomized isolation trees detect anomalies without historical hashes.",
      content: (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", fontSize: "0.88rem", lineHeight: "1.6" }}>
          <p>
            Traditional intrusion detection systems (Snort, Suricata) rely on static byte patterns. When an attacker modifies payload signatures or exploits a novel zero-day flaw, signature lookups fail completely.
          </p>
          <p>
            <strong>Isolation Forest</strong> operates on the principle that anomalies are few and different. By recursively partitioning multi-dimensional flow feature space with random splits, abnormal flows isolate near the roots of the trees (short path length $h(x)$), yielding an anomaly score &lt; 0.0.
          </p>
          <div style={{ background: "rgba(0,0,0,0.4)", padding: "0.9rem", borderRadius: "8px", border: "1px solid rgba(0, 157, 255, 0.25)" }}>
            <strong style={{ color: "#00f0ff" }}>Mathematical Anomaly Score:</strong>
            <div style={{ fontFamily: "monospace", color: "#4ade80", marginTop: "0.4rem", fontSize: "0.95rem" }}>
              s(x, n) = 2^(-E(h(x)) / c(n))
            </div>
            <div style={{ color: "rgba(255,255,255,0.6)", fontSize: "0.78rem", marginTop: "0.3rem" }}>
              Scores close to 1.0 indicate definite anomalies; scores &lt; 0.5 represent normal benign baseline traffic.
            </div>
          </div>
        </div>
      )
    },
    {
      id: 1,
      title: <>Flow Feature <span>Telemetry</span> Breakdown</>,
      tag: "FEATURE ENGINEERING",
      summary: "How raw Wireshark packets are aggregated into bidirectional 5-tuple statistical vectors exposing covert attacks.",
      content: (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", fontSize: "0.88rem", lineHeight: "1.6" }}>
          <p>
            Raw packets are too voluminous for real-time inference. Dot Sentinel aggregates frames into 5-tuple flows <em>(src IP, dst IP, src port, dst port, protocol)</em> and calculates 20+ behavioral metrics:
          </p>
          <ul style={{ margin: 0, paddingLeft: "1.2rem", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
            <li><strong>Flow Duration:</strong> Microsecond timing reveals port sweeps (&lt;10ms) vs data exfiltration (&gt;60s).</li>
            <li><strong>Byte Asymmetry Ratio:</strong> 99% forward bytes indicates volumetric exfiltration or DDoS; balanced ratios indicate normal web traffic.</li>
            <li><strong>TCP Flag Ratios:</strong> High SYN count with zero ACK responses flags SYN flooding and stealth port scans.</li>
            <li><strong>Inter-Arrival Time (IAT):</strong> Mean and variance of packet intervals uncovers robotic C2 beaconing (Cobalt Strike) vs organic human browsing.</li>
          </ul>
        </div>
      )
    },
    {
      id: 2,
      title: <>Agentic AI: How <span>Gemini</span> Eliminates Alert Fatigue</>,
      tag: "AGENTIC SYNTHESIS",
      summary: "Transforming high-dimensional numeric vectors into natural-language executive threat advisories and 72-hour playbooks.",
      content: (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", fontSize: "0.88rem", lineHeight: "1.6" }}>
          <p>
            Tier-1 SOC analysts are overwhelmed by 10,000+ daily raw alerts. Dot Sentinel uses DBSCAN to group correlated anomaly flows into an attack campaign, and passes the campaign context to <strong>Google Gemini</strong>.
          </p>
          <p>
            The Agentic AI acts as an autonomous Tier-3 analyst: deducing the threat actor's objective, assessing blast radius, mapping to MITRE ATT&CK techniques, and authoring a prioritized 72-hour containment playbook with actionable CLI commands.
          </p>
        </div>
      )
    },
    {
      id: 3,
      title: <>The Four <span>Defensive Posture</span> Pillars</>,
      tag: "SECURITY BENCHMARK",
      summary: "Auditing defensive hardening against NIST SP 800-63B, CIS Controls v8, and CISA Zero Trust directives.",
      content: (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", fontSize: "0.88rem", lineHeight: "1.6" }}>
          <ul style={{ margin: 0, paddingLeft: "1.2rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <li><strong>⚙️ System & Software:</strong> Checks for EOL operating systems, unpatched CVEs, unencrypted disks, and cleartext protocols.</li>
            <li><strong>🔑 Identity & Access:</strong> Validates global MFA enforcement, NIST 800-63B password complexity, excessive admin accounts, and orphaned staff accounts.</li>
            <li><strong>🌐 Network & Border:</strong> Audits firewall ACL rules for Any-to-Any entries, exposed management ports, and 6 critical HTTP security headers.</li>
            <li><strong>📝 Monitoring & Resilience:</strong> Audits centralized SIEM telemetry, 365-day log retention, and 3-2-1 backup architecture with ransomware-proof WORM immutability.</li>
          </ul>
        </div>
      )
    }
  ]

  return (
    <section id="explanations" className="explanations-section-wrap">
      <div className="AboutTitle">
        <h1>
          Technical <span>Explanations</span> & Core Principles
        </h1>
        <p className="section-description-text">
          Deep-dive analysis into unsupervised anomaly scoring, flow telemetry feature engineering, and agentic AI threat deduction.
        </p>
      </div>

      <div className="explanations-grid">
        {TOPICS.map((topic) => {
          const isSelected = activeCard === topic.id
          return (
            <article
              key={topic.id}
              className={`card wide-card ${isSelected ? "card-focused is-active" : ""}`}
              onClick={() => setActiveCard(isSelected ? null : topic.id)}
            >
              <section className="card__hero">
                <span className="step-pill" style={{ marginBottom: "0.8rem", alignSelf: "flex-start" }}>
                  {topic.tag}
                </span>

                <h3 className="card-headline">
                  {topic.title}
                </h3>

                <p className="card-summary">
                  {topic.summary}
                </p>

                {isSelected && (
                  <div className="card-expanded-content">
                    {topic.content}
                  </div>
                )}
              </section>

              <footer className="card__footer">
                <span className="card-status-text">
                  {isSelected ? "● Content Expanded" : "Click to Read Topic"}
                </span>
                <button className="card__btn" style={{ fontSize: "0.82rem", padding: "0.35rem 0.9rem" }}>
                  {isSelected ? "Collapse" : "Read More →"}
                </button>
              </footer>
            </article>
          )
        })}
      </div>
    </section>
  )
}
