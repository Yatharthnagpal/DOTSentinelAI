import { useState } from "react"

export default function Architecture() {
  const [activeStep, setActiveStep] = useState(0)

  const PIPELINE_STEPS = [
    {
      num: "01",
      title: "Packet Ingestion",
      tech: "Scapy & Tshark Engine",
      summary: "Ingests raw .pcap and .pcapng network capture files up to gigabyte scale without packet loss.",
      details: "Parses frame headers, reconstructs TCP handshakes, de-duplicates retransmissions, and extracts OSI metrics from Layer 2 through Layer 7 with microsecond-precision timestamps."
    },
    {
      num: "02",
      title: "Flow Aggregation",
      tech: "20+ Statistical Vectors",
      summary: "Aggregates raw packets into bidirectional 5-tuple network conversations with high-throughput statistical feature vectors.",
      details: "Groups packets by 5-tuple: (src IP, dst IP, src Port, dst Port, Protocol). Computes Flow Duration, Inter-Arrival Times, Byte Volume, and Flag Ratios (SYN/ACK/FIN/RST)."
    },
    {
      num: "03",
      title: "Zero-Day Anomaly Scoring",
      tech: "Isolation Forest (Unsupervised ML)",
      summary: "Ensemble of randomized decision trees isolates statistical anomalies without requiring prior attack signatures.",
      details: "Normal flows cluster densely and require deep tree path lengths to isolate. Zero-day attacks and abnormal volumetric bursts isolate in very few splits (anomaly score < 0.0)."
    },
    {
      num: "04",
      title: "Campaign Correlation",
      tech: "DBSCAN Spatio-Temporal Clustering",
      summary: "Correlates concurrent anomalous flows across destination subnets and time windows into structured attack campaigns.",
      details: "Applies density-based spatial clustering (eps=0.15) over feature vectors, reducing thousands of isolated packet alerts into 1 or 2 actionable attack incidents."
    },
    {
      num: "05",
      title: "Agentic AI Threat Synthesis",
      tech: "Google Gemini 2.5",
      summary: "Synthesizes low-level hex and flow metrics into plain-English threat advisories and 72-hour containment plans.",
      details: "Acts as a virtual Tier-3 SOC analyst. Analyzes campaign context, assesses adversary intent, and produces an actionable 72-hour remediation playbook."
    },
    {
      num: "06",
      title: "MITRE ATT&CK Mapping",
      tech: "Enterprise Matrix v14",
      summary: "Maps every detected anomaly and posture deficiency directly to standard MITRE ATT&CK Enterprise techniques.",
      details: "Standardizes incident reporting across enterprise security ecosystems (T1498 for SYN flood, T1110 for password brute force, T1190 for public CVEs, T1048 for exfiltration)."
    }
  ]

  return (
    <section id="architecture" className="architecture-section-wrap">
      <div className="AboutTitle">
        <h1>
          <span>How</span> Sentinel Works <span>—</span> Pipeline
        </h1>
        <p className="section-description-text">
          End-to-end autonomous telemetry pipeline: from raw binary packet captures to executive SOC incident playbooks.
        </p>
      </div>

      <div className="architecture-grid">
        {PIPELINE_STEPS.map((step, idx) => {
          const isSelected = activeStep === idx
          return (
            <article
              key={idx}
              className={`card wide-card ${isSelected ? "card-focused is-active" : ""}`}
              onClick={() => setActiveStep(isSelected ? null : idx)}
            >
              <section className="card__hero">
                <div className="card-top-row">
                  <span className="step-pill">
                    STEP {step.num}
                  </span>
                  <span className="step-tech">
                    {step.tech}
                  </span>
                </div>

                <h3 className="card-headline">
                  {step.title}
                </h3>

                <p className="card-summary">
                  {step.summary}
                </p>

                {isSelected && (
                  <div className="card-expanded-content">
                    <strong className="expanded-title">Pipeline Engine Logic:</strong>
                    <p className="expanded-desc">{step.details}</p>
                  </div>
                )}
              </section>

              <footer className="card__footer">
                <span className="card-status-text">
                  {isSelected ? "● Details Open" : "Click to Inspect"}
                </span>
                <button className="card__btn" style={{ fontSize: "0.82rem", padding: "0.35rem 0.9rem" }}>
                  {isSelected ? "Collapse" : "Details →"}
                </button>
              </footer>
            </article>
          )
        })}
      </div>
    </section>
  )
}
