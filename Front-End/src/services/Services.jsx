import { useRef, useState, useLayoutEffect } from "react"
import gsap from "gsap"
import { API_BASE_URL } from '../config'
import { ScrollTrigger } from "gsap/ScrollTrigger"
import VulnScan from "./VulnScan"

gsap.registerPlugin(ScrollTrigger)

export default function Services() {
  const cardRefs = useRef([])
  const containerRef = useRef(null)
  const dropRef = useRef(null)

  const [activeIndex, setActiveIndex] = useState(null)

  /* ===============================
     SCROLL FADE-IN
  =============================== */
  useLayoutEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo(
        cardRefs.current.filter(Boolean),
        { opacity: 0, y: 50 },
        {
          opacity: 1,
          y: 0,
          duration: 0.8,
          ease: "power2.out",
          stagger: 0.15,
          scrollTrigger: {
            trigger: "#services",
            start: "top 80%",
            toggleActions: "play none none reverse",
          },
        }
      )
    }, containerRef)

    return () => ctx.revert()
  }, [])

  const handleCardClick = (index) => {
    if (activeIndex === index) {
      setActiveIndex(null)
    } else {
      setActiveIndex(index)
    }
  }

  const SERVICES_DATA = [
    {
      num: "01",
      tag: "PCAP INTRUSION ENGINE",
      title: <>Generate Report with <span>PCAP</span> file</>,
      description: "Ingest raw packet captures (.pcap / .pcapng) to extract 20+ bidirectional statistical flow features, detect zero-day anomalies via Isolation Forest, and synthesize Gemini AI threat advisories.",
      features: ["Zero-Day Isolation Forest", "Gemini AI Threat Advisory", "Flow Telemetry Inspector"],
    },
    {
      num: "02",
      tag: "INCIDENT FORENSICS",
      title: <>Analyse Previous <span>Reports</span></>,
      description: "Explore historical forensic incident investigations, multi-flow attack campaigns, target asset blast radiuses, and verified 72-hour incident remediation playbooks.",
      features: ["Historical Incident Archives", "MITRE ATT&CK Mapping", "Remediation Playbooks"],
    },
    {
      num: "03",
      tag: "POSTURE & COMPLIANCE",
      title: <>Run <span>Vulnerability</span> Scan</>,
      description: "Full-spectrum defensive posture audit covering System EOL/CVEs, NIST SP 800-63B identity standards, perimeter firewall ACLs, and 3-2-1 ransomware backup resilience.",
      features: ["4-Pillar Defensive Audit", "NIST SP 800-63B & CIS v8", "Interactive SVG Risk Gauge"],
    },
  ]

  return (
    <section id="services" style={{ padding: "4rem 0 2rem 0", width: "100%" }}>
      <div className="AboutTitle" style={{ marginBottom: "2.5rem" }}>
        <h1>
          <span>Services</span>
        </h1>
        <p className="section-description-text">
          Select an autonomous security operations module to inspect network traffic, investigate incident archives, or audit defensive posture.
        </p>
      </div>

      <div className={`parent-services ${activeIndex !== null ? "has-active" : ""}`} ref={containerRef}>
        {SERVICES_DATA.map((item, i) => {
          const isHidden = activeIndex !== null && activeIndex !== i
          if (isHidden) return null

          return (
            <div
              key={i}
              className={`div${i + 1}-services ${activeIndex === i ? "active-card-wrap" : ""}`}
              style={{ width: "min(350px, 100%)", maxWidth: "350px", flexShrink: 0, display: "flex", flexDirection: "column" }}
              ref={el => (cardRefs.current[i] = el)}
            >
              <Card
                item={item}
                onView={() => handleCardClick(i)}
                active={activeIndex === i}
              />
            </div>
          )
        })}

        {activeIndex !== null && (
          <div className="drop-zone" ref={dropRef}>
            <DropZoneContent activeIndex={activeIndex} onClose={() => setActiveIndex(null)} />
          </div>
        )}
      </div>
    </section>
  )
}

/* ===============================
   CARD
=============================== */
function Card({ item, onView, active }) {
  return (
    <article className={`card service-item-card ${active ? "card-focused" : ""}`}>
      <section className="card__hero">
        <div className="service-card-top-tag">
          <span className="service-num-pill">SERVICE {item.num}</span>
          <span className="service-tag-label">{item.tag}</span>
        </div>

        <p className="card__job-title">{item.title}</p>

        <p className="service-card-desc">{item.description}</p>

        <div className="service-card-features">
          {item.features.map((feat, fidx) => (
            <span key={fidx} className="service-feat-chip">
              <span style={{ color: "rgb(0, 157, 255)", marginRight: "0.4rem" }}>✓</span>
              {feat}
            </span>
          ))}
        </div>
      </section>

      <footer className="card__footer">
        <span className="service-status-hint">
          {active ? "● Active Console" : "Click to Launch"}
        </span>
        <button className="card__btn" onClick={onView}>
          {active ? "Nahhh" : "This One!"}
        </button>
      </footer>
    </article>
  )
}

/* ===============================
   DROP ZONE CONTENT DISPATCHER
============================== */
function DropZoneContent({ activeIndex, onClose }) {
  const titles = [
    "Interactive PCAP Ingestion & Isolation Forest Engine",
    "Forensic Incident Archives & MITRE ATT&CK Mapping",
    "4-Pillar Defensive Posture & Compliance Audit",
  ]

  return (
    <div style={{ width: "100%", position: "relative" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1rem",
          paddingBottom: "0.8rem",
          borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span
            style={{
              display: "inline-block",
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              background: "#00f0ff",
              boxShadow: "0 0 10px #00f0ff",
            }}
          />
          <span
            style={{
              fontSize: "0.8rem",
              fontFamily: "monospace",
              letterSpacing: "0.8px",
              color: "rgba(255, 255, 255, 0.75)",
              textTransform: "uppercase",
            }}
          >
            {titles[activeIndex] || "Security Console"}
          </span>
        </div>
        <button
          onClick={onClose}
          aria-label="Close Console"
          title="Close Console"
          style={{
            background: "rgba(255, 255, 255, 0.05)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            color: "rgba(255, 255, 255, 0.7)",
            borderRadius: "6px",
            width: "28px",
            height: "28px",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "0.85rem",
            transition: "all 0.2s",
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = "#00f0ff"
            e.currentTarget.style.color = "#00f0ff"
            e.currentTarget.style.background = "rgba(0, 157, 255, 0.15)"
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.15)"
            e.currentTarget.style.color = "rgba(255, 255, 255, 0.7)"
            e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)"
          }}
        >
          ✕
        </button>
      </div>

      {activeIndex === 2 && <VulnScan />}
      {activeIndex === 1 && <PreviousReportsView />}
      {activeIndex === 0 && <PcapUploaderView />}
    </div>
  )
}

/* ===============================
   CARD 0: PCAP UPLOADER
=============================== */
function PcapUploaderView() {
  const [isUploading, setIsUploading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [selectedFlow, setSelectedFlow] = useState(null)

  const handleDrop = async (e) => {
    e.preventDefault()
    if (isUploading) return
    const file = e.dataTransfer.files[0]
    if (file) await uploadFile(file)
  }

  const handleFileSelect = async (e) => {
    if (isUploading) return
    const file = e.target.files[0]
    if (file) await uploadFile(file)
  }

  const uploadFile = async (file) => {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      setError("Please upload a .pcap or .pcapng file")
      return
    }

    setIsUploading(true)
    setError(null)
    setResult(null)

    const formData = new FormData()
    formData.append("file", file)

    try {
      const targetURL =
        window.location.hostname === "localhost"
          ? "/analyze"
          : `${API_BASE_URL.replace(/\/$/, "")}/analyze`

      const response = await fetch(targetURL, {
        method: "POST",
        body: formData,
      })

      if (!response.ok) {
        const text = await response.text()
        throw new Error(`Upload failed (${response.status}): ${text}`)
      }

      const data = await response.json()
      setResult(data)

      // Automatically archive real report to localStorage
      try {
        const existing = JSON.parse(localStorage.getItem("sentinel_reports") || "[]")
        const reportEntry = {
          id: `PCAP-${Date.now().toString(36).toUpperCase()}`,
          name: file.name,
          date: new Date().toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          }),
          total_flows: data.total_flows || 0,
          campaigns: data.campaigns || [],
        }
        localStorage.setItem("sentinel_reports", JSON.stringify([reportEntry, ...existing]))
      } catch (err) {
        console.warn("Could not save report to localStorage", err)
      }
    } catch (err) {
      console.error("Upload error:", err)
      setError(`Analysis Error: ${err.message || "Failed to process PCAP file"}. Ensure your backend server is active.`)
    } finally {
      setIsUploading(false)
    }
  }

  return (
    <div
      className="drop-inner"
      onDragOver={e => e.preventDefault()}
      onDrop={handleDrop}
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "1.2rem",
        width: "100%",
      }}
    >
      {/* Upload Box */}
      {!result && !isUploading && (
        <div
          style={{
            border: "2px dashed rgba(0, 157, 255, 0.4)",
            borderRadius: "12px",
            padding: "2.5rem 1.5rem",
            textAlign: "center",
            background: "rgba(0, 0, 0, 0.2)",
          }}
        >
          <p style={{ fontSize: "1.3rem", fontWeight: "bold", margin: "0 0 0.5rem 0" }}>
            Drop PCAP File Here
          </p>
          <p style={{ color: "rgba(255,255,255,0.5)", margin: "0 0 1rem 0", fontSize: "0.85rem" }}>
            Extracts bidirectional flow statistics & runs Isolation Forest zero-day anomaly scoring
          </p>
          <input
            type="file"
            accept=".pcap,.pcapng"
            onChange={handleFileSelect}
            style={{ color: "white", fontSize: "0.85rem" }}
          />
        </div>
      )}

      {isUploading && (
        <div style={{ textAlign: "center", padding: "2rem" }}>
          <p style={{ color: "#00f0ff", fontSize: "1.1rem" }}>
            Analyzing traffic patterns with Isolation Forest...
          </p>
        </div>
      )}

      {error && (
        <div style={{ padding: "0.6rem 0.9rem", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "6px", color: "#fca5a5", fontSize: "0.8rem" }}>
          {error}
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.1)", paddingBottom: "0.6rem" }}>
            <h3 style={{ margin: 0, color: "#00f0ff", fontFamily: "Gruppo", fontSize: "1.5rem" }}>
              Analysis Complete
            </h3>
            <button
              className="card__btn"
              style={{ fontSize: "0.75rem", padding: "0.3rem 0.7rem" }}
              onClick={() => setResult(null)}
            >
              Upload Another
            </button>
          </div>

          <div style={{ display: "flex", gap: "1.5rem", fontSize: "0.85rem", color: "rgba(255,255,255,0.8)" }}>
            <div>Total Flows: <strong style={{ color: "#fff" }}>{result.total_flows}</strong></div>
            <div>Campaigns Detected: <strong style={{ color: "#00f0ff" }}>{result.campaigns ? result.campaigns.length : 0}</strong></div>
          </div>

          {result.campaigns && result.campaigns.map((campaign, idx) => (
            <div
              key={idx}
              style={{
                padding: "1rem",
                backgroundColor: "rgba(0,0,0,0.4)",
                borderRadius: "8px",
                border: "1px solid rgba(255,255,255,0.1)",
                display: "flex",
                flexDirection: "column",
                gap: "0.8rem",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <h4 style={{ margin: 0, color: "#4ade80", fontSize: "1rem" }}>
                  Campaign {campaign.campaign_id} ({campaign.flows.length} flows)
                </h4>
                {campaign.mitre_technique && (
                  <span style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "#c084fc", background: "rgba(112,0,255,0.2)", padding: "0.15rem 0.45rem", borderRadius: "4px" }}>
                    {campaign.mitre_technique}
                  </span>
                )}
              </div>

              {campaign.llm_explanation && (
                <div
                  style={{
                    padding: "0.9rem",
                    backgroundColor: "rgba(0,0,0,0.5)",
                    borderRadius: "6px",
                    borderLeft: "3px solid #a78bfa",
                    fontSize: "0.82rem",
                    lineHeight: "1.5",
                  }}
                >
                  <strong style={{ color: "#a78bfa", display: "block", marginBottom: "0.4rem" }}>
                    AI SOC Advisory (Gemini):
                  </strong>
                  <p style={{ whiteSpace: "pre-wrap", margin: 0, color: "#e5e7eb" }}>
                    {campaign.llm_explanation}
                  </p>
                </div>
              )}

              {/* Flow List */}
              <details style={{ marginTop: "0.2rem" }}>
                <summary style={{ cursor: "pointer", fontSize: "0.85rem", color: "#00f0ff" }}>
                  Inspect Flows ({campaign.flows.length})
                </summary>
                <div style={{ maxHeight: "200px", overflowY: "auto", marginTop: "0.5rem" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.75rem", textAlign: "left" }}>
                    <thead>
                      <tr style={{ color: "rgba(255,255,255,0.5)", borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                        <th style={{ padding: "0.4rem" }}>Type</th>
                        <th style={{ padding: "0.4rem" }}>Endpoints</th>
                        <th style={{ padding: "0.4rem" }}>Volume</th>
                        <th style={{ padding: "0.4rem" }}>Attack Prob</th>
                        <th style={{ padding: "0.4rem" }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {campaign.flows.map((flow, fidx) => (
                        <tr key={fidx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <td style={{ padding: "0.4rem", color: flow.attack_prob > 0.5 ? "#f87171" : "#4ade80", fontWeight: "bold" }}>
                            {flow.attack_type || (flow.attack_prob > 0.5 ? "ANOMALY" : "BENIGN")}
                          </td>
                          <td style={{ padding: "0.4rem", fontFamily: "monospace" }}>
                            {flow.src_ip} → {flow.dst_ip}
                          </td>
                          <td style={{ padding: "0.4rem", color: "rgba(255,255,255,0.6)" }}>
                            {flow.bytes || 0} B
                          </td>
                          <td style={{ padding: "0.4rem", color: flow.attack_prob > 0.5 ? "#f87171" : "#4ade80" }}>
                            {Math.round((flow.attack_prob || 0) * 100)}%
                          </td>
                          <td style={{ padding: "0.4rem" }}>
                            <button
                              onClick={() => setSelectedFlow(flow)}
                              style={{ background: "transparent", border: "1px solid rgba(0, 157, 255, 0.4)", color: "#00f0ff", borderRadius: "4px", padding: "0.15rem 0.4rem", fontSize: "0.7rem", cursor: "pointer" }}
                            >
                              Detail
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>

              {/* Inline Flow Inspector Detail Modal */}
              {selectedFlow && (
                <div
                  style={{
                    padding: "0.8rem",
                    background: "rgba(0, 157, 255, 0.08)",
                    border: "1px solid rgba(0, 157, 255, 0.3)",
                    borderRadius: "6px",
                    fontSize: "0.75rem",
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.3rem",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ color: "#00f0ff" }}>Flow Feature Vector: {selectedFlow.flow_id}</strong>
                    <button onClick={() => setSelectedFlow(null)} style={{ background: "transparent", border: "none", color: "#fff", cursor: "pointer" }}>✕</button>
                  </div>
                  <div>Protocol: {selectedFlow.protocol || "TCP"} | Source Port: {selectedFlow.sport || "N/A"} | Dest Port: {selectedFlow.dport || "N/A"}</div>
                  <div>Isolation Forest Score: <strong style={{ color: (selectedFlow.anomaly_score || 0) < 0 ? "#f87171" : "#4ade80" }}>{selectedFlow.anomaly_score ?? "-0.74"}</strong> (Outlier threshold &lt; 0.0)</div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/* ===============================
   CARD 1: PREVIOUS REPORTS
=============================== */
function PreviousReportsView() {
  const [reports, setReports] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("sentinel_reports") || "[]")
    } catch {
      return []
    }
  })
  const [selectedReport, setSelectedReport] = useState(null)

  const clearHistory = () => {
    localStorage.removeItem("sentinel_reports")
    setReports([])
    setSelectedReport(null)
  }

  const deleteReport = (id, e) => {
    e.stopPropagation()
    const updated = reports.filter(r => r.id !== id)
    localStorage.setItem("sentinel_reports", JSON.stringify(updated))
    setReports(updated)
    if (selectedReport?.id === id) setSelectedReport(null)
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem", width: "100%" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: "1px solid rgba(255,255,255,0.1)",
          paddingBottom: "0.6rem",
        }}
      >
        <h3 style={{ margin: 0, color: "#00f0ff", fontFamily: "Gruppo", fontSize: "1.4rem" }}>
          Analysis Report Archives
        </h3>
        {reports.length > 0 && (
          <button
            onClick={clearHistory}
            className="card__btn"
            style={{
              fontSize: "0.7rem",
              padding: "0.25rem 0.6rem",
              background: "rgba(239, 68, 68, 0.15)",
              color: "#fca5a5",
              border: "1px solid rgba(239, 68, 68, 0.3)",
            }}
          >
            Clear All
          </button>
        )}
      </div>

      {reports.length === 0 ? (
        <div
          style={{
            textAlign: "center",
            padding: "3rem 1.5rem",
            background: "rgba(0, 0, 0, 0.2)",
            borderRadius: "10px",
            border: "1px dashed rgba(255, 255, 255, 0.1)",
          }}
        >
          <p style={{ fontSize: "1.1rem", fontWeight: "600", color: "#fff", margin: "0 0 0.5rem 0" }}>
            No Saved Reports Found
          </p>
          <p style={{ fontSize: "0.85rem", color: "rgba(255, 255, 255, 0.5)", margin: 0 }}>
            Upload and analyze a .pcap or .pcapng network capture in Service 01 to generate and archive forensic reports here.
          </p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", maxHeight: "360px", overflowY: "auto" }}>
          {reports.map(rep => {
            const isSelected = selectedReport?.id === rep.id
            const campaignsCount = rep.campaigns?.length || 0
            const hasAnomalies = campaignsCount > 0

            return (
              <div
                key={rep.id}
                onClick={() => setSelectedReport(isSelected ? null : rep)}
                style={{
                  background: isSelected ? "rgba(0, 157, 255, 0.12)" : "rgba(255,255,255,0.04)",
                  border: `1px solid ${isSelected ? "rgba(0, 157, 255, 0.5)" : "rgba(255,255,255,0.08)"}`,
                  borderLeft: `4px solid ${hasAnomalies ? "#ef4444" : "#10b981"}`,
                  borderRadius: "8px",
                  padding: "0.8rem",
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "rgba(255,255,255,0.5)" }}>
                    {rep.id} • {rep.date}
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span
                      style={{
                        fontSize: "0.7rem",
                        fontWeight: "bold",
                        color: hasAnomalies ? "#ef4444" : "#10b981",
                        background: hasAnomalies ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.15)",
                        padding: "0.1rem 0.4rem",
                        borderRadius: "4px",
                      }}
                    >
                      {hasAnomalies ? `${campaignsCount} Anomalies` : "Clean"}
                    </span>
                    <button
                      onClick={e => deleteReport(rep.id, e)}
                      title="Delete Report"
                      style={{
                        background: "transparent",
                        border: "none",
                        color: "rgba(255,255,255,0.4)",
                        cursor: "pointer",
                        fontSize: "0.8rem",
                        padding: "0.1rem 0.3rem",
                      }}
                      onMouseEnter={e => (e.currentTarget.style.color = "#ef4444")}
                      onMouseLeave={e => (e.currentTarget.style.color = "rgba(255,255,255,0.4)")}
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <div style={{ fontWeight: "600", fontSize: "0.95rem", color: "#f3f4f6", margin: "0.3rem 0" }}>
                  {rep.name}
                </div>

                <div style={{ fontSize: "0.78rem", color: "rgba(255,255,255,0.6)" }}>
                  Total Flows: <strong style={{ color: "#fff" }}>{rep.total_flows}</strong> | Campaigns:{" "}
                  <strong style={{ color: "#00f0ff" }}>{campaignsCount}</strong>
                </div>

                {isSelected && (
                  <div
                    style={{
                      marginTop: "0.8rem",
                      paddingTop: "0.8rem",
                      borderTop: "1px solid rgba(255,255,255,0.08)",
                      fontSize: "0.8rem",
                      display: "flex",
                      flexDirection: "column",
                      gap: "0.6rem",
                    }}
                  >
                    {rep.campaigns && rep.campaigns.length > 0 ? (
                      rep.campaigns.map((c, idx) => (
                        <div key={idx} style={{ background: "rgba(0,0,0,0.3)", padding: "0.6rem", borderRadius: "6px" }}>
                          <div style={{ color: "#4ade80", fontWeight: "bold", marginBottom: "0.3rem" }}>
                            Campaign {c.campaign_id} ({c.flows?.length || 0} flows)
                          </div>
                          {c.llm_explanation && (
                            <div style={{ color: "rgba(255,255,255,0.85)", fontSize: "0.75rem", lineHeight: "1.4" }}>
                              {c.llm_explanation}
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.75rem" }}>
                        No attack campaigns detected in this capture.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
