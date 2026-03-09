import { useState } from "react"

export default function Faq() {
  const [openIdx, setOpenIdx] = useState(0)

  const FAQS = [
    {
      q: "What packet capture file formats are supported by DOT Sentinel AI?",
      a: "DOT Sentinel AI natively ingests both standard .pcap (Wireshark, tcpdump, WinDump) and modern .pcapng (Next Generation Packet Capture) formats. Capture files from enterprise network taps, SPAN mirror ports, cloud VPC flow logs, and edge firewall dumps can be uploaded directly."
    },
    {
      q: "How does DOT Sentinel AI analyze encrypted TLS / HTTPS traffic without breaking privacy?",
      a: "Unlike intrusive SSL decryption proxies that introduce certificate vulnerabilities, DOT Sentinel AI inspects flow-level statistical metadata rather than raw payload text. It evaluates packet sizes, microsecond inter-arrival times, sequence randomness, byte asymmetry, and TLS handshake negotiation characteristics (ciphers, SNI, protocol versions). This identifies malicious beaconing and exfiltration even through TLS 1.3 tunnels without violating data privacy."
    },
    {
      q: "Why use Unsupervised Isolation Forest instead of traditional signature tools like Snort or Suricata?",
      a: "Traditional signature engines look for exact byte strings of known attacks. They are powerless against novel zero-day exploits, modified malware binaries, or subtle temporal beaconing. Isolation Forest builds randomized partitioning trees in high-dimensional feature space; abnormal flows naturally isolate in significantly fewer splits than dense normal traffic, flagging zero-day threats with zero requirement for pre-written signatures."
    },
    {
      q: "How does the Agentic AI (Gemini) prevent SOC alert fatigue?",
      a: "Rather than bombarding security teams with 10,000 isolated packet alerts, DOT Sentinel first uses DBSCAN to correlate multi-flow attacks into structured campaigns. The Google Gemini Agentic AI then acts as an automated Tier-3 SOC analyst: analyzing the campaign context, deducing threat actor objectives, cross-referencing MITRE ATT&CK techniques, and producing a prioritized 72-hour remediation playbook with copy-paste terminal commands."
    },
    {
      q: "Can DOT Sentinel AI run completely on-premises or in an air-gapped network?",
      a: "Yes. The Scapy packet parser, flow feature engineering engine, and Isolation Forest ML models run 100% locally with zero external network connectivity. When deployed in air-gapped classified environments without internet access to Google Gemini, the platform automatically activates an offline heuristic threat synthesis engine that generates full MITRE ATT&CK advisories and playbooks locally."
    },
    {
      q: "What compliance standards and frameworks does the 4-Pillar Posture Scanner audit against?",
      a: "The posture audit engine benchmarks configurations against NIST SP 800-63B (Digital Identity & Authentication Guidelines), CIS Critical Security Controls v8, CISA Zero Trust Maturity Model, OWASP Top 10 API Security, and ISO/IEC 27001 data protection controls."
    },
    {
      q: "How does the system export reports for enterprise SIEM/SOAR platforms?",
      a: "All analysis results can be exported with a single click as standardized JSON schemas or formatted Markdown advisories. The structured JSON output includes RFC-compliant timestamps, 5-tuple flow records, MITRE ATT&CK technique IDs, and numerical anomaly scores, making it seamless to ingest into Splunk, Elastic SIEM, Microsoft Sentinel, or Cortex XSOAR."
    }
  ]

  return (
    <section id="faq" className="faq-section">
      <div className="faq-container">
        {/* Header */}
        <div className="section-head-center">
          <div className="section-tag-badge">KNOWLEDGE BASE & SOC FAQ</div>
          <h2 className="section-title">
            Frequently Asked <span className="text-glow-cyan">Questions</span>
          </h2>
          <p className="section-subtitle">
            Everything you need to know about packet telemetry parsing, machine learning inference,
            privacy guarantees, and enterprise SOC integration.
          </p>
        </div>

        {/* FAQ Accordion List */}
        <div className="faq-accordion-list">
          {FAQS.map((faq, idx) => {
            const isOpen = openIdx === idx
            return (
              <div
                key={idx}
                className={`faq-item ${isOpen ? "open" : ""}`}
                onClick={() => setOpenIdx(isOpen ? null : idx)}
              >
                <button className="faq-question-btn">
                  <span className="faq-q-text">{faq.q}</span>
                  <span className="faq-toggle-icon">{isOpen ? "−" : "+"}</span>
                </button>

                {isOpen && (
                  <div className="faq-answer-pane">
                    <p>{faq.a}</p>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

