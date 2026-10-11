# Registry of Outstanding Issues & Author Decisions

**Audit Date**: October 12, 2026  
**Auditor**: Independent Peer Review & Scientific Audit Taskforce  
**Manuscript Target**: `paper/revised_manuscript.tex` / `paper/revised_manuscript.pdf`  
**Overall Status**: Ready for Author Review and Journal Submission

---

## 1. Author Review & Approval Checklist

The following items are completely verified from the engineering and data audit perspective, but represent editorial or administrative decisions requiring author confirmation prior to final submission:

| Issue ID | Category | Description | Recommended Resolution | Status |
|---|---|---|---|---|
| **AUTH-01** | **Author Affiliation & ORCID** | Confirm author names, affiliations, email addresses, and ORCID identifiers:  <br>• Harish Parshuram Bhabad (ORCID: `0000-0002-3620-3331`)<br>• Anand Singh Rajawat (Corresponding, ORCID: `0000-0002-2342-8321`) | Author to review and confirm final institutional details in `paper/revised_manuscript.tex` line 19–22. | `REQUIRES AUTHOR APPROVAL` |
| **AUTH-02** | **Target Journal Scope** | Target template is formatted for Acadlore Journal System (`acadlore.cls`). If submitting to another venue (e.g., IEEE Transactions on Information Forensics and Security, Elsevier Computers & Security), style class must be adapted. | Author to confirm if submission is targeting Acadlore or if conversion to IEEEtran / Elsevier CAS is required. | `REQUIRES AUTHOR APPROVAL` |
| **AUTH-03** | **Funding & Grant Numbers** | Backmatter (`sections/11_backmatter.tex`) currently states: "This research received no external funding." | Author to confirm whether any institutional or national research grants should be acknowledged. | `REQUIRES AUTHOR APPROVAL` |
| **AUTH-04** | **Data Repository Link** | Backmatter states that code and pre-trained models are available upon reasonable request or in an institutional repository. | Author to supply public GitHub / Zenodo DOI link prior to camera-ready publication. | `REQUIRES AUTHOR APPROVAL` |

---

## 2. Technical Boundaries & Disclosed Limitations

These items represent physical or empirical constraints of the current project that have been explicitly disclosed in the manuscript (Section 08 `08_limitations.tex`) to preserve scientific integrity:

| Limitation ID | Technical Area | Manuscript Disclosure | Scientific Rationale | Status |
|---|---|---|---|---|
| **TECH-01** | **Quantum Key Distribution Hardware** | BB84 QKD and TC-QC key expansion are executed as software numerical simulations rather than on optical fiber / free-space photon hardware. | Explicitly disclosed in Abstract, Section 04, Section 06, and Section 08. Reviewers are informed that physical optical losses and detector dark counts are modeled mathematically. | `DISCLOSED AS LIMITATION` |
| **TECH-02** | **Blockchain EVM Environment** | Smart contracts were benchmarked on a local Ganache EVM RPC testbed rather than Ethereum Mainnet. | Explicitly documented in Section 06 and Section 08. Local gas costs and execution latencies isolate smart contract computational complexity without network congestion variance. | `DISCLOSED AS LIMITATION` |
| **TECH-03** | **Multi-Class Attribution Imbalance** | Classes with low support (e.g., MITM with 182 samples) or high similarity (e.g., DDoS_HTTP and Vulnerability_scanner) exhibit lower F1 scores (80.7%–84.1%) than binary screening (99.89%). | Documented in Section 06 and Table 4. Explains why the dual-tier design uses binary screening as the primary defense barrier and multi-class attribution as a secondary advisory tier. | `DISCLOSED AS LIMITATION` |
| **TECH-04** | **Benchmark Synthetic Network Setting** | Edge-IIoTset is a modern, high-fidelity testbed dataset but represents controlled network captures rather than live hospital clinical network traffic. | Explicitly noted in Section 08. Recommends future cross-dataset validation on live clinical telemetry (e.g., MIMIC-IV connected medical telemetry). | `DISCLOSED AS LIMITATION` |

---

## 3. Recommended Future Work (Post-Publication Extensions)

1. **Physical QKD Integration**: Interfacing the key expansion pipeline with physical QKD hardware testbeds (e.g., ID Quantique Clavis3 or Toshiba QKD).
2. **Layer-2 Rollup Deployment**: Deploying the EHR smart contract access control digest anchors to an Ethereum Layer-2 rollup (e.g., Arbitrum, Optimism, or Polygon zkEVM) to reduce transaction latency from 13.6 ms down to sub-millisecond ranges and gas fees by $95\%$.
3. **Cross-Dataset Generalization**: Evaluating the top-20 flow telemetry feature subset on external datasets such as CIC-IoMT2024 and WUSTL-IIoT without fine-tuning.

---

## 4. Verification Conclusion
There are zero blockers to submission. All scientific discrepancies and ungrounded claims have been resolved. The author may proceed with final proofreading and submission upon confirming items `AUTH-01` through `AUTH-04`.
