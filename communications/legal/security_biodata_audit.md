# EDEN-BioGuard Security & Biodata Legal Compliance Audit Guide (Kenya)

**Document owner:** Legal & Compliance  
**Validation reviewer:** Kimberly Onduru  
**Last updated:** 2026-05-10 (UTC)

## 1) Audit Objective and Scope

Use this guide to audit EDEN-BioGuard handling of software-security data and ecological/biodata in line with Kenyan constitutional privacy principles and applicable data protection expectations.

**In scope:**
- User/stakeholder communications data
- Incident data, logs, and evidence artifacts
- Ecological surveillance and biodata feeds (including risk scoring inputs)
- Access events, system logs, and blockchain-linked audit metadata
- Cross-border transfers to cloud, APIs, analytics, or partner systems

---

## 2) Security & Biodata Legal Compliance Audit Checklist

Mark each item **Compliant / Partial / Gap** and record evidence.

### A. Data minimization and purpose limitation
- [ ] Each data field in collection forms/API payloads has a documented purpose tied to a defined EDEN-BioGuard workflow.
- [ ] No excess personal or sensitive biodata is collected where aggregate, pseudonymized, or less granular data would meet the same purpose.
- [ ] Field-level necessity has been reviewed within the last 12 months.
- [ ] Reuse of data outside original purpose has legal basis and documented approval.
- [ ] Data flow diagrams identify where data is transformed, aggregated, or de-identified.

**Recommendation standard:** Prefer least-identifiable data first; collect additional attributes only when required for safety, legal duty, or incident response.

### B. Consent and legal basis
- [ ] User-facing notices clearly state what data is collected, why, retention period, and contact channel.
- [ ] Consent capture is explicit where required (timestamp, version of notice, method of consent).
- [ ] Non-consent legal bases (public interest, legal obligation, vital interest, contract) are documented per processing activity.
- [ ] Consent withdrawal/revocation path exists and is operationally testable.
- [ ] Consent changes are propagated to downstream systems and archives.

**Recommendation standard:** Keep consent language plain, specific, and separated from non-essential terms.

### C. Retention, archival, and deletion
- [ ] A retention schedule exists for communications, incident records, biodata inputs, logs, and derived analytics.
- [ ] Retention periods are risk-based and legally defensible; indefinite storage is prohibited unless formally justified.
- [ ] Secure deletion or irreversible anonymization controls are implemented and logged.
- [ ] Legal hold procedure exists for investigations, disputes, or regulatory requests.
- [ ] Backups, replicas, and exported files follow the same retention/deletion controls.

**Recommendation standard:** Retain only what is required for safety, accountability, and legal compliance; purge on schedule with proof.

### D. Incident reporting and public communications
- [ ] Incident severity criteria define when legal/compliance escalation is mandatory.
- [ ] Incident register captures event time, detection source, affected data categories, impact, and containment actions.
- [ ] Internal notification workflow includes Security, Legal, Operations, and Communications leads.
- [ ] Public communication templates are factual, non-speculative, and avoid exposing personal/biodata.
- [ ] Post-incident report records root cause, legal impact assessment, and corrective actions.

**Recommendation standard:** Communicate early, factual updates while preserving confidentiality and evidentiary integrity.

### E. Cross-border data transfers
- [ ] All external processors, infrastructure locations, and transfer pathways are inventoried.
- [ ] Transfer necessity is documented (why in-country processing is insufficient or unavailable).
- [ ] Contractual safeguards exist with partners/processors (security obligations, breach notice duties, onward transfer limits).
- [ ] Transfer risk assessment covers destination-country legal protections and access risks.
- [ ] Technical safeguards (encryption in transit/at rest, key management, access segmentation) are verifiable.

**Recommendation standard:** Default to local/regional processing where feasible; when transfer is necessary, use layered legal + technical safeguards.

### F. Access control, logging, and audit trails
- [ ] Role-based access control enforces least privilege for security and biodata repositories.
- [ ] Privileged actions require strong authentication and are separately logged.
- [ ] Access logs are immutable or tamper-evident, time-synchronized (UTC), and retained per policy.
- [ ] Audit trails link data access, data changes, approvals, and communication releases to accountable identities.
- [ ] Periodic access recertification removes stale, orphaned, and excessive privileges.

**Recommendation standard:** Every sensitive access and change must be attributable, reviewable, and resistant to tampering.

---

## 3) Kenyan Constitution Privacy Principles → EDEN-BioGuard Data Flow Mapping

> **Reference anchor:** Constitution of Kenya (2010), Article 31 (right to privacy), read together with national data protection principles (lawful processing, purpose specification, minimization, accuracy, storage limitation, integrity/confidentiality, accountability).

| Kenyan privacy principle (application lens) | EDEN-BioGuard data flow | Primary legal/compliance concern | Required control |
|---|---|---|---|
| Privacy of person, home, communications and information (Art. 31) | User/stakeholder incident alerts, contact channels, acknowledgement records | Unnecessary exposure of identities and contact metadata | Minimize recipient data; restrict audience lists; redact personal identifiers in broad notices |
| Lawful and fair processing | Ingestion of ecological incidents and biodata from feeds/partners | Processing without clear legal basis or notice | Record legal basis per source; maintain source notices and data-sharing terms |
| Purpose specification and limitation | Reuse of surveillance/biodata for analytics, dashboards, or token-linked reporting | Function creep beyond original safety/public-health purpose | Maintain purpose registry; require legal approval before secondary use |
| Data minimization | Intake schemas for field/lab/ecological records | Over-collection of directly identifying data | Apply field-level necessity review; prefer aggregation/pseudonymization |
| Accuracy and integrity | Risk scoring, incident classification, public status updates | Harm from inaccurate data and reputational/legal exposure | Validation checks, correction workflow, versioned updates, provenance logging |
| Storage limitation | Logs, incident artifacts, and biodata history stores | Excessive retention increasing breach and misuse risk | Enforced retention schedule, legal hold controls, auditable deletion |
| Security safeguards and confidentiality | Platform access, admin tooling, API integrations, exports | Unauthorized access, insider misuse, silent exfiltration | RBAC, MFA for privileged roles, encryption, segmented environments, immutable logs |
| Accountability and auditability | End-to-end processing across ingestion → scoring → communications | Inability to evidence compliance decisions | Maintain auditable trails for consent/legal basis, approvals, access, and releases |
| Cross-border protection | Cloud providers, foreign processors, external analytics | Transfer to jurisdictions with weaker protections | Transfer impact assessment, contractual safeguards, encryption, transfer register |

---

## 4) Evidence Pack Requirements for Audit Sign-off

For each checklist section, attach:
- Policy/control reference (document ID + version)
- System evidence (screenshot, log extract, config, or query output)
- Control owner and review date
- Open gaps with target remediation date

**Minimum sign-off block:**
- Security Lead: ____________________
- Legal/Compliance Reviewer (Kimberly Onduru): ____________________
- Engineering Owner: ____________________
- Date (UTC): ____________________

---

## 5) Template Language for “Requirements or Change Recommendations” (Issue/PR Reviews)

Use these snippets in GitHub issues/PR review comments.

### A. Requirement statement template

```text
Requirement: [LEGAL/SECURITY/BIODATA]
Current behavior: <what exists now>
Risk/Legal concern: <privacy, lawful basis, over-collection, retention, transfer, access, incident disclosure, etc.>
Required change: <specific change required>
Evidence of completion: <tests, logs, screenshots, policy links>
Owner: <team/person>
Due date: <YYYY-MM-DD>
```

### B. PR recommendation template (blocking)

```text
Change recommendation (Blocking):
This PR introduces or modifies data handling in a way that requires explicit legal/security controls.
Please implement the following before approval:
1) <control/change 1>
2) <control/change 2>
3) <control/change 3>
Acceptance criteria:
- <criterion 1>
- <criterion 2>
Compliance mapping:
- Kenyan Constitution Article 31 privacy alignment: <yes/no + explanation>
- Data protection principles alignment: <yes/no + explanation>
```

### C. PR recommendation template (non-blocking)

```text
Change recommendation (Non-blocking):
To strengthen compliance posture, consider implementing:
- <improvement 1>
- <improvement 2>
Suggested timeline: <sprint/date>
Rationale: Improves minimization, accountability, or transfer-risk posture.
```

### D. Incident communication legal check template

```text
Incident legal check:
- Facts verified: <yes/no>
- Personal/biodata exposed in draft communication: <yes/no>
- Redaction applied: <yes/no/not needed>
- Public statement limited to necessary details: <yes/no>
- Legal reviewer sign-off required: <yes/no>
```

---

## 6) Operational Review Cadence

- Monthly: access recertification + logging integrity sampling
- Quarterly: retention/deletion control verification + cross-border transfer review
- Per major release: privacy impact review for new data flows
- Per incident: legal communications review and post-incident compliance closeout

This guide is intended to be implementation-ready for legal validation and engineering execution.
