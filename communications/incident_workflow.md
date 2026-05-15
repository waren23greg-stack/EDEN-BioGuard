# EDEN-BioGuard Crisis Communication Workflow

This document defines the end-to-end communication workflow for incident response, including public alerts, stakeholder updates, acknowledgement tracking, and post-incident follow-up.

## 1. Workflow Goals
- Communicate quickly and accurately during cybersecurity and ecological incidents.
- Align public messaging and stakeholder coordination from a single process.
- Track recipient acknowledgement and follow-up actions for audit and compliance readiness.

## 2. Communication Roles
- **Incident Commander (IC):** Owns incident status and release approvals.
- **Comms Lead (Rosemary Achieng):** Owns wording, audience targeting, and channel selection.
- **Ops/Engineering Lead:** Verifies technical accuracy.
- **Compliance/Legal Lead:** Reviews notices requiring regulatory alignment.

## 3. Workflow Stages

### Stage A: Detection & Triage (0-15 minutes)
1. Incident is detected by monitoring, field teams, or partner escalation.
2. IC assigns initial severity and opens incident reference code.
3. Comms Lead selects initial template:
   - `communications/templates/incident_alert.md` for broad/public messaging.
   - `communications/templates/stakeholder_notice.md` for targeted stakeholder messaging.

### Stage B: First Communication Release (15-30 minutes)
1. Draft first alert/notice using known facts only.
2. Complete required fields: status, severity, affected groups, immediate actions, next update time.
3. Route for rapid approval:
   - Technical validation by Ops/Engineering Lead.
   - Compliance review when required.
4. Release via designated channels (dashboard, email, SMS, partner channel).

### Stage C: Receipt & Feedback Confirmation (30+ minutes)
1. Track recipient acknowledgement by channel:
   - Email replies
   - Portal acknowledgement
   - API acknowledgement (future integration)
2. Identify non-responding critical stakeholders and escalate contact.
3. Log inbound feedback/questions and map them to incident tasks.

### Stage D: Ongoing Updates (Hourly or status-triggered)
1. Publish status updates at declared cadence or on major changes.
2. Include what changed, what remains uncertain, and revised actions.
3. Keep reference code stable across all updates for traceability.

### Stage E: Resolution & Closure
1. Publish resolution notice with final impact summary and mitigation completed.
2. Provide stakeholder-specific closure details where required.
3. Archive timeline, sent notices, and acknowledgements for audit.

### Stage F: Post-Incident Review (Within 5 business days)
1. Conduct communication retrospective (timing, clarity, reach, acknowledgement rate).
2. Capture lessons learned and update templates/workflow.
3. Share improvement actions with owners and due dates.

## 4. Escalation Matrix (Example)
| Severity | First Public Alert | Stakeholder Notice | Escalation Trigger |
|---|---|---|---|
| Low | Optional | Yes (targeted) | Repeated reports or broadened impact |
| Medium | Yes | Yes | Cross-region impact or service degradation |
| High | Immediate | Immediate | Regulatory concern or critical service outage |
| Critical | Immediate + recurring | Immediate + executive channel | National/partner emergency or safety risk |

## 5. Message Quality Checklist
Before send, confirm:
- [ ] Facts verified and speculation removed
- [ ] Audience and recipient group selected correctly
- [ ] Action steps are concrete and time-bound
- [ ] Next update time is explicitly stated
- [ ] Contact/escalation paths are included
- [ ] Reference code appears in all messages

## 6. Integration Notes for Engineering
- Frontend component: `src/components/UserCommunicationsInterface.jsx`
- Live backend API implemented at: `src/api/communications_api.py`
- Available backend hooks:
  - `POST /api/communications/send`
  - `GET /api/communications/{referenceCode}/status`
  - `POST /api/communications/{referenceCode}/acknowledgements`
- Run locally:
  - `python -m src.api.communications_api`

## 7. Demo Incident Response Cycle
1. Create public incident alert (status: `INVESTIGATING`, severity: `HIGH`).
2. Send stakeholder notice to partners and regulators.
3. Simulate acknowledgement collection.
4. Publish follow-up update (status: `CONTAINED`).
5. Publish final resolution message and archive communication record.
