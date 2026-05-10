# EDEN-BioGuard UI Legal & Privacy Banners (Kenya Context)

> **Draft for legal review by Kimberly Onduru.**
> This content is prepared for product implementation and is **not legal advice**.

## 1) Privacy Notice Banner (Short Form)

**Title:** Privacy & Biodata Notice  
**Banner Copy:**
"EDEN-BioGuard collects software telemetry and ecological observations to protect biodiversity and community safety. We process personal data under the Kenya Data Protection Act, 2019 and the Constitution (Art. 31 privacy)."

**Buttons / Links:**
- `View Privacy & Consent Terms`
- `Manage Data Preferences`
- `Continue`

## 2) Data Sharing Banner (Public Alerts)

**Title:** Public Alert Data Use  
**Banner Copy:**
"When legally and operationally necessary, EDEN-BioGuard may publish area-level public alerts. Personal identifiers are minimized before publication to protect privacy while supporting public interest and environmental protection."

**Buttons / Links:**
- `How Public Alerts Work`
- `Data Minimization Policy`
- `Understood`

## 3) Explicit Consent Banner (User Action Required)

**Title:** Consent Required  
**Banner Copy:**
"By selecting ‘I Consent,’ you agree that EDEN-BioGuard may process account, device, and ecological field data for security response, ecosystem risk detection, and compliance obligations under Kenyan law."

**Required Checkbox Text:**
- `[ ] I have read and understood the EDEN-BioGuard User Consent and Data Processing Notice.`

**Buttons:**
- `I Consent`
- `Decline`

## 4) Field Collection / Land-Linked Data Banner

**Title:** Land & Community Data Safeguard  
**Banner Copy:**
"Field records may include geospatial or land-linked observations. EDEN-BioGuard applies privacy-by-design, lawful-use controls, and fair-treatment principles aligned with constitutional privacy and property rights protections."

**Buttons / Links:**
- `Land Data Safeguards`
- `Community Rights Information`

## 5) Banner Display Rules

- Show **Privacy Notice Banner** at first login and after material policy changes.
- Show **Explicit Consent Banner** before enabling uploads of user-linked ecological data.
- Show **Data Sharing Banner** before users access public-alert dashboards the first time.
- Retain audit evidence of consent choice (timestamp, policy version, user ID hash).
- Support clear language in English first, with Swahili version queued for public deployments (operational alignment with Kenya's official-language context; final legal requirement to be confirmed by counsel).

## Kenyan Constitutional & Legal Mapping (Implementation Notes)

- **Constitution of Kenya, Article 31 (Privacy):** informs user notice, consent, and minimization requirements.
- **Constitution of Kenya, Article 40 (Property):** supports careful handling of land-linked data and non-arbitrary interference.
- **Constitution of Kenya, Article 10 (National values):** transparency, accountability, and public participation influence alert governance.
- **Data Protection Act, 2019:** lawful basis, purpose limitation, data minimization, retention controls, and data subject rights.

## Compliance Checklist (Future Legal Review)

- [ ] Banner copy reviewed for legal accuracy by Kimberly Onduru.
- [ ] Consent action is explicit (no pre-ticked checkbox).
- [ ] Privacy banner links to current policy version and effective date.
- [ ] Public alert workflow confirms identifier minimization before publication.
- [ ] Audit logs capture consent version, timestamp, and actor ID.
- [ ] Swahili translation approved for public-facing deployments.

## References (Non-Legal Advice)

1. Constitution of Kenya (2010), Articles 10, 31, 40.
2. Kenya Data Protection Act, 2019.
3. Office of the Data Protection Commissioner (Kenya) implementation guidance.
