# Microsoft-Preview-Data-protection-DLP

# Project 4 — Microsoft Purview: Data Protection & Compliance
 
> Hands-on lab: build layered data-protection controls in Microsoft Purview — sensitivity labels with encryption, a DLP policy keyed to those labels, and a retention label with disposition review — mapped to a documented insider trade-secret theft case.
 
---
 
## 1. Scenario — the real-world incident this maps to
 
**Anchor: the Anthony Levandowski / Waymo–Uber trade-secret theft (2016–2017).**
 
One of the most thoroughly documented insider data-exfiltration cases on record, producing both a federal criminal conviction and a major civil trade-secrets action.
 
Levandowski was a senior engineer on Google's self-driving car project (later Waymo). In the weeks before resigning to found a startup subsequently acquired by Uber, he downloaded approximately **14,000 confidential files** — design documents, schematics, and trade secrets — from an internal repository onto a personal device. Waymo sued Uber; the case settled for a reported $245M in equity. Levandowski was later criminally convicted of trade-secret theft.
 
The pattern is the classic **departing-insider exfiltration**:
 
> A legitimate, authorised user with normal access — in a defined window around resignation — bulk-downloads sensitive material and moves it somewhere the organisation doesn't control (personal device, USB, personal cloud, personal email).
 
### The problem it solves
 
Project 3 (Defender XDR) dealt with an **external** attacker breaking in. This is the mirror image: a **trusted insider**, no malware, no exploit — just an authorised human moving data they're permitted to touch, to a place they shouldn't. Traditional threat detection is largely blind to this, because nothing is technically malicious.
 
Purview answers it by governing **the data itself and the behaviour around it**. Each control maps to a stage of the incident:
 
| Control | What it would have done in the Waymo case |
|---|---|
| **Sensitivity labels** | Classified and *encrypted* the design docs so exfiltrated copies are unreadable off-network |
| **DLP** | Detected and blocked bulk movement of that content to external recipients |
| **Retention** | Governed how long the material legitimately lives, and prevented premature destruction of records |
| **Insider Risk** | Correlated an HR leaver signal with anomalous data movement — the purpose-built detection for this exact pattern |
| **Audit** | Provided the forensic record of who accessed what, when — the evidence that made the case provable |
 
---
 
## 2. Environment
 
| Component | Detail |
|---|---|
| Tenant | Microsoft 365 E5 trial |
| Portal | Microsoft Purview unified portal (`purview.microsoft.com`) |
| Test identity | `testuser1` |
| Cost | £0 — all controls built are covered by per-user E5 licensing; pay-as-you-go paths deliberately avoided |
 
**Cost discipline note:** Purview now operates two billing models — per-user licensing for Microsoft 365 and Windows/macOS endpoint sources (covered by E5), and a **pay-as-you-go consumption model** for non-M365 data sources (AWS, GCP, Azure SQL, Box, Dropbox) and certain browser/network protections. The DLP creation flow surfaces a "Set up pay-as-you-go billing" prompt and an "Inline web traffic" option that falls under the metered model. Both were declined. Everything built here sits inside E5 entitlement.
 
---
 
## 3. Build
 
### 3.1 Sensitivity label — classification and encryption
 
Created a custom label, `Trade Secret - Internal Only`, positioned at priority 12 (above Microsoft's built-in `Highly Confidential` at 9).
 
![Sensitivity label review — access control, watermark and footer configured](screenshots/01-sensitivity-label.png)
 
**Configuration and reasoning:**
 
- **Scope: Files & other data assets, Email** — protects documents and mail, not containers.
- **Access control: encryption with permissions assigned to all users in the organisation.** This is the core control. Encryption binds to the *file*, not the location — a copy on a USB stick, in personal cloud storage, or attached to a personal email address remains encrypted and openable only by permitted identities. This is the direct counter to the Waymo exfiltration.
- **Content marking: watermark (`TRADE SECRET`) + footer (`TRADE SECRET - Internal Only`).** Deliberately paired with encryption to demonstrate the two-layer model — **marking is a human control** (deters the careless, makes leaked screenshots self-evidently company property); **encryption is the technical control** (stops the determined). Real deployments use both.
- **Auto-labelling: deliberately not configured.** Auto-labelling matches *content patterns* (credit card numbers, national IDs). "Trade secret" is not pattern-detectable — a design schematic contains no regex-matchable string. This tier is manually applied by content owners. Auto-labelling is appropriate for regulated data types where content matching is reliable, not for IP.
- **Container labelling (Teams/Groups/SharePoint): skipped.** It protects the container, not the files within it, and requires separate tenant enablement.
**Design decision worth noting — offline access.** The label allows offline access indefinitely. For genuine trade secrets, tightening this (a fixed number of days) means a departing employee's cached copies stop working once the window lapses. Encryption alone isn't the whole story; **revocation matters too.**
 
### 3.2 Publishing the label
 
A created label does nothing until published via a label policy. This create-vs-publish distinction is the most common point of confusion in Purview.
 
![Label policy review — scoped publication with justification requirement enabled](screenshots/02-label-policy.png)
 
**Key settings:**
 
- **Scoped to one account** rather than the global policy. Building a dedicated policy (rather than piggybacking on the existing global one) forces engagement with the scoping and settings screens, and mirrors real practice — restrictive labels are scoped to the teams that need them, not blanket-published.
- **"Users must provide a justification to remove a label or lower its classification" — enabled.** This is the insider-threat control. A user attempting to downgrade a Trade Secret document must type a reason, and that justification text is written to Activity Explorer. A departing employee trying to strip protection leaves an audit trail. It's a detection signal, not just friction.
- **Default label: explicitly cleared.** The wizard defaulted both documents *and* emails to `Trade Secret - Internal Only`. Left unchanged, every routine email and document created by that user would have been automatically encrypted and restricted to internal-only — breaking external communication entirely and rendering the classification meaningless (if everything is top-tier, nothing is). **Classification only works if it discriminates.** Caught at review and removed.
### 3.3 Data Loss Prevention — enforcement at the boundary
 
The label answers *"what is this?"* DLP answers *"where is it allowed to go?"*
 
![DLP policy creation review — custom policy, Exchange scope, simulation mode](screenshots/03-dlp-create.png)
 
**Policy: `Trade Secret DLP - Block External Sharing`**
 
- **Custom policy** rather than a regulatory template — templates key off built-in sensitive info types; this rule needed to reference a custom label.
- **Location: Exchange email only.** Deliberately narrow. Endpoint DLP (Devices) was excluded as the lab VM was deallocated; Teams and SharePoint were declined in favour of proving one channel first. *Start narrow, validate, then expand.*
- **Policy mode: simulation.** A DLP policy in enforce mode on day one can break business functions immediately — misconfigured conditions or an over-broad classifier can stop finance emailing invoices. Simulation logs every match and shows exactly what *would* have been blocked, without blocking. The professional workflow is **simulate → review matches → tune → enforce.**
- **Declined auto-promotion after 15 days.** The wizard offers to switch the policy to enforcement automatically if untouched for 15 days. Left off — **enforcement should follow review of simulation results, not elapse by default.**
**The rule:**
 
![DLP rule conditions and actions — sensitive info type, external sharing, sensitivity label](screenshots/06-dlp-rule.png)
 
```
Conditions:
  Content contains sensitive info types: Credit Card Number
  AND Content is shared from Microsoft 365 with people outside my organization
  AND Content contains sensitivity labels: Trade Secret - Internal Only
 
Actions:
  Notify users with email and policy tips
  Restrict access to the content for external users
  Send alerts to Administrator
```
 
Notes on the configuration:
 
- **Confidence level: High.** A credit card match requires Luhn checksum validation, not merely a 16-digit pattern. Lower confidence catches more but flags arbitrary numbers.
- **Instance count: 1 to Any.** In production this floor would typically be raised — one card number in an email is likely a legitimate transaction; fifty is a data dump. **Tuning instance count is how you separate routine business from bulk exfiltration.**
- **External scoping lives in the action, not the condition.** The action "Block only people outside your organization" (rather than "Block everyone") means internal collaboration flows freely while egress is blocked. This is not obvious from the documentation.
- **Policy tips enabled.** Most data loss is careless rather than malicious; a warning shown in Outlook *while composing* stops the accident at the point of decision. Arguably DLP's highest-value feature for real-world risk reduction.
- **Known limitation:** the three conditions are joined by **AND**, narrowing the rule to content matching *all* classifiers simultaneously. In production these would be OR'd, or split into separate rules, so either signal fires independently.
### 3.4 Retention label — governance over time
 
![Retention label review — 7 years, disposition review, named reviewer stage](screenshots/07-retention-label.png)
 
**Label: `Trade Secret - 7 Year Retention`**
 
- **Retain items for a specific period: 7 years, based on creation date.** The critical property is not "keep for 7 years" but that **labelled items cannot be permanently deleted during that period, including by their creator.** In the insider context, this means a departing employee cannot destroy the records of what they accessed.
- **Retention action: "Preserve, review and delete" (disposition review)** rather than automatic deletion. Auto-deletion destroys content on a timer with no human judgement — the clock doesn't know whether a document is currently evidence in litigation or still commercially live. Disposition review routes it to a named reviewer and creates an audit record of **who approved destruction and when.** For IP and legal-sensitive records, that's the defensible posture.
- **Disposition stage: `Legal Review`, single named reviewer.** Purview supports up to 5 sequential stages — Legal → Records Management → Business Owner, each logged. That approval chain *is* the defensibility in litigation.
- **Automatic stage approval: left off.** It auto-approves a stage if the reviewer doesn't respond within 7–365 days, meaning records could be destroyed because someone was on holiday rather than because anyone decided. Same principle as declining DLP auto-promotion: **destruction should be a decision, not a timeout.**
*Lab caveat: `testuser1` was assigned as disposition reviewer. In production this role belongs to legal, records management, or a compliance owner — it carries real authority, since the reviewer approves permanent destruction of records.*
 
### 3.5 Audit — the forensic layer
 
Unified audit logging was found to be **disabled** in the tenant. The Audit search interface was greyed out with the message *"we're having trouble figuring out if activity is being recorded"* and prompted **"Start recording user and admin activity."**
 
**Finding:** audit logging is not universally on by default in a fresh E5 trial, and **it only captures activity from the moment it is enabled** — no historical backfill. All configuration performed prior to enablement is therefore absent from the log. Search results also take up to 24 hours to become available after first enabling.
 
This is a genuinely important operational lesson: **the forensic layer that made the Waymo case provable has to be switched on before the incident, not after.** An organisation that enables audit in response to a suspected insider event has already lost the evidence.
 
---
 
## 4. Problems encountered
 
Documented honestly, because the friction is the realistic part.
 
### 4.1 Conditional Access from Project 2 blocked label validation
 
Attempting to verify the published label as `testuser1` in Office on the web returned an access denial.
 
![Conditional Access block — compliant device required](screenshots/04-ca-block.png)
 
The Conditional Access policy built in **Project 2** requires a compliant, Intune-enrolled device. Testing from a non-enrolled personal machine was denied in Chrome (hard block), then in Edge after switching browser profile and signing in app-only.
 
**Resolution: deferred, deliberately.** The available options were (a) enrol a personal device into a lab tenant, (b) exclude the test user from the Conditional Access policy, or (c) pay to run the Intune-enrolled VM. Rather than enrol a personal device or weaken a working security control for convenience, end-user validation was deferred and the label configuration confirmed admin-side.
 
**This is a genuine example of layered controls interacting** — a data-protection test blocked by an identity control, both working exactly as designed. It is also the correct outcome: the CA policy did its job.
 
### 4.2 Label-to-DLP synchronisation delay
 
On the day of creation, `Trade Secret - Internal Only` did not appear in the DLP rule's sensitivity-label picker (which showed only the 9 Microsoft built-in labels). The DLP policy was therefore built initially using the **Credit Card Number** sensitive info type — instantly available, and easier to test.
 
The label appeared and was successfully added as a condition the following day. **Dependency to be aware of: DLP cannot reference a sensitivity label until that label has synced into the DLP service, which is not immediate.**
 
![DLP policy edit — stage renamed to "Advanced DLP rules"](screenshots/05-dlp-edit.png)
 
### 4.3 Portal navigation drift
 
- The classic compliance portal (`compliance.microsoft.com`) now redirects to the unified Purview portal. Course material and blog walkthroughs written against the classic UI no longer match.
- The unified portal distinguishes a **solution catalog entry** (a description page with Overview / Benefits / Requirements) from **the solution itself** (the working UI). Landing on the catalog card and finding no "Create" button is a common and confusing dead end.
- The same wizard stage is named **"Policy settings"** during DLP policy *creation* and **"Advanced DLP rules"** during *editing* — the reason a rule can appear impossible to locate when returning to a policy.
### 4.4 Propagation delays throughout
 
| Control | Stated delay |
|---|---|
| Sensitivity label → user apps | Up to 24 hours |
| Sensitivity label → DLP picker | ~24 hours observed |
| DLP policy sync | Up to ~1 hour |
| Retention label publishing | Up to 7 days |
| Audit search availability after enablement | Up to 24 hours |
 
Purview is **policy-driven and asynchronous**. Unlike EDR work, where an action produces observable telemetry within minutes, configuration here often cannot be validated in the same session. This materially changes how the tool is worked with — and is worth knowing before committing to a deployment timeline.
 
---
 
## 5. Data classification mapping
 
| Tier | Label | Protection | Example content |
|---|---|---|---|
| 0 | Personal | None | Personal, non-business |
| 1 | Public | None | Press releases, marketing |
| 2 | General | Marking | Everyday internal documents |
| 5 | Confidential | Marking + optional encryption | Sensitive business information |
| 9 | Highly Confidential | Encryption, restricted groups | Financial, legal, HR records |
| **12** | **Trade Secret - Internal Only** | **Encryption + internal-only + watermark/footer** | **Design documents, schematics, IP — the Waymo tier** |
 
Tiers 0–9 are Microsoft's built-in taxonomy (present by default on new tenants under the modern label scheme). Tier 12 was purpose-built for this scenario.
 
---
 
## 6. Control mapping to the insider kill chain
 
| Stage of insider exfiltration | Control | Status in this lab |
|---|---|---|
| Sensitive content exists unclassified | Sensitivity label + encryption | ✅ Built |
| User downgrades/strips classification | Justification requirement + Activity Explorer logging | ✅ Built |
| Content sent to external recipient | DLP block + policy tip + admin alert | ✅ Built (simulation) |
| Records destroyed to cover tracks | Retention label — deletion prevented for 7 years | ✅ Built |
| Disposal without oversight | Disposition review, named reviewer, staged approval | ✅ Built |
| Behavioural signal (leaver + anomalous access) | Insider Risk Management | ⬜ Out of scope |
| Forensic reconstruction after the fact | Unified audit logging | ⚠️ Enabled; no historical data |
 
**Insider Risk Management was scoped out.** It is the most direct analogue to the Levandowski pattern — the departing-employee policy correlates an HR leaver signal with anomalous data movement — but it requires an HR data connector to produce meaningful signal, and carries its own analytics delay. Without a connector feeding leaver events, the policy would have been configured but inert. Documented as a known gap rather than built for appearance.
 
---
 
## 7. Key takeaways
 
1. **Insider threat is a different problem from external attack.** No malware, no exploit, no anomalous authentication — an authorised user moving data they're permitted to touch. Threat detection tooling is largely blind to it; the answer is governing the data and the behaviour.
2. **Encryption binds to the file, not the location.** This is what makes labelling more than a sticker — exfiltrated content stays unreadable. But it must be paired with **revocation** (offline-access limits, expiry) to counter cached copies held by departing staff.
3. **Create ≠ publish.** Both sensitivity labels and retention labels are inert until published via a policy. The single most common Purview misconception.
4. **Defaults are dangerous.** The label policy wizard defaulted every document and email to the most restrictive label. Left unreviewed, that alone would have broken external communication and rendered the classification scheme meaningless.
5. **Simulation before enforcement, decisions before timeouts.** DLP in simulation mode, auto-promotion declined, disposition review rather than auto-delete, automatic stage approval off. Every enforcement and destruction action should follow a human decision.
6. **Controls interact — sometimes adversarially.** A Conditional Access policy from an earlier project blocked validation of a data-protection control in this one. Both were correct. Understanding how layers collide is part of operating them.
7. **Audit must be enabled before the incident.** Logging captures nothing retrospectively. An organisation that turns on audit in response to a suspected insider event has already lost the evidence.
---
 
## 8. Cleanup
 
All Purview controls built in this lab are policy objects with no ingestion cost, so no teardown is required for billing reasons. To remove them:
 
- **DLP** → Policies → delete `Trade Secret DLP - Block External Sharing`
- **Information Protection** → Policies → Label policies → delete `Trade Secret Label Policy`; then Sensitivity labels → delete `Trade Secret - Internal Only`
- **Data Lifecycle Management** → Retention labels → delete the retention label policy, then `Trade Secret - 7 Year Retention`
- **Audit** — may be left enabled; it is good practice for a tenant regardless
- **Entra** — if the Conditional Access policy was temporarily modified for testing, ensure any exclusion has been reverted
*Note: the Azure VM from Project 3 (`intune-test-vm`) remains deallocated and was not required for any part of this project.*
 
---
 
*Lab conducted on a Microsoft 365 E5 trial tenant. No production data involved. All pay-as-you-go Purview capabilities deliberately avoided; total cost £0.*
 
