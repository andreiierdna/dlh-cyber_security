# MedDefense Health Systems  
## Task 4 — The Governance Architecture

MedDefense's governance problem is not an absence of technical personnel. It is an absence of clearly assigned decision rights. Existing project evidence already shows shared ownership across IT, Security, Clinical Operations, Biomedical Engineering, Finance, Radiology, and vendors. For example, EHR assets are assigned to Clinical Operations/IT, PACS to Radiology/IT, billing to Finance/IT, and medical IoT to Clinical Operations/Biomedical Engineering. The governance structure below separates **security accountability**, **technical execution**, and **business/data ownership** so that those responsibilities are not confused.

# Part 1 — RACI Matrix

**R = Responsible:** performs the work.  
**A = Accountable:** owns the outcome and final decision.  
**C = Consulted:** provides required expertise or business input.  
**I = Informed:** receives status or decisions.

| Security Activity | CEO | Deputy CISO — James Chen | IT Director — Sarah Park | Dept Heads | Security Analyst |
|---|---|---|---|---|---|
| **Security budget approval** | **A** | **R** | C | C | C |
| **Vulnerability remediation** | I | **A** | **R** | C | **R** |
| **Incident response execution** | I | **A** | **R** | C | **R** |
| **Security policy approval** | **A** | **R** | C | C | **R** |
| **Risk acceptance decisions** | **A** | **R** | C | C | C |
| **Security awareness training** | I | **A** | C | **R** | **R** |
| **Vendor risk assessment** | I | **A** | C | C | **R** |
| **Audit coordination** | I | **A** | C | C | **R** |

### Governance Rationale

The key distinction is between **Security deciding what risk must be addressed** and **IT implementing the technical change**. James therefore owns the vulnerability-management program and is accountable for remediation being prioritized and tracked, while Sarah is responsible for implementing operating-system, network, application, identity, and infrastructure changes. The Security Analyst identifies vulnerabilities, validates remediation, maintains evidence, and reports unresolved exceptions.

That model matches the existing remediation evidence. For example, the priority matrix assigns EHR database remediation to IT/Database + Security + the EHR owner, Active Directory remediation to IT/AD + Security, medical-device changes to IT + Security + Biomedical/Clinical + the vendor, and Apache remediation to IT + Security + the Finance application owner. Governance therefore should formalize this shared execution model rather than declaring either IT or Security the sole owner of endpoint or infrastructure security.

The **CEO is accountable for material risk acceptance** because accepting a cybersecurity risk means accepting the associated clinical, financial, regulatory, and operational consequences on behalf of MedDefense. James should analyze the risk, recommend treatment, and document the exception, but Security should not be able to unilaterally accept organizational risk that it is also responsible for assessing.

Department Heads are consulted whenever a control affects clinical or business operations. This is especially important for Radiology, Biomedical Engineering, Finance, Clinical Operations, and other departments whose systems cannot be changed solely on technical grounds. They do not, however, have unilateral authority to exempt departmental systems or data from enterprise security requirements.

---

# Part 2 — Role Definitions

## Data Owner

**Assigned Role:** **Relevant Department Head / Business or Clinical Leader**

Examples include the Clinical Operations leader for EHR information, the Finance leader for billing information, Radiology leadership for PACS/imaging data, and Dr. Patel for Cardiology data within his departmental authority.

A **Data Owner** is the business or clinical authority accountable for how a particular information set is used. The owner determines legitimate business use, approves appropriate access, supports classification and retention decisions, and determines how loss of confidentiality, integrity, or availability affects the department.

The project evidence already associates assets with functional owners: the EHR with Clinical Operations/IT, PACS with Radiology/IT, billing with Finance/IT, and department file data with IT/department owners.

Dr. Patel can therefore be a **Data Owner for authorized Cardiology data**, but that does not mean he personally owns the data or can remove it from MedDefense governance. His ownership is an accountability role exercised within organizational security, privacy, retention, and technology requirements. The personal Cardiology NAS finding demonstrates why this distinction matters: business ownership does not authorize an individual to create an unmanaged storage environment outside enterprise controls.

## Data Controller

**Assigned Role:** **MedDefense Health Systems as the organization, represented by the CEO and executive leadership**

A **Data Controller** determines the purposes for which personal information is processed and the principal means by which that processing occurs. This role properly belongs to MedDefense as an organization rather than to James, Sarah, Dr. Patel, or another individual employee.

MedDefense decides why patient, employee, billing, identity, and clinical information is collected and which organizational systems and authorized services process it. The CEO represents executive accountability for those organizational decisions, while departmental leaders and technical personnel act under that authority.

This distinction prevents a department from treating institutional patient or employee information as independently controlled departmental property.

## Data Processor

**Assigned Role:** **Authorized third-party service providers and technology vendors that process MedDefense information on MedDefense's behalf**

A **Data Processor** performs processing activities for the Data Controller according to contractual or authorized instructions. Depending on the service, this could include an EHR service provider, cloud/SaaS provider, hosted application provider, or another contracted technology organization that processes MedDefense information while providing its service.

The processor does not become the owner of MedDefense's information simply because its systems store or manipulate the information. MedDefense remains responsible for defining the authorized purpose and appropriate controls, while the vendor must operate within the agreed processing relationship.

This role also explains why **vendor risk assessment belongs under security governance**. MedDefense's threat analysis includes trusted third-party and vendor pathways, so outsourcing processing does not outsource accountability for the associated risk.

## Data Custodian / Steward

**Assigned Role:** **IT Director Sarah Park and delegated IT/system administrators, working with designated departmental data stewards**

A **Data Custodian** is responsible for the technical handling and protection of information according to requirements established by the Data Owner and MedDefense governance. Custodial responsibilities include maintaining systems, implementing access controls, backups, approved configurations, patching, availability, and operational safeguards.

Sarah is the appropriate enterprise-level custodian because IT operates the infrastructure that stores, transmits, authenticates access to, and backs up much of MedDefense's information. The Asset Registry repeatedly shows shared departmental/IT ownership of the underlying technical systems.

The **stewardship** component should remain close to the business department. A departmental steward helps maintain appropriate access lists, data definitions, quality, classification, and acceptable use, while Sarah's IT organization implements the technical controls. Security advises both parties and verifies that the resulting controls satisfy enterprise requirements.

The separation can therefore be summarized as:

**Data Owner:** decides what authorized use should be.  
**Data Controller:** MedDefense determines why and how organizational personal data is processed.  
**Data Processor:** authorized vendor processes data on MedDefense's behalf.  
**Data Custodian/Steward:** implements and maintains the operational controls and day-to-day governance around the information.

---

# Part 3 — The CISO Question

## Consequences of the Vacant CISO Position

The vacant CISO position leaves MedDefense without a single executive security authority responsible for translating Board-level risk decisions into an enduring security program. James can perform many operational leadership functions as Deputy CISO, but the vacancy contributes directly to the governance ambiguity described in the scenario: Security and IT can dispute ownership, departments can treat enterprise requirements as optional, and significant risk decisions may be driven by operational pressure rather than an established authority structure.

The consequences include fragmented accountability for security strategy, inconsistent risk acceptance, unclear authority during incidents, conflict over control ownership, weaker enforcement of enterprise policy, fragmented vendor oversight, and difficulty sustaining multi-year initiatives such as vulnerability management, centralized monitoring, identity governance, segmentation, and recovery resilience. These are particularly significant because the posture assessment already identifies formal incident response, vulnerability management, centralized monitoring, identity governance, change management, and shadow-IT governance as material weaknesses.

## Recommendation: Use a vCISO as the Interim Model

MedDefense should **engage a vCISO rather than hire a full-time CISO during the current funding cycle**, while retaining James as the internal Deputy CISO and operational security leader. The reason is financial capacity, not a reduced need for leadership. The current vulnerability plan commits **$116,000** of the **$120,000** annual security budget, leaving only **$120,000 − $116,000 = $4,000** in contingency. The complete remediation roadmap is **$161,000**, producing an existing funding deficit of **$161,000 − $120,000 = $41,000** before any CISO staffing expense is added. A full-time CISO funded from the same security budget would therefore require MedDefense to displace already-prioritized controls unless the Board provides additional funding. A vCISO provides the more appropriate interim governance model because the engagement can be scoped around executive risk governance, policy authority, Board reporting, incident-readiness oversight, and mentoring James without immediately creating another full-time executive position. The project files do not provide either CISO salary data or vCISO pricing, so no unsupported cost estimate should be inserted. Any vCISO expenditure above the remaining **$4,000** contingency must therefore receive separate funding or an explicit Board-approved reallocation. MedDefense should reassess the case for a permanent full-time CISO in the next budget cycle after the initial remediation program and governance structure have been established.

## Governance Outcome

The proposed structure resolves the ownership dispute by separating responsibilities rather than assigning every security activity to one department. **Security governs risk; IT operates technology; Department Heads own legitimate business use of their data and systems; executive leadership accepts organizational risk; and the Security Analyst provides assessment, monitoring, validation, and evidence.**

Under this model, Sarah does not independently own endpoint-security risk merely because IT administers the endpoints, James does not personally execute every technical safeguard merely because Security governs the program, and Dr. Patel cannot exempt Cardiology information from enterprise controls merely because he is clinically responsible for its use. Each party has defined authority, and no Critical security decision depends on whoever “shouts loudest.”
