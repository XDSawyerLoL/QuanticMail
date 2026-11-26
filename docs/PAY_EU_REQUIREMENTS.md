# Quantic Pay — European requirements baseline (2026-11-21)

Internal engineering baseline, not an official Eurosystem specification or legal opinion. Product role: technical service provider (TSP) to an authorized PSP. Quantic does not issue euros, hold client funds, operate DESP or claim certification. The existing ledgers are synthetic and must never determine actual digital euro balances or settlement. The PSP/Eurosystem interface is authoritative for real outcomes.

## Source hierarchy and change control
- Digital euro legislative file 2023/0212(COD), ongoing: https://eur-lex.europa.eu/procedure/EN/2023_212
- Commission proposal COM(2023)369 (not final law): https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=COM%3A2023%3A0369%3AFIN
- ECB scheme rulebook portal, interim draft v0.91 dated 2 July 2026: https://www.ecb.europa.eu/euro/digital_euro/timeline/rulebook/html/index.en.html
- ECB pilot FAQ updated 28 October 2026, Q46, Q49, Q79, Q84–86: https://www.ecb.europa.eu/euro/digital_euro/pilot/html/ecb.faq-digital-euro-pilot.en.html
- GDPR: https://eur-lex.europa.eu/eli/reg/2016/679
- PSD2 SCA technical standards: https://eur-lex.europa.eu/eli/reg_del/2018/389/2023-09-12/eng
- DORA: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- European Digital Identity framework: https://eur-lex.europa.eu/eli/reg/2024/1183/oj

Legal requirements and draft pilot specifications must be tracked separately. Reassess upon publication of final law, rulebook revisions, PSD3/PSR applicability, applicable implementing acts and PSP onboarding documents. No invented mandatory holding limit, NFC protocol version or official endpoint. Pilot candidates can change. Contractually agree scope and applicable laws with PSP and counsel, including AML/CFT, consumer protection, accessibility and cybersecurity product obligations.

## Requirements and acceptance evidence
| ID | Control | Basis | Acceptance evidence | Current gap |
| --- | --- | --- | --- | --- |
| EU-01 | PSP responsibility and authoritative settlement | ECB pilot FAQ Q46/Q49; legislative proposal | PSP agreement, assigned roles, certified interface and status reconciliation | no partner or DESP access |
| EU-02 | Payment data dictionary | FAQ Q84–85 | exact versioned official JSON schemas, contract tests, field mapping and negative tests | offline conceptual ISO 20022 projection only |
| EU-03 | Payment authentication and dynamic linking | RTS 2018/389 arts 4–5, subject to applicability | independently assessed SCA factors, credential lifecycle, explicit amount and payee display, rejection of modified intent and replay | hybrid signatures and native lab approval are not certified SCA |
| EU-04 | Privacy and minimization | GDPR arts 5, 25, 32; draft rulebook | data inventory, legal bases, retention and access rules, DPIA where required, tested deletion/restore, role-specific disclosures | full histories currently visible to lab witnesses; no production personal data |
| EU-05 | Operational resilience | DORA arts 28–30 and applicable PSP obligations | risk inventory, incident process, tested recovery, RTO/RPO agreed with PSP, audit/access and exit terms, subcontractor/location register | lab SQLite and CI only, no independent recovery audit |
| EU-06 | Safe acceptance/contactless | FAQ Q79/Q84 | exact applicable CPACE profile, SoftPOS certification per PSP, device and NFC tests | no NFC implementation |
| EU-07 | EUDI interoperability | Regulation 2024/1183; FAQ Q86 | approved relying-party onboarding and credential validation, consent and minimization tests; optional method in pilot | no EUDI integration or eIDAS certification |
| EU-08 | Offline privacy and spending limits | draft law and rulebook, not final | PSP-approved device architecture, offline double-spend and recovery tests, applicable privacy and limit requirements | no offline funds; online quorum is not offline payment |
| EU-09 | Fraud, dispute, refund and AML/CFT | applicable PSP duties and draft rulebook | risk controls, sanctions responsibilities, verifiable status, dispute/recourse procedures, operational test evidence | no regulated onboarding or live accounts |
| EU-10 | Accessibility and inclusion | applicable accessibility law; scheme requirements | accessible UI, screen-reader/keyboard checks, assisted flows and independent usability evaluation | native console lab only |
| EU-11 | Cryptographic agility and isolation | internal security objective supporting risk controls, not an ECB mandated algorithm | approved algorithms per interface, independent audit, key rotation, custody, upgrade and rollback tests | P-256/Ed25519 + ML-DSA-65 lab; no mandated PQ certification |
| EU-12 | Availability and integrity of internal quorum | internal control supporting DORA risk management | reviewed consensus protocol with safety and progress assumptions, faults, partitions, rollback and recovery tests | 3-1 certificate recovery works; 2-2 remains blocked; no production BFT |
| EU-13 | Contractual responsibility and supply chain | DORA art 30 | inventory/SBOM, signed distribution, patch policy, testing and handover, partner-approved contractual controls | unsigned alpha, no PSP contract |

The same matrix is represented in lib/quantic/pay-eu-readiness.mjs as a frozen baseline of unmet/partial/external requirements. It is a reporting boundary, not a certificate validator or production enablement system. No configuration flag, test success or claimed partner can make the laboratory authorized to transmit live payment instructions.

## Engineering policy
1. Separate native security, simulated ledger and PSP adapter. Never use lab keys, synthetic ids, internal witness votes or traffic covering as proof of a real settlement or identity.
2. Implement applicable public requirements now with negative tests. Maintain versioned traceability, independent evidence and an external acceptance owner for partner-only requirements.
3. Keep APIs fail-closed. Explicitly distinguish local authorization, PSP acceptance and confirmed settlement. No simulated response may be accepted as a real PSP result.
4. Minimize personal data with approved disclosure; Scattering must not subvert lawful PSP fraud controls, operational monitoring or statutory record obligations. Offline mode needs its own reviewed design, not a global witness log of offline purchases.
5. Design consensus recovery independently from official payment scheme requirements. No arbitrary unlock or lowering quorum to overcome a split.
