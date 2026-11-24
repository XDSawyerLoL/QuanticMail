# Quantic Pay — European interoperability preparation

As of 2026-11-21, laboratory only. No authorized PSP, DESP connection, certification, real account or monetary settlement.

Primary sources:
- ECB pilot FAQ, updated 28 October 2026, Q46, Q53–55, Q84–85: https://www.ecb.europa.eu/euro/digital_euro/pilot/html/ecb.faq-digital-euro-pilot.en.html
- ECB pilot timeline: https://www.ecb.europa.eu/euro/digital_euro/pilot/html/index.en.html
- ISO 20022 CustomerCreditTransferInitiationV09 definition: https://www.iso20022.org/standardsrepository/type/CustomerCreditTransferInitiationV09

The pilot uses an ISO 20022-based data dictionary and adapted REST APIs, not an assertion that the pilot accepts pain.001 XML. CPACE is a candidate for online proximity NFC. Exact specifications and eligibility remain dependent on the authorized participant and final standards. A TSP can support a pilot PSP, which remains responsible. The first issuance is conditional on legislation and an ECB decision.

Implementation: pay-iso20022-preview.mjs projects a verified fictional transaction into a small offline model using payment identification, decimal EUR amount, synthetic creditor and initiation time, with proof set commitment. It requires a fresh authenticated hybrid quorum over the local set. The reference is deterministic and limited to 34 characters. This is not an ISO schema-valid document or a DESP request; no account routing, personal identifiers, live endpoint, settlement or PSP token. The lab adapter explicitly refuses submit and settle.

Integration test: four separate witness processes, four private stores, optional four distinct native UDP Scattering links, reboot of witness processes, stale wallet history rejection and loss of one/two witnesses, plus offline mapping from a fresh signed quorum. Wallet signer is synthetic Node fixture, not native Windows terminal. Physical tests and full Windows launcher are still needed.

Before a real integration: contract with an authorized PSP and acquire applicable pilot technical specifications; validate exact data types and schema, idempotency/status/refund model, approved connectivity and key custody; define responsibility for authentication, AML, fraud controls, privacy, operational resilience and incident handling with the PSP; conduct independent security audit and PSP/Eurosystem tests. Do not infer regulatory approval from interoperability tests. Preserve end-user authorization and distinguish submitted, accepted and settled outcomes. No production adapter should be enabled by this laboratory code.
