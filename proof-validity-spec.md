# Proof Validity Specification

**Document ID:** PP-SPEC-002  
**Version:** 1.0  
**Status:** Published  
**License:** CC BY 4.0  
**Maintained by:** Proof Economy Standards Alliance (PESA)  
**Repository:** https://github.com/proofprotocol  
**Published:** 2026-07-12  

---

## Abstract

This specification defines what constitutes a valid proof artifact under the Proof Protocol. It establishes the minimum required elements for a proof to be considered authentic, tamper-evident, and certifiable, and explicitly defines what does not meet the proof standard. The purpose is to close the structural gap that allows vendor-generated log files, reports, and post-hoc attestations to be presented as independent evidence of security efficacy.

A valid proof under this specification must be structurally impossible to fabricate retroactively. This requirement is not a design preference — it is the minimum threshold that separates proof from assertion.

---

## Status of This Document

This document is a published specification of the Proof Protocol. It is released under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this document for any purpose, including commercially, provided appropriate credit is given to Nebulonium, Inc. / HACKERverse and PESA as the original source.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Terminology](#2-terminology)
3. [Required Elements of a Valid Proof](#3-required-elements-of-a-valid-proof)
   - 3.1 Pre-Execution Commitment
   - 3.2 Temporal Integrity
   - 3.3 Chain Continuity
   - 3.4 Witness Declaration
   - 3.5 Immutable Anchoring
   - 3.6 Scope Integrity
4. [What Is Not a Valid Proof](#4-what-is-not-a-valid-proof)
5. [Validity Tiers](#5-validity-tiers)
6. [Validity Assessment Procedure](#6-validity-assessment-procedure)
7. [Conformance](#7-conformance)
8. [Relationship to Other Proof Protocol Specifications](#8-relationship-to-other-proof-protocol-specifications)
9. [IANA Considerations](#9-iana-considerations)
10. [References](#10-references)
11. [Authors](#11-authors)

---

## 1. Motivation

The cybersecurity industry operates on a foundation of self-attestation. Vendors produce reports, logs, and scores that describe the performance of their own products. Buyers have no independent mechanism to verify these claims. This is not a gap in implementation — it is a structural property of how security efficacy is currently measured and communicated.

The consequences are predictable:

- Buyers cannot distinguish between products that perform differently in adversarial conditions
- Vendors face no market penalty for inflated claims
- Regulatory and compliance frameworks accept documentation that would not survive independent scrutiny
- The emergence of autonomous agentic AI systems introduces a new category of unverifiable action at machine speed, where human review of self-reported logs is neither practical nor sufficient

This specification defines what a proof artifact must contain to be treated as valid evidence of security efficacy. It is written as a technical standard, not a vendor requirement. Any tool, platform, or methodology that meets these requirements may produce a valid proof. Any artifact that does not meet these requirements, regardless of its source, format, or authority, is not a proof.

---

## 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

**Proof Artifact:** A structured record asserting that a security behavior occurred, meeting the validity requirements defined in this specification.

**Pre-Execution Commitment:** A cryptographic hash of test parameters and system state submitted to a verifiable external randomness source before execution begins.

**System Under Test (SUT):** The security tool, platform, or agent whose behavior is being proven.

**Verifiable Randomness Source (VRS):** An external, publicly auditable source of timestamped randomness that neither the tester nor the vendor controls. The NIST Randomness Beacon is the reference implementation.

**Proof Chain:** An append-only sequence of hash-linked records documenting execution events from commitment through completion.

**Proof Bundle:** The complete container artifact including proof header, chain records, witness declarations, PES score, and anchor reference.

**Witness:** A declared party that attests to the conditions, execution, or results of a proof run. Witnesses are classified by independence level (see Witness Protocol Specification, PP-SPEC-005).

**ProofRegister:** The append-only public registry where completed proof bundles are anchored and made queryable.

**Proof of Efficacy Score (PES):** A numeric score expressing containment performance. Defined as `Blocked / (Blocked + Missed) × 100`. OBSERVED and IRRELEVANT classified cases are explicitly excluded from the denominator.

**ProofStamp:** The HACKERverse certification mark awarded to proof artifacts that meet Proof-Complete validity tier requirements and pass independent registry review.

---

## 3. Required Elements of a Valid Proof

A valid proof artifact MUST contain all six of the following elements. The absence of any single element results in an artifact that does not meet the proof standard under this specification.

---

### 3.1 Pre-Execution Commitment

**Requirement:** A cryptographic hash of the test parameters, scope definition, and declared system state MUST be committed to a Verifiable Randomness Source before any execution begins.

**Rationale:** This is the foundational requirement. Without a pre-execution commitment to an external, uncontrollable randomness source, any artifact can be constructed after the fact. Log files can be edited. Timestamps can be forged. Hash values can be computed over fabricated data. Pre-execution commitment to an external VRS makes retroactive fabrication computationally and practically infeasible.

**Implementation:**

```
commitment_payload = {
  "sut_fingerprint": "<SHA-256 of SUT version, config, and scope>",
  "test_parameters_hash": "<SHA-256 of test case manifest>",
  "declared_witness_ids": ["<witness_id_1>", ...],
  "declared_scope": "<scope definition string>",
  "commitment_timestamp_utc": "<ISO 8601>"
}

commitment_hash = SHA-256(JSON.stringify(commitment_payload))
```

The commitment hash MUST be submitted to the VRS and the VRS response MUST be recorded in the proof header before execution begins.

**Failure mode:** Any artifact where the VRS pulse postdates execution events, or where no VRS reference exists, fails this requirement. No exception is permitted.

---

### 3.2 Temporal Integrity

**Requirement:** All execution events MUST postdate the pre-execution commitment VRS pulse. The proof header MUST record the VRS pulse sequence number, seed value, and output value.

**Implementation:**

```
proof_header = {
  "vrs_provider": "NIST Randomness Beacon",
  "vrs_pulse_uri": "https://beacon.nist.gov/beacon/2.0/pulse/...",
  "vrs_pulse_sequence": <integer>,
  "vrs_seed_value": "<hex>",
  "vrs_output_value": "<hex>",
  "commitment_hash": "<SHA-256 from 3.1>",
  "execution_start_utc": "<ISO 8601 — MUST postdate VRS pulse>"
}
```

**Failure modes:**

- Any execution event timestamped before or at the VRS pulse time fails temporal integrity
- A VRS reference that cannot be independently verified against the public VRS record fails this requirement
- A VRS pulse from a provider controlled by the tester or vendor fails this requirement

---

### 3.3 Chain Continuity

**Requirement:** Every proof record in the chain MUST hash-link to its predecessor. The genesis record MUST link to the VRS pulse output value. Any break in chain continuity invalidates all records from the break point forward.

**Implementation:**

```
proof_record = {
  "record_id": "<sequential integer>",
  "record_type": "TTP | OBSERVATION | SCOPE_EVENT | ...",
  "classification": "BLOCKED | MISSED | OBSERVED | IRRELEVANT",
  "content_hash": "<SHA-256 of record content>",
  "previous_record_hash": "<SHA-256 of prior record — genesis uses VRS output value>",
  "chain_hash": "<SHA-256(content_hash + previous_record_hash)>",
  "timestamp_utc": "<ISO 8601>"
}
```

**Failure modes:**

- A missing record in the sequence is not a gap — it is an invalidation event
- A hash mismatch at any link invalidates the chain from that point forward
- A chain that does not originate from the VRS pulse output value is not a valid chain under this specification
- A chain submitted as complete that does not account for all declared test cases in the original commitment is incomplete and fails this requirement

**Note:** An incomplete chain is not a partial proof. It is an invalid proof. Partial execution MUST be declared as a scope event within the chain, not resolved by omission.

---

### 3.4 Witness Declaration

**Requirement:** At minimum one witness MUST be declared in the proof header before execution begins. Witnesses added after execution begins do not satisfy this requirement.

Witness classes are defined in the Witness Protocol Specification (PP-SPEC-005):

- **Class 1 — Automated:** Machine-generated telemetry from an independent system
- **Class 2 — Human-in-Loop:** A human observer present during execution
- **Class 3 — Independent Third Party:** A party with no financial or organizational relationship to the tester or vendor

**Implementation:**

```
witness_declaration = {
  "witness_id": "<unique identifier>",
  "witness_class": 1 | 2 | 3,
  "declared_pre_execution": true,
  "attestation_method": "<description>",
  "credential_reference": "<optional>"
}
```

**Failure modes:**

- A witness declared after execution begins does not satisfy this requirement
- A witness with a financial or organizational relationship to the vendor cannot be classified as Class 3
- A vendor's own logging infrastructure cannot serve as the sole Class 1 witness — it must be an independent automated system

---

### 3.5 Immutable Anchoring

**Requirement:** The completed proof bundle MUST be anchored to an append-only public registry. The anchor block reference and registry record hash MUST be included in the final proof bundle.

**Implementation:**

```
anchor_record = {
  "registry": "ProofRegister | <equivalent append-only registry>",
  "campaign_id": "<registry campaign identifier>",
  "block_number": <integer>,
  "anchor_hash": "<SHA-256 of submitted proof bundle>",
  "anchor_timestamp_utc": "<ISO 8601>",
  "registry_query_uri": "<publicly queryable endpoint>"
}
```

**Failure modes:**

- A registry controlled by the tester or vendor does not satisfy the immutability requirement
- A registry that allows record modification or deletion after submission fails this requirement
- An anchor hash that does not match the submitted bundle on independent verification fails this requirement

---

### 3.6 Scope Integrity

**Requirement:** The System Under Test MUST be declared and cryptographically fingerprinted before execution begins. Changes to the SUT during execution MUST be recorded as scope events within the chain. Post-execution scope amendments are not permitted.

**Implementation:**

```
sut_declaration = {
  "sut_name": "<product or agent name>",
  "sut_version": "<version string>",
  "sut_config_hash": "<SHA-256 of configuration>",
  "sut_fingerprint": "<SHA-256 of version + config>",
  "declared_pre_execution": true
}
```

**Failure modes:**

- A SUT that is updated, patched, or reconfigured during execution without a chain scope event fails this requirement
- A SUT declaration submitted after execution begins fails this requirement
- A SUT fingerprint that cannot be independently verified against the declared version and configuration fails this requirement

---

## 4. What Is Not a Valid Proof

The following artifact types do not meet the proof standard under this specification, regardless of the authority, format, or detail level of the issuing party. These exclusions are explicit and non-negotiable.

---

### 4.1 Log Files

A log file — including cryptographically signed logs — is not a proof. Logs record what a system reported about itself. They have no pre-execution commitment, no external witness, and no chain linkage. A signed log proves only that a file existed at signing time. It does not prove what the system did, when it did it, or under what conditions.

This includes: SIEM exports, EDR telemetry exports, firewall logs, agent activity logs, and any structured log format regardless of signing method.

### 4.2 Vendor-Generated Reports

A report summarizing test results, authored by the party with a financial interest in the outcome, is self-attestation. It is not a proof. This applies regardless of report length, technical detail, third-party branding, or regulatory framing.

This includes: penetration test reports, red team reports, vendor benchmark reports, compliance assessment reports, and AI safety evaluation summaries authored by the evaluated vendor.

### 4.3 Screenshots and Video Recordings

Unanchored media has no verifiable relationship to the system state it purports to capture. Media can be staged, edited, selectively captured, or generated. Without pre-execution commitment and chain linkage, media evidence cannot establish what occurred, when it occurred, or whether it is representative.

### 4.4 Post-Hoc Hashes

Hashing a results file after execution and submitting it as proof of integrity proves only that the file existed at hash time. It does not establish what was executed, when execution occurred, or whether the results file reflects actual execution. Post-hoc hashing is the most common form of false proof architecture in current security tooling.

### 4.5 Incomplete Chains

A proof chain that covers a subset of execution events and is silent on the remainder is not a partial proof. Silence in a proof chain is fabrication by omission. An incomplete chain submitted as complete is a materially false proof artifact.

If a test run is genuinely incomplete, it MUST be registered as Proof-Attempted (see Section 5) with explicit gap declaration. It cannot be registered as Proof-Complete or Proof-Minimal.

### 4.6 Self-Anchored Chains

A proof chain that references only infrastructure controlled by the tester or vendor for its root of trust has no external verifiability. The controlling party controls the clock, the hash function, the chain, and the registry. This describes the current architecture of most blockchain-based security attestation products. Control of the root of trust by an interested party disqualifies a chain from meeting this specification.

### 4.7 Scores Without Denominators

A score expressed without a declared denominator, exclusion criteria, and case classification methodology is a marketing number. It is not a proof metric. Claiming "100% detection" or "99% containment" without publishing the total case count, the classification of each case, and the formula applied to derive the score does not constitute a measurable proof claim.

### 4.8 Clean Runs Without Anomaly Documentation

Any execution that produces zero failures, zero edge cases, and zero OBSERVED or IRRELEVANT classifications SHOULD be treated as suspect. Real adversarial testing against real systems surfaces anomalies. An execution record with no anomaly documentation is not evidence of perfect performance — it is evidence that anomalies were not recorded, not reported, or not encountered due to inadequate test scope.

A proof artifact with no anomaly records is not automatically invalid. However, it MUST include an explicit declaration explaining the absence of anomaly classifications, which will be reviewed as part of registry anchoring.

---

## 5. Validity Tiers

Proof artifacts are classified into four validity tiers. Tier classification determines registry eligibility and certification eligibility.

| Tier | Name | Description | ProofStamp Eligible |
|------|------|-------------|---------------------|
| 1 | **Proof-Complete** | All six required elements present. Chain intact. Anchored to ProofRegister. Minimum Class 2 witness. | Yes |
| 2 | **Proof-Minimal** | All six required elements present. Chain intact. Anchored to ProofRegister. Class 1 witness only. | No |
| 3 | **Proof-Attempted** | Pre-execution commitment present. One or more other elements missing or degraded. Explicit gap declaration required. | No |
| 4 | **Not a Proof** | No pre-execution commitment present. Cannot be registered as a proof artifact under any classification. MAY be registered as a Report for audit trail purposes with explicit non-proof labeling. | No |

**Tier 4 is a hard floor.** The absence of pre-execution commitment is not a degraded proof. It is a categorically different artifact class. Tier 4 artifacts registered in ProofRegister under a Report classification MUST carry explicit machine-readable and human-readable labeling indicating they do not meet the proof standard.

---

## 6. Validity Assessment Procedure

The following procedure is used by ProofRegister and by independent assessors to evaluate proof artifact validity.

### Step 1 — Pre-Execution Commitment Check
- Retrieve the VRS pulse referenced in the proof header
- Verify the pulse sequence number, seed value, and output value against the public VRS record
- Verify that the commitment hash was submitted to the VRS before the execution start timestamp
- **Failure at this step → Tier 4**

### Step 2 — Temporal Integrity Check
- Verify that all chain records postdate the VRS pulse timestamp
- Verify that the execution start timestamp in the proof header postdates the VRS pulse
- **Failure at this step → Tier 4**

### Step 3 — Chain Continuity Check
- Recompute each chain hash from record content and previous record hash
- Verify the genesis record links to the VRS output value
- Verify that all declared test cases in the commitment manifest are accounted for in the chain
- **Failure at this step → Tier 3 if commitment exists, Tier 4 if commitment absent**

### Step 4 — Witness Declaration Check
- Verify that all declared witnesses appear in the proof header with pre-execution declaration flag set to true
- Verify witness class declarations
- **Failure at this step (no witness declared pre-execution) → Tier 3**

### Step 5 — Anchoring Check
- Verify the anchor hash against the ProofRegister block record
- Verify the registry record is publicly queryable and matches the submitted bundle
- **Failure at this step → Tier 3**

### Step 6 — Scope Integrity Check
- Verify the SUT fingerprint matches the declared version and configuration
- Verify that scope events are recorded within the chain for any SUT changes during execution
- **Failure at this step → Tier 3**

### Step 7 — Tier Assignment
- All steps pass, Class 2+ witness → **Tier 1: Proof-Complete**
- All steps pass, Class 1 witness only → **Tier 2: Proof-Minimal**
- Step 1 passes, one or more other steps fail → **Tier 3: Proof-Attempted**
- Step 1 fails → **Tier 4: Not a Proof**

---

## 7. Conformance

An implementation conforms to this specification if:

1. It produces proof artifacts that satisfy all six required elements defined in Section 3
2. It correctly classifies artifacts according to the validity tiers defined in Section 5
3. It applies the validity assessment procedure defined in Section 6 without modification
4. It does not represent Tier 3 or Tier 4 artifacts as meeting the proof standard
5. It does not accept the artifact types enumerated in Section 4 as substitutes for valid proof artifacts

Implementations seeking ProofStamp certification MUST conform to this specification and produce artifacts that qualify at minimum as Tier 1: Proof-Complete.

---

## 8. Relationship to Other Proof Protocol Specifications

This specification defines proof validity. It is foundational to the following companion specifications:

| Document | Relationship |
|----------|-------------|
| Proof Protocol Specification (PP-SPEC-001) | Core protocol. This document defines validity criteria for artifacts produced under PP-SPEC-001. |
| Witness Protocol Specification (PP-SPEC-005) | Defines witness classes referenced in Section 3.4. |
| ProofBundle Format Specification (PP-SPEC-003) | Defines the container format that carries the elements required by this specification. |
| ProofRegister API Specification (PP-SPEC-004) | Defines the anchoring endpoint referenced in Section 3.5 and the query interface for validity assessment in Section 6. |
| Proof of Efficacy Score Specification (PP-SPEC-006) | Defines the PES formula and denominator logic referenced in Section 4.7. |
| ProofStamp Certification Criteria (PP-SPEC-007) | Defines the certification requirements that build on Tier 1 validity established here. |

---

## 9. IANA Considerations

This document has no IANA considerations.

---

## 10. References

- NIST Randomness Beacon: https://beacon.nist.gov
- RFC 2119 — Key words for use in RFCs: https://www.rfc-editor.org/rfc/rfc2119
- Proof Protocol Specification v1.1 (PP-SPEC-001): https://github.com/proofprotocol
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for Random Bit Generation
- Creative Commons CC BY 4.0: https://creativecommons.org/licenses/by/4.0/

---

## 11. Authors

Proof Economy Standards Alliance (PESA)  
https://proofeconomy.foundation  
contact@proofeconomy.foundation  

*This specification is maintained by PESA. Governance of this specification follows the PESA practitioner-led model. Vendors may contribute but do not govern.*

---

*Copyright 2026 Nebulonium, Inc. dba HACKERverse. Licensed under CC BY 4.0.*  
*ProofStamp is a certification mark of Nebulonium, Inc.*
