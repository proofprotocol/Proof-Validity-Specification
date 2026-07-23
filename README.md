> **Zenodo DOI:** [10.5281/zenodo.21379780](https://doi.org/10.5281/zenodo.21379780) — Published 2026-07-15

# Proof Validity Specification

**Document ID:** PP-SPEC-002  
**Version:** 1.0  
**Status:** Published  
**License:** CC BY 4.0  
**Maintained by:** Proof Economy™ Standards Alliance (PESA)  
**Repository:** https://github.com/proofprotocol  
**Published:** 2026-07-12  

---

## Abstract

This specification defines what constitutes a valid proof artifact under the Proof Protocol™. It establishes the minimum required elements for a proof to be considered authentic, tamper-evident, and certifiable, and explicitly defines what does not meet the proof standard. The purpose is to close the structural gap that allows vendor-generated log files, reports, and post-hoc attestations to be presented as independent evidence of security efficacy.

A valid proof under this specification must be structurally impossible to fabricate retroactively. This requirement is not a design preference - it is the minimum threshold that separates proof from assertion.

---

## Status of This Document

This document is a published specification of the Proof Protocol™. It is released under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this document for any purpose, including commercially, provided appropriate credit is given to Nebulonium, Inc. / HACKERverse and PESA as the original source.

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
8. [Relationship to Other Proof Protocol™ Specifications](#8-relationship-to-other-proof-protocol-specifications)
9. [IANA Considerations](#9-iana-considerations)
10. [References](#10-references)
11. [Authors](#11-authors)

---

## 1. Motivation

The cybersecurity industry operates on a foundation of self-attestation. Vendors produce reports, logs, and scores that describe the performance of their own products. Buyers have no independent mechanism to verify these claims. This is not a gap in implementation - it is a structural property of how security efficacy is currently measured and communicated.

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

**ProofRegister™:** The append-only public registry where completed proof bundles are anchored and made queryable.

**Proof of Efficacy Score (PES):** A pair of scores expressing containment and detection performance, defined in PP-SPEC-006. Containment is `BLOCKED / (BLOCKED + OBSERVED + MISSED) × 100`. Detection is `DETECTED / (BLOCKED + OBSERVED + MISSED) × 100`. Only IRRELEVANT cases are excluded from the denominator. Both scores MUST be published together.

**ProofStamp™:** A certification mark awarded to Reports that carry proof and pass independent registry review. Certification criteria are defined in PP-SPEC-009. Carrying proof is necessary but not sufficient for certification.

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
  "execution_start_utc": "<ISO 8601 - MUST postdate VRS pulse>"
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
  "detected": true,
  "content_hash": "<SHA-256 of record content>",
  "previous_record_hash": "<SHA-256 of prior record - genesis uses VRS output value>",
  "chain_hash": "<SHA-256(content_hash + previous_record_hash)>",
  "timestamp_utc": "<ISO 8601>"
}
```

**Failure modes:**

- A missing record in the sequence is not a gap - it is an invalidation event
- A hash mismatch at any link invalidates the chain from that point forward
- A chain that does not originate from the VRS pulse output value is not a valid chain under this specification
- A chain submitted as complete that does not account for all declared test cases in the original commitment is incomplete and fails this requirement

**Note:** An incomplete chain is not a partial proof. It is an invalid proof. Partial execution MUST be declared as a scope event within the chain, not resolved by omission.

---

### 3.4 Witness Declaration

**Requirement:** At minimum one witness MUST be declared in the proof header before execution begins. Witnesses added after execution begins do not satisfy this requirement.

Witness eligibility is defined in the Witness Protocol Specification (PP-SPEC-005) Section 2. It consists of two binary gates:

- **Gate A - Structural:** the witness operates outside the trust boundary of the System Under Test's operator and cannot be configured, disabled, or silenced by them.
- **Gate B - Disinterest:** the witness's economic position is identical whether the resulting Report carries proof or not, and regardless of any score it carries.

Both gates MUST hold. There are no witness classes, levels, or grades. A witness is eligible or it is not.

**Implementation:**

```
witness_declaration = {
  "witness_id": "<unique identifier>",
  "declared_pre_execution": true,
  "gate_a_basis": "<architectural basis for structural independence>",
  "gate_b_declaration": "<compensation basis, invariant to verdict>",
  "roles_also_held": ["corpus_authority" | "scoring_authority" | "none"],
  "residual_trust": "<what must still be trusted>",
  "attestation_method": "<description>",
  "credential_reference": "<optional>"
}
```

**Failure modes:**

- A witness declared after execution begins does not satisfy this requirement
- A witness whose compensation varies with the verdict fails Gate B, whether disclosed or not
- A witness the SUT operator can configure, disable, or silence fails Gate A regardless of corporate separation
- The SUT operator's own logging infrastructure cannot serve as a witness

### 3.5 Immutable Anchoring

**Requirement:** The completed proof bundle MUST be anchored to an append-only public registry. The anchor block reference and registry record hash MUST be included in the final proof bundle.

**Implementation:**

```
anchor_record = {
  "registry": "ProofRegister™ | <equivalent append-only registry>",
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

A log file - including cryptographically signed logs - is not a proof. Logs record what a system reported about itself. They have no pre-execution commitment, no external witness, and no chain linkage. A signed log proves only that a file existed at signing time. It does not prove what the system did, when it did it, or under what conditions.

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

If a test run is genuinely incomplete, it MUST still be registered as a Report with `proof: false` and an explicit gap declaration recording which committed items are unaccounted for. An incomplete run is not a degraded proof. It is a Report that does not carry proof.

### 4.6 Self-Anchored Chains

A proof chain that references only infrastructure controlled by the tester or vendor for its root of trust has no external verifiability. The controlling party controls the clock, the hash function, the chain, and the registry. This describes the current architecture of most blockchain-based security attestation products. Control of the root of trust by an interested party disqualifies a chain from meeting this specification.

### 4.7 Scores Without Denominators

A score expressed without a declared denominator, exclusion criteria, and case classification methodology is a marketing number. It is not a proof metric. Claiming "100% detection" or "99% containment" without publishing the total case count, the classification of each case, and the formula applied to derive the score does not constitute a measurable proof claim.

### 4.8 Clean Runs Without Anomaly Documentation

Any execution that produces zero failures, zero edge cases, and zero OBSERVED or IRRELEVANT classifications SHOULD be treated as suspect. Real adversarial testing against real systems surfaces anomalies. An execution record with no anomaly documentation is not evidence of perfect performance - it is evidence that anomalies were not recorded, not reported, or not encountered due to inadequate test scope.

A proof artifact with no anomaly records is not automatically invalid. However, it MUST include an explicit declaration explaining the absence of anomaly classifications, which will be reviewed as part of registry anchoring.

---

## 5. Proof Determination

Every execution produces exactly one Report. Reports are always produced, always registered, and always retained, regardless of outcome.

A Report either carries proof or it does not. This is a boolean recorded in the Report header in machine-readable and human-readable form. There are no tiers, levels, or grades, and no partial, degraded, or attempted state.

### 5.1 The Proof Floor

A Report carries proof if and only if both of the following hold:

1. **Independent witness.** A witness satisfying both gates of PP-SPEC-005 Section 2 was declared before execution and attested to the run.

2. **Pre-execution commitment.** A hash of the declared scope was submitted to a Verifiable Randomness Source before execution began, every chain record postdates that pulse, and every committed item is accounted for in the chain.

Failure of either condition sets `proof: false`. No exceptions, no weighting, no threshold.

> **Note - proof is indifferent to the result.**
>
> No score affects the determination. A Report carrying 25 percent containment is exactly as valid a proof as one carrying 100 percent. The floor asks who witnessed the execution and whether the scope was committed beforehand. It does not ask how the subject performed.
>
> A protocol that withheld proof from poor results would produce a registry containing only winners, which is vendor benchmarking with cryptography applied. Poor results MUST be as provable as good ones.

### 5.2 Report Attributes

The following are recorded as attributes. They describe the run and do not determine whether it carries proof.

| Attribute | Values |
|---|---|
| `environment_class` | arena, production |
| `chain_complete` | true, false |
| `gaps_declared` | list of declared gaps, empty if none |
| `anomaly_declaration` | required where zero anomalies recorded |
| `residual_trust` | declaration per PP-SPEC-005 Section 2.4 |
| `roles` | corpus authority, witness, scoring authority |

### 5.3 Environment Class

Every Report MUST declare exactly one environment class.

| | Arena | Production |
|---|---|---|
| Adversary | Controlled corpus | Unknown |
| Commitment binds | Full case manifest | Posture and observation scope |
| Denominator | Known | Unknown |

A containment or detection score MUST NOT be asserted from a Production Report. The set of adversarial conditions that occurred is not the set detected.

### 5.4 Certification

ProofStamp eligibility is determined separately under PP-SPEC-009. A Report MUST carry proof to be eligible. Carrying proof does not by itself confer certification. Any performance threshold is a certification decision and forms no part of the proof determination.

---

## 6. Proof Assessment Procedure

The following procedure is used by the registry and by independent assessors. Any failure sets `proof: false` and records the failing step. There is no branching.

### Step 1 - Witness Eligibility
- Verify a witness was declared in the proof header with `declared_pre_execution` set to true
- Verify the Gate A basis describes a position outside the SUT operator's trust boundary
- Verify the Gate B declaration establishes compensation invariant to the verdict
- Verify roles also held are declared

### Step 2 - Pre-Execution Commitment
- Retrieve the VRS pulse referenced in the proof header
- Verify pulse sequence number, seed value, and output value against the public VRS record
- Verify the commitment hash was submitted before the execution start timestamp

### Step 3 - Temporal Integrity
- Verify all chain records postdate the VRS pulse timestamp
- Verify the execution start timestamp postdates the VRS pulse

### Step 4 - Chain Continuity
- Recompute each chain hash from record content and previous record hash
- Verify the genesis record links to the VRS output value
- Verify every item bound in the commitment is accounted for in the chain

### Step 5 - Anchoring
- Verify the anchor hash against the registry block record
- Verify the registry record is publicly queryable and matches the submitted bundle

### Step 6 - Scope Integrity
- Verify the SUT fingerprint matches the declared version and configuration
- Verify scope events are recorded in the chain for any SUT change during execution

### Step 7 - Determination
- All steps pass → `proof: true`
- Any step fails → `proof: false`, with the failing step recorded in the Report

---

## 7. Conformance

An implementation conforms to this specification if:

1. It produces Reports that satisfy all six required elements defined in Section 3
2. It records the proof boolean and the environment class on every Report as defined in Section 5
3. It applies the proof assessment procedure defined in Section 6 without modification
4. It does not represent a Report carrying `proof: false` as meeting the proof standard
5. It does not accept the artifact types enumerated in Section 4 as substitutes for Reports carrying proof
6. It registers and retains every Report regardless of outcome

Implementations seeking ProofStamp™ certification MUST conform to this specification and produce Reports carrying `proof: true`. Certification criteria are defined in PP-SPEC-009.

---

## 8. Relationship to Other Proof Protocol™ Specifications

This specification defines proof validity. It is foundational to the following companion specifications:

| Document | Relationship |
|----------|-------------|
| Proof Protocol™ Specification (PP-SPEC-001) | Core protocol. This document defines validity criteria for artifacts produced under PP-SPEC-001. |
| Witness Protocol Specification (PP-SPEC-005) | Defines the witness eligibility gates referenced in Section 3.4. |
| ProofBundle™ Format Specification (PP-SPEC-003) | Defines the container format that carries the elements required by this specification. |
| ProofRegister™ API Specification (PP-SPEC-004) | Defines the anchoring endpoint referenced in Section 3.5 and the query interface for validity assessment in Section 6. |
| Proof of Efficacy Score Specification (PP-SPEC-006) | Defines the containment and detection formulas and denominator logic referenced in Section 4.7. |
| ProofStamp™ Certification Criteria (PP-SPEC-009) | Defines the certification requirements that build on the proof determination established here. |

---

## 9. IANA Considerations

This document has no IANA considerations.

---

## 10. References

- NIST Randomness Beacon: https://beacon.nist.gov
- RFC 2119 - Key words for use in RFCs: https://www.rfc-editor.org/rfc/rfc2119
- Proof Protocol™ Specification v1.1 (PP-SPEC-001): https://github.com/proofprotocol
- NIST SP 800-90B - Recommendation for the Entropy Sources Used for Random Bit Generation
- Creative Commons CC BY 4.0: https://creativecommons.org/licenses/by/4.0/

---

## 11. Authors

Proof Economy™ Standards Alliance (PESA)  
https://proofeconomy.foundation  
contact@proofeconomy.foundation  

*This specification is maintained by PESA. Governance of this specification follows the PESA practitioner-led model. Vendors may contribute but do not govern.*

---

*Copyright 2026 Nebulonium, Inc. dba HACKERverse. Licensed under CC BY 4.0.*  
*ProofStamp™ is a certification mark of Nebulonium, Inc.*
