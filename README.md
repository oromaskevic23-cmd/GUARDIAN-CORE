<p align="center"><img src="assets/branding/banner.svg" alt="GUARDIAN CORE — Policy & Risk Decision Engine" width="100%"/></p>

# GUARDIAN CORE

**Policy & Risk Decision Engine · IMPERIAL Core**

*Protect every decision.*

A pure deterministic decision function with explicit deny precedence, scoped veto snapshots, organization isolation and approval requirements.

**Status: LOCAL TESTED REFERENCE / INDEPENDENT QA PENDING.** No production deployment, certification or real Owner enrollment is claimed.

## Quick start

Node.js 22.13+; no external dependencies or paid services. The local run in this iteration used Node.js 24.22.1.

```sh
npm test
```

Use `PolicyFloor.evaluate(...)` for signed local policy and veto checks. The lower-level `evaluate(...)` assumes its inputs are already authenticated. In both APIs the host is responsible for identity verification.

- [Architecture and release gates](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Source](src/index.mjs) · [Tests](test/reference.test.mjs) · [Local test evidence](evidence/LOCAL_TEST_EVIDENCE.md)
- [Authorship](AUTHORS.md) · [Roadmap](ROADMAP.md)

## Limitations

Inputs must be authenticated by a trusted caller; no signed policy distribution, verified identity integration, risk telemetry or remote enforcement is deployed.

## Related components

[ZERO TRUST](https://github.com/oromaskevic23-cmd/ZERO-TRUST) · [GUARDIAN CORE](https://github.com/oromaskevic23-cmd/GUARDIAN-CORE) · [APPROVAL GATEWAY](https://github.com/oromaskevic23-cmd/APPROVAL-GATEWAY) · [AUDIT LEDGER](https://github.com/oromaskevic23-cmd/AUDIT-LEDGER) · [CYBER HAK](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public)

## Founder and authorship

<p align="center"><img src="https://raw.githubusercontent.com/oromaskevic23-cmd/oromaskevic23-cmd/main/assets/alexander-romaskevich-portrait-20261110.jpg" alt="Alexander Romaskevich" width="160"/></p>

**Alexander Nikolaevich Romaskevich (RomaskevicH)** — Founder • Owner • CEO, IMPERIAL Core. Architect / Final Architectural Decision Authority.

Public source visibility is not a license grant. See [LICENSE](LICENSE).

**Architecture Before Implementation. Evidence Before Trust.**

## Local policy and veto rollback protection

[PolicyFloor](src/policy-floor.mjs) verifies signed policy and veto snapshots, stores their monotonic floors together, and rejects rollback or changed content at the same epoch. A trusted host must verify identity before supplying `identityVerified`; this module does not authenticate that claim. State checks are not atomic with external execution. Key rotation and distributed state are not implemented.

SQLite files are created with owner-only POSIX permissions; existing files with broader permissions and symlinks are rejected on POSIX. Use a trusted directory and protect the database against replacement. Windows ACL enforcement is not implemented or tested.

## Security hardening v0.2

[Implementation](src/veto.mjs) · [Tests](test/veto.test.mjs) · [Evidence and limitations](docs/HARDENING_V0_2.md).

## Security composition v0.3

Signed organization-scoped policy evaluation and signed veto verification. Deny on malformed, expired, tampered or rolled-back state. The identityVerified input must be established by the trusted host, not accepted from an agent.

[Implementation](src/signed-policy.mjs) · [Tests](test/signed-policy.test.mjs) · [Scope and evidence](docs/COMPOSITION_V0_3.md).
