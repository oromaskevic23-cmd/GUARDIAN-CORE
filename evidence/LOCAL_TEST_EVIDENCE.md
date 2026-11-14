# Local reference test evidence — 2026-11-14

Status: LOCAL TESTED REFERENCE; independent QA pending.

- Tested source revision: `6bf344729e2312b41250574bd15141daad8b0792`
- Node.js v22.16.0; command: `node --test test/reference.test.mjs`
- Result: 7/7 PASS, 0 failed.
- Source Git blob SHA-1: `e9751d7887de0e8d71b41fe2041302560e2b68ee`
- Test Git blob SHA-1: `b6f14290046a448bf5b73286ba246bfb9dd80ece`
- Both local file blob identifiers matched GitHub's fetched file identifiers for the exact tested revision.

## Cross-component smoke evidence

Two additional tests passed locally with all four exact source blobs. Total: 25 unit + 2 integration = 27 passing tests. The integration fixture uses ephemeral synthetic Ed25519 keys, a synthetic identity, a pre-signed permit, an in-memory veto snapshot and a signed checkpoint. It neither issues real approvals nor executes external operations. Integration script: [AUDIT LEDGER smoke test](https://github.com/oromaskevic23-cmd/AUDIT-LEDGER/blob/301352f2cd880485f39412896e41f50f7b2b6c9f/integration/smoke.test.mjs). Git blob SHA-1: `d29c33bdbcba79c3cc1c5c53fd5bcfba93bceda9` (matched GitHub).

Reproduction: place sibling checkouts at these exact source revisions (AUDIT-LEDGER at integration commit 301352f2cd880485f39412896e41f50f7b2b6c9f), run `node --test AUDIT-LEDGER/integration/smoke.test.mjs` from parent directory.

- ZERO-TRUST: `18d895334ad077dce70db9b1b53a210a816c2f43`
- GUARDIAN-CORE: `6bf344729e2312b41250574bd15141daad8b0792`
- APPROVAL-GATEWAY: `1fde4606f48ede3d1db73ed194658664d55cb746`
- AUDIT-LEDGER: `0381a21d0db0a903d3a3ff343852fe2cbdaa9e08`

No CI run, independent reviewer, deployment, real Owner credential enrollment, durable storage, production execution or external security audit is claimed. No paid services used.
