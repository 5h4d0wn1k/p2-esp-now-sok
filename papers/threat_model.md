# P2 — ESP-NOW Threat Model Table

| Threat ID | Attack | Layer | Precondition | Impact | Difficulty | Mitigation Status | Reference |
|-----------|--------|-------|--------------|--------|------------|-------------------|-----------|
| T1 | Passive eavesdropping | Data-link | Radio in range, channel known | Confidentiality loss | Low | Not mitigated | — |
| T2 | Action-frame replay | Data-link | Capture + replay, same MAC | Cache poisoning, stale state | Medium | Patched (CVE-2024-42483) | CVE-2024-42483 |
| T3 | MAC spoofing / injection | Data-link | No cryptographic identity binding | Impersonation, forged commands | Low | Not mitigated | — |
| T4 | DoS / flood | Data-link | Channel access, no rate limit | Availability loss | Low | Not mitigated | — |
| T5 | Cross-tech confusion | PHY | Shared 2.4 GHz band | Misattribution, decode errors | Medium | Partial (channel select) | — |
| T6 | Key recovery via SCA | PHY (power) | Physical shunt + scope, 100 MS/s | Key extraction | High | Not mitigated (N/A) | P4 reference |
