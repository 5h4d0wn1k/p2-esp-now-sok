# P2 — ESP-NOW Security SoK — p2-esp-now-sok

Research tooling pack for a systematic-knowledge survey (SoK) of ESP-NOW security: attack taxonomy, frame parser, replay simulator, independent-observer fidelity metric, and SoK results matrix exporter.

## Overview

- Embedded **attack taxonomy matrix** mapping ESP-NOW attacks (eavesdropping, CVE-2024-42483 replay/cache-poisoning reproduction, MAC spoofing/injection, denial, cross-technology confusion) to preconditions, impact, and mitigation status
- **Action-frame parser** that decodes ESP-NOW byte payloads and surfaces peer MAC, payload, and replay-relevant fields
- **Replay engine simulator** that models whether a captured frame would be accepted against `patched` (stateful anti-replay) vs `unpatched` (no state) targets
- **Independent-observer fidelity metric** comparing a "victim log" to an "nRF24 observer log" for frames seen, precision/coverage, and timing correlation
- **SoK results matrix exporter** producing a paper-ready attack x mitigation table (markdown + LaTeX + text)
- Fully offline demo over embedded data; no hardware required

## Features

- **Taxonomy Engine**: attack x preconditions x impact x mitigation matrix, rendered as text and markdown
- **Frame Parser**: decodes category/OUI, peer MAC, frame type, sequence counter, and payload from raw hex frames
- **Replay Simulator**: stateful anti-replay (patch) vs stateless (unpatched) acceptance logic
- **Fidelity Metric**: coverage, precision, F1, and Pearson timing correlation between victim and observer logs
- **SoK Exporter**: full attack x mitigation matrix as a paper table (markdown, LaTeX, text)
- **Offline Demo**: self-contained with embedded sample frames and CSV logs

## Research framing

This repository is **tooling for the P2 paper** — a systematic-knowledge (SoK) survey of ESP-NOW security. The embedded taxonomy, frame decoder, replay model, and fidelity metric here support the analysis and artifact pipeline; the live dataset is to be collected later on the hardware rig (ESP32 peers plus an independent nRF24 observer) and dropped into the same CSV/frame formats this toolchain consumes. The offline demo currently runs all pieces on embedded sample data to validate the pipeline before hardware collection.

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 run_demo.py
```

## Usage

```bash
# Run full offline demo (taxonomy + parser + replay + fidelity + exporter)
python3 run_demo.py

# Run unit tests
python3 -m unittest discover -s tests -v
```

Programmatic use:

```python
from esp_now_sok import TaxonomyEngine, FrameParser, ReplaySimulator, FidelityMetric, SokResultsExporter

eng = TaxonomyEngine()                      # embedded attack matrix
print(eng.markdown_report())                # markdown taxonomy table

parser = FrameParser()
frames = parser.parse_all()                 # parse embedded sample frames
frame = frames[0]
print(frame["peer_mac"], frame["sequence"]) # decode peer MAC / replay-relevant seq

sim = ReplaySimulator()
print(sim.simulate(frame, "unpatched"))     # would replay be accepted?

fm = FidelityMetric()                       # victim vs nRF24-observer logs
print(fm.compute())                         # fidelity score

print(SokResultsExporter().to_latex())      # paper-ready LaTeX table
```

## Example Output

```
[1] ATTACK TAXONOMY MATRIX (text)
  [2] CVE-2024-42483 Replay / Cache-Poisoning Reproduction
      Preconditions : Vulnerable ESP-NOW stack (cache not cleared); ...
      Impact        : Replay of stale cached frames/state, cache poisoning...
      Mitigation    : Mitigated in patched stacks; reproducibly vulnerable in unpatched
[2] ESP-NOW ACTION-FRAME PARSER
  copy of CVE-2024-42483 replay vector   mac=b0:c1:02:2a:00:00 type=0 seq=16 replay=True payload_n=8
[3] REPLAY ENGINE SIMULATOR
  state=patched   seq=16  -> accepted=True (monotonic seq accepted)
  state=unpatched seq=16  -> accepted=True (no anti-replay state; replay accepted)
[4] INDEPENDENT-OBSERVER FIDELITY METRIC
  coverage=0.75 precision=1.00 f1=0.86 timing_correlation=1.000
  fidelity_score=85.71
[+] Demo complete — exit 0
```

## Live Lab Test Plan

| Phase | Description | Go / No-Go Criteria | Status |
|-------|-------------|---------------------|--------|
| Phase 0 | Offline pipeline validation (this tool) | Demo exits 0, all tests pass, fidelity > 80 | DONE |
| Phase 1 | ESP32 peer setup + frame capture | Two ESP32 peers exchange action frames; nRF24 observer logs match victim | PENDING |
| Phase 2 | Replay attack reproduction (own lab only) | Replay accepted on unpatched target, rejected on patched target | PENDING |
| Phase 3 | Full SoK matrix completion | All 5 attack categories exercised with empirical data | PENDING |

## Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Taxonomy coverage | 5/5 attack categories | 5/5 |
| Frame parser accuracy | Decode all embedded frames | 3/3 |
| Replay simulator correctness | Patched rejects stale seq | Verified |
| Fidelity score (offline) | > 80 | 85.71 |
| Test pass rate | 100% | 100% |
| Demo exit code | 0 | 0 |

## Bibliography

See `papers/bibliography.md` for the full structured bibliography (14 entries covering ESP-NOW protocol, CVE-2024-42483, 2.4 GHz coexistence, side-channel analysis, and legal/regulatory references).

## Threat Model

See `papers/threat_model.md` for the threat model table mapping attacks to layers, preconditions, and mitigation status.

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security research purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the device/network owner before capturing or analyzing ESP-NOW or any 2.4 GHz traffic
- Intercepting wireless communications on devices you do not own is illegal
- This tool should ONLY be used on devices you own or have written authorization to test
- Any on-air experimentation requires compliance with local RF regulations

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **FCC Regulations**: Operating 2.4 GHz radio hardware must comply with Part 15 regulations

### Acceptable Use
- Analyzing captured ESP-NOW / frame data on your own devices in a controlled lab
- Authorized penetration testing with written scope
- Academic security research with IRB/ethics approval where applicable
- Security education and training demonstrations

### Prohibited Use
- Intercepting or replaying ESP-NOW traffic on devices you don't own
- Injecting, spoofing, or flooding frames without authorization
- Reproducing CVE-2024-42483 against production systems you do not control
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the affected device vendor / Espressif privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
