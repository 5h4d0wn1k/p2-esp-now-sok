#!/usr/bin/env python3
"""P2 — ESP-NOW Security SoK. Taxonomy engine, frame parser, replay simulator, observer-fidelity metric, SoK matrix exporter."""

import csv
import io
import sys


# ---------------------------------------------------------------------------
# Attack taxonomy matrix: attack x preconditions x impact x mitigation status
# ---------------------------------------------------------------------------
TAXONOMY = [
    {
        "attack": "Eavesdropping / Passive Capture",
        "preconditions": [
            "Radio tuned to traffic 2.4 GHz channel",
            "Peer MAC addresses within range",
            "Data transmitted in clear (ESP-NOW has no built-in confidentiality)",
        ],
        "impact": "Confidentiality breach of telemetry/payload; frame contents, seq, and MAC exposed",
        "mitigation_status": "Not mitigated (data-link layer unencrypted)",
    },
    {
        "attack": "CVE-2024-42483 Replay / Cache-Poisoning Reproduction",
        "preconditions": [
            "Vulnerable ESP-NOW stack (cache not cleared)",
            "Attacker can capture and retransmit captured action frame",
            "Same source MAC spoofed on replay",
        ],
        "impact": "Replay of stale cached frames/state, cache poisoning leading to stale trust decisions",
        "mitigation_status": "Mitigated in patched stacks; reproducibly vulnerable in unpatched",
    },
    {
        "attack": "MAC Spoofing / Frame Injection",
        "preconditions": [
            "Attacker controls source address (ESP32 does not cryptographically bind sender identity)",
            "Target accepts frames based on MAC only",
        ],
        "impact": "Impersonation, injection of forged commands/state into legitimate peer",
        "mitigation_status": "Not mitigated (identity not bound to cryptographic key at frame layer)",
    },
    {
        "attack": "Denial of Service / Flood",
        "preconditions": [
            "Ability to occupy channel / exhaust peer receive buffers",
            "No authenticated rate limiting at ESP-NOW layer",
        ],
        "impact": "Availability loss; peer reboots, buffer exhaustion, missed legitimate frames",
        "mitigation_status": "Not mitigated (layer has no built-in DoS protection)",
    },
    {
        "attack": "Cross-Technology Confusion (2.4 GHz coexistence)",
        "preconditions": [
            "Shared 2.4 GHz band with Wi-Fi/BLE/nRF24 devices",
            "Identical/overlapping addressing or packet axis",
        ],
        "impact": "Misattribution of frames, decode errors, jamming between technologies",
        "mitigation_status": "Partially mitigated (channel selection, coexistence config)",
    },
]


class TaxonomyEngine:
    """Embedded attack x preconditions x impact x mitigation status matrix."""

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else list(TAXONOMY)

    def text_report(self):
        out = []
        out.append("Attack Taxonomy Matrix (P2 — ESP-NOW SoK)")
        out.append("=" * 78)
        for i, r in enumerate(self.rows, 1):
            out.append(f"[{i}] {r['attack']}")
            out.append(f"    Preconditions : {'; '.join(r['preconditions'])}")
            out.append(f"    Impact        : {r['impact']}")
            out.append(f"    Mitigation    : {r['mitigation_status']}")
            out.append("")
        return "\n".join(out)

    def markdown_report(self):
        out = ["# ESP-NOW Attack x Mitigation SoK Matrix", ""]
        out.append("| # | Attack | Preconditions | Impact | Mitigation Status |")
        out.append("|---|--------|---------------|--------|-------------------|")
        for i, r in enumerate(self.rows, 1):
            pre = "<br>".join(r["preconditions"])
            out.append(f"| {i} | {r['attack']} | {pre} | {r['impact']} | {r['mitigation_status']} |")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# ESP-NOW action-frame parser
# ---------------------------------------------------------------------------
# Sample ESP-NOW action frame layout (as captured on-air):
#   [0:3]   category + OUI (action frame header, e.g. 04 00 00)
#   [3:12]  peer MAC address (6 bytes + reserve 3)
#   [12:14] frame type / arity byte
#   [14:16] sequence / replay-relevant counter
#   [16:]   payload
SAMPLE_FRAMES = [
    {
        "raw": bytes.fromhex("04 00 00 24 0f 5a b0 c1 02 2a 00 00 00 01 00 10 11 22 33 44 55 66 77 88"),
        "label": "copy of CVE-2024-42483 replay vector",
    },
    {
        "raw": bytes.fromhex("04 00 00 24 0f 5a b0 c1 02 2a 00 00 02 5b 90 77 88 99 aa bb cc dd ee ff"),
        "label": "late legitimate action frame",
    },
    {
        "raw": bytes.fromhex("04 00 00 30 ae a4 93 00 12 34 00 00 03 01 ad 55 11 fe 22 dc"),
        "label": "MAC-spoofed injection frame",
    },
]


def parse_action_frame(raw):
    """Decode an ESP-NOW action-frame byte payload into its fields."""
    if len(raw) < 14:
        raise ValueError("frame too short to be a valid ESP-NOW action frame")
    oui = raw[3:6]
    peer_mac = raw[6:12]
    frame_type = raw[12]
    seq = int.from_bytes(raw[14:16], "big")
    payload = raw[16:]
    return {
        "category": raw[0],
        "oui": oui.hex(),
        "peer_mac": ":".join(f"{b:02x}" for b in peer_mac),
        "frame_type": frame_type,
        "sequence": seq,
        "replay_relevant": True,  # seq present -> replay-relevant counter
        "payload_len": len(payload),
        "payload_hex": payload.hex(),
        "raw_len": len(raw),
    }


class FrameParser:
    """Parse embedded + supplied ESP-NOW action-frame byte payloads."""

    def parse(self, raw, label="unnamed"):
        return {"label": label, "raw_len": len(raw), **parse_action_frame(raw)}

    def parse_all(self, frames=None):
        frames = frames if frames is not None else SAMPLE_FRAMES
        return [self.parse(f["raw"], f.get("label", "unnamed")) for f in frames]


# ---------------------------------------------------------------------------
# Replay engine simulator
# ---------------------------------------------------------------------------
class ReplaySimulator:
    """Given a captured frame + target state, simulate whether a replay is accepted."""

    def __init__(self):
        self._seen = {}

    def simulate(self, frame, target_state):
        """target_state: 'patched' (stateful anti-replay) or 'unpatched' (none)."""
        key = (frame["peer_mac"], frame["frame_type"])
        old_seq = self._seen.get(key, -1)
        frame_seq = frame["sequence"]

        if target_state == "patched":
            # Stateful anti-replay: reject if seq <= last accepted for (mac,type)
            if frame_seq <= old_seq:
                return {"accepted": False, "reason": "anti-replay rejects stale/non-monotonic seq"}
            self._seen[key] = frame_seq
            return {"accepted": True, "reason": "monotonic seq accepted"}
        # unpatched: no state, any same-seq frame accepted
        return {"accepted": True, "reason": "no anti-replay state; replay accepted"}


# ---------------------------------------------------------------------------
# Independent-observer fidelity metric
# ---------------------------------------------------------------------------
VICTIM_LOG_CSV = """seq,peer_mac,payload_len,ts
1,24:0f:5a:b0:c1:02,8,0.000
2,24:0f:5a:b0:c1:02,8,0.100
3,24:0f:5a:b0:c1:02,8,0.200
4,24:0f:5a:b0:c1:02,8,0.300
5,30:ae:a4:93:00:12,9,0.400
6,24:0f:5a:b0:c1:02,8,0.500
7,24:0f:5a:b0:c1:02,8,0.601
8,30:ae:a4:93:00:12,9,0.700
"""

NRF24_OBSERVER_LOG_CSV = """seq,peer_mac,payload_len,ts
1,24:0f:5a:b0:c1:02,8,0.003
2,24:0f:5a:b0:c1:02,8,0.101
3,24:0f:5a:b0:c1:02,8,0.198
4,30:ae:a4:93:00:12,9,0.402
5,24:0f:5a:b0:c1:02,8,0.499
6,24:0f:5a:b0:c1:02,8,0.603
"""


class FidelityMetric:
    """Compare a 'victim log' with an 'nRF24 observer log' for fidelity scoring."""

    def __init__(self, victim_csv=None, observer_csv=None, tolerance=0.05):
        self.victim_csv = victim_csv if victim_csv is not None else VICTIM_LOG_CSV
        self.observer_csv = observer_csv if observer_csv is not None else NRF24_OBSERVER_LOG_CSV
        self.tolerance = tolerance

    @staticmethod
    def _load(csv_text):
        rdr = csv.DictReader(io.StringIO(csv_text))
        rows = []
        for row in rdr:
            rows.append(
                {
                    "seq": int(row["seq"]),
                    "peer_mac": row["peer_mac"],
                    "payload_len": int(row["payload_len"]),
                    "ts": float(row["ts"]),
                }
            )
        return rows

    def compute(self):
        victim = self._load(self.victim_csv)
        observer = self._load(self.observer_csv)

        # Frame-key match: same peer + payload_len within timing tolerance
        matched = 0
        v_index = 0
        matched_rows = []
        observer_used = [False] * len(observer)
        for v in victim:
            best_i = None
            for oi, o in enumerate(observer):
                if observer_used[oi]:
                    continue
                if o["peer_mac"] == v["peer_mac"] and o["payload_len"] == v["payload_len"]:
                    if abs(o["ts"] - v["ts"]) <= self.tolerance:
                        if best_i is None or abs(o["ts"] - v["ts"]) < abs(observer[best_i]["ts"] - v["ts"]):
                            best_i = oi
            if best_i is not None:
                observer_used[best_i] = True
                matched += 1
                matched_rows.append((v, observer[best_i]))

        n_victim = len(victim)
        n_observer = len(observer)
        coverage = matched / n_victim if n_victim else 0.0  # fraction of victim frames seen
        precision = matched / n_observer if n_observer else 0.0  # fraction of observer frames that matched

        # Timing correlation: Pearson r on matched timestamps
        if matched >= 2:
            vts = [v["ts"] for v, _ in matched_rows]
            ots = [o["ts"] for _, o in matched_rows]
            correlation = _pearson(vts, ots)
        else:
            correlation = 0.0
        if correlation is None:
            correlation = 0.0

        f1 = 0.0
        if coverage + precision > 0:
            f1 = 2 * coverage * precision / (coverage + precision)

        fidelity = 100 * f1 * correlation if correlation > 0 else 0.0
        return {
            "victim_frames": n_victim,
            "observer_frames": n_observer,
            "matched_frames": matched,
            "coverage": coverage,
            "precision": precision,
            "f1": f1,
            "timing_correlation": correlation,
            "fidelity_score": round(fidelity, 2) if fidelity else round(100 * coverage, 2),
            "tolerance": self.tolerance,
        }


def _pearson(a, b):
    n = len(a)
    if n == 0:
        return None
    ma = sum(a) / n
    mb = sum(b) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    dena = sum((x - ma) ** 2 for x in a)
    denb = sum((y - mb) ** 2 for y in b)
    denom = (dena * denb) ** 0.5
    if denom == 0:
        return None
    return num / denom


class SokResultsExporter:
    """Export the full attack x mitigation matrix ready for a paper table."""

    def __init__(self, engine=None):
        self.engine = engine if engine is not None else TaxonomyEngine()

    def to_markdown(self):
        return self.engine.markdown_report()

    def to_latex(self):
        rows = []
        rows.append(r"\begin{table}[h]")
        rows.append(r"\centering")
        rows.append(r"\caption{ESP-NOW Attack x Mitigation SoK Matrix (P2)}")
        rows.append(r"\label{tab:espnow-sok}")
        rows.append(
            r"\begin{tabular}{@{}p{3.2cm}p{4.0cm}p{3.6cm}p{3.0cm}@{}}"
        )
        rows.append(r"\toprule")
        rows.append(r"Attack & Preconditions & Impact & Mitigation Status \\")
        rows.append(r"\midrule")
        for r in self.engine.rows:
            pre = r" / ".join(r["preconditions"])
            esc = lambda s: s.replace("&", r"\&").replace("%", r"\%").replace("_", r"\_")
            rows.append(
                rf"{esc(r['attack'])} & {esc(pre)} & {esc(r['impact'])} & {esc(r['mitigation_status'])} \\"
            )
        rows.append(r"\bottomrule")
        rows.append(r"\end{tabular}")
        rows.append(r"\end{table}")
        return "\n".join(rows)

    def text_table(self):
        return "\n".join(
            f"| {i} | {r['attack']} | {r['mitigation_status']} |"
            for i, r in enumerate(self.engine.rows, 1)
        )


def demo():
    print("=" * 78)
    print("  P2 — ESP-NOW Security SoK: taxonomy + independent observation tooling")
    print("=" * 78)

    eng = TaxonomyEngine()
    print("\n[1] ATTACK TAXONOMY MATRIX (text)")
    print(eng.text_report())

    parser = FrameParser()
    frames = parser.parse_all()
    print("[2] ESP-NOW ACTION-FRAME PARSER")
    for f in frames:
        print(
            f"  {f['label']:<38} mac={f['peer_mac']} type={f['frame_type']} "
            f"seq={f['sequence']} replay={f['replay_relevant']} payload_n={f['payload_len']}"
        )

    print("\n[3] REPLAY ENGINE SIMULATOR")
    sim = ReplaySimulator()
    for frame in frames:
        for state in ("patched", "unpatched"):
            res = sim.simulate(frame, state)
            print(
                f"  state={state:<9} seq={frame['sequence']:<3} "
                f"-> accepted={res['accepted']} ({res['reason']})"
            )

    print("\n[4] INDEPENDENT-OBSERVER FIDELITY METRIC")
    fm = FidelityMetric()
    score = fm.compute()
    print(
        f"  victim={score['victim_frames']} observer={score['observer_frames']} "
        f"matched={score['matched_frames']}"
    )
    print(f"  coverage={score['coverage']:.2f} precision={score['precision']:.2f} f1={score['f1']:.2f}")
    print(f"  timing_correlation={score['timing_correlation']:.3f}")
    print(f"  fidelity_score={score['fidelity_score']}")

    print("\n[5] SoK RESULTS MATRIX (markdown)")
    print(SokResultsExporter().to_markdown())

    print("\n[+] Demo complete — exit 0")
    return 0


def main(argv=None):
    return demo()


if __name__ == "__main__":
    sys.exit(main())
