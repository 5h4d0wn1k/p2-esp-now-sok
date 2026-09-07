#!/usr/bin/env python3
"""P2 — ESP-NOW Security SoK: unit tests."""
import csv
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "firmware"))

from esp_now_sok import (
    TAXONOMY,
    FidelityMetric,
    FrameParser,
    NRF24_OBSERVER_LOG_CSV,
    ReplaySimulator,
    SokResultsExporter,
    TaxonomyEngine,
    VICTIM_LOG_CSV,
    _pearson,
    parse_action_frame,
)


class TestTaxonomyEngine(unittest.TestCase):
    def test_rows_loaded(self):
        eng = TaxonomyEngine()
        self.assertEqual(len(eng.rows), 5)

    def test_text_report_nonempty(self):
        out = TaxonomyEngine().text_report()
        self.assertIn("Attack Taxonomy Matrix", out)
        self.assertIn("Eavesdropping", out)

    def test_markdown_report_has_table_header(self):
        md = TaxonomyEngine().markdown_report()
        self.assertIn("| # | Attack |", md)
        self.assertIn("CVE-2024-42483", md)

    def test_custom_rows(self):
        custom = [{"attack": "X", "preconditions": ["a"], "impact": "b", "mitigation_status": "c"}]
        eng = TaxonomyEngine(rows=custom)
        self.assertEqual(len(eng.rows), 1)
        self.assertIn("X", eng.text_report())


class TestFrameParser(unittest.TestCase):
    def test_parse_all_returns_3(self):
        frames = FrameParser().parse_all()
        self.assertEqual(len(frames), 3)

    def test_parse_cve_frame(self):
        raw = bytes.fromhex("04 00 00 24 0f 5a b0 c1 02 2a 00 00 00 01 00 10 11 22 33 44 55 66 77 88")
        result = parse_action_frame(raw)
        self.assertEqual(result["peer_mac"], "b0:c1:02:2a:00:00")
        self.assertEqual(result["sequence"], 16)
        self.assertTrue(result["replay_relevant"])
        self.assertEqual(result["payload_len"], 8)

    def test_parse_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_action_frame(b"\x04\x00")

    def test_parse_frame_type(self):
        frames = FrameParser().parse_all()
        self.assertEqual(frames[0]["frame_type"], 0)
        self.assertEqual(frames[1]["frame_type"], 2)
        self.assertEqual(frames[2]["frame_type"], 3)


class TestReplaySimulator(unittest.TestCase):
    def test_unpatched_always_accepts(self):
        sim = ReplaySimulator()
        frame = {"peer_mac": "aa:bb:cc:dd:ee:ff", "frame_type": 0, "sequence": 100}
        r = sim.simulate(frame, "unpatched")
        self.assertTrue(r["accepted"])

    def test_patched_monotonic_accepted(self):
        sim = ReplaySimulator()
        frame = {"peer_mac": "aa:bb:cc:dd:ee:ff", "frame_type": 0, "sequence": 10}
        r = sim.simulate(frame, "patched")
        self.assertTrue(r["accepted"])

    def test_patched_rejects_stale_seq(self):
        sim = ReplaySimulator()
        f1 = {"peer_mac": "aa:bb:cc:dd:ee:ff", "frame_type": 0, "sequence": 20}
        sim.simulate(f1, "patched")
        f2 = {"peer_mac": "aa:bb:cc:dd:ee:ff", "frame_type": 0, "sequence": 15}
        r = sim.simulate(f2, "patched")
        self.assertFalse(r["accepted"])


class TestFidelityMetric(unittest.TestCase):
    def test_compute_returns_keys(self):
        fm = FidelityMetric()
        result = fm.compute()
        for k in ("coverage", "precision", "f1", "timing_correlation", "fidelity_score"):
            self.assertIn(k, result)

    def test_coverage_range(self):
        fm = FidelityMetric()
        r = fm.compute()
        self.assertGreaterEqual(r["coverage"], 0.0)
        self.assertLessEqual(r["coverage"], 1.0)

    def test_precision_range(self):
        fm = FidelityMetric()
        r = fm.compute()
        self.assertGreaterEqual(r["precision"], 0.0)
        self.assertLessEqual(r["precision"], 1.0)

    def test_known_values(self):
        fm = FidelityMetric()
        r = fm.compute()
        self.assertAlmostEqual(r["coverage"], 0.75, places=2)
        self.assertAlmostEqual(r["precision"], 1.0, places=2)

    def test_custom_csv(self):
        victim = "seq,peer_mac,payload_len,ts\n1,aa:bb:cc:dd:ee:ff,10,0.0\n"
        observer = "seq,peer_mac,payload_len,ts\n1,aa:bb:cc:dd:ee:ff,10,0.01\n"
        fm = FidelityMetric(victim_csv=victim, observer_csv=observer, tolerance=0.05)
        r = fm.compute()
        self.assertEqual(r["matched_frames"], 1)
        self.assertAlmostEqual(r["coverage"], 1.0)


class TestPearson(unittest.TestCase):
    def test_perfect_correlation(self):
        self.assertAlmostEqual(_pearson([1, 2, 3], [2, 4, 6]), 1.0)

    def test_negative_correlation(self):
        self.assertAlmostEqual(_pearson([1, 2, 3], [3, 2, 1]), -1.0)

    def test_empty(self):
        self.assertIsNone(_pearson([], []))


class TestSokExporter(unittest.TestCase):
    def test_to_markdown(self):
        md = SokResultsExporter().to_markdown()
        self.assertIn("ESP-NOW", md)

    def test_to_latex(self):
        latex = SokResultsExporter().to_latex()
        self.assertIn("\\begin{table}", latex)
        self.assertIn("\\begin{tabular}", latex)

    def test_text_table(self):
        tt = SokResultsExporter().text_table()
        self.assertIn("1", tt)


class TestDemo(unittest.TestCase):
    def test_demo_runs(self):
        from esp_now_sok import demo
        ret = demo()
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
