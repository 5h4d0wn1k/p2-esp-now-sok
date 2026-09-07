#!/usr/bin/env python3
"""P2 — CLI wrapper for ESP-NOW Security SoK demo."""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware"))

from esp_now_sok import main as sok_main  # noqa: E402


def _run_demo(args):
    return sok_main()


def main():
    parser = argparse.ArgumentParser(
        prog="esp_now_sok",
        description="P2 — ESP-NOW Security SoK: taxonomy, frame parser, replay simulator, fidelity metric, exporter.",
    )
    parser.add_argument("--taxonomy-only", action="store_true",
                        help="Only print the attack taxonomy matrix (not implemented in demo)")
    parser.add_argument("--no-color", action="store_true", help="Accepted for CLI compatibility")
    args = parser.parse_args()
    sys.exit(_run_demo(args))


if __name__ == "__main__":
    main()
