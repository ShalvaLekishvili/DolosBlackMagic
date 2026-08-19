from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import WazuhAnalysisEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Wazuh exports locally with DolosBlackMagic")
    parser.add_argument("input", nargs="?", help="JSON/NDJSON export path. Reads stdin when omitted.")
    parser.add_argument("-o", "--output", help="Write analysis JSON to a file instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args()

    if args.input:
        payload = Path(args.input).read_text(encoding="utf-8", errors="replace")
    else:
        payload = sys.stdin.read()
    result = WazuhAnalysisEngine().analyze(payload)
    text = json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
