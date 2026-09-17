#!/usr/bin/env python3
"""Turn an Autobahn report into an exit code.

The suite writes an HTML report a human reads and a JSON index a machine can.
This reads the JSON and fails the job on anything that is not a pass, because a
report nobody opens is not a check.
"""

import json
import sys
from pathlib import Path

# OK is a pass. NON-STRICT is a pass where the RFC allows more than one answer
# and this one took a different permitted branch. INFORMATIONAL and UNIMPLEMENTED
# carry no verdict.
PASSING = {"OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"}


def main() -> int:
    index = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("autobahn/reports/servers/index.json")
    if not index.exists():
        print(f"no report at {index}: the suite did not run")
        return 1

    report = json.loads(index.read_text())

    failures = []
    total = 0
    for agent, cases in report.items():
        for case, result in cases.items():
            total += 1
            behavior = result.get("behavior", "MISSING")
            close = result.get("behaviorClose", "MISSING")
            if behavior not in PASSING or close not in PASSING:
                failures.append((agent, case, behavior, close))

    if not total:
        print("the report is empty: the suite did not run any cases")
        return 1

    for agent, case, behavior, close in failures:
        print(f"FAIL {agent} {case}: behavior={behavior} close={close}")

    print(f"{total - len(failures)}/{total} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
