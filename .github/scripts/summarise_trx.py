#!/usr/bin/env python3
"""Summarise a .trx test report and assert the suite actually ran.

Batch 3-2 (docs/PRODUCTION-PLAN.md).

Why this exists rather than reading the `dotnet test` console output:

  * `dotnet test` rewrites its progress line with \\r, so a redirected or
    captured log can end up as a mangled tail with no usable counts.
  * A crashed test host prints "Passed!" next to a non-zero exit code, and its
    total silently omits every test that never got to run. Once, that turned
    235 tests into 129 with no failure, no skip, and no trace.
  * A test that calls Assert.Ignore is recorded as NotExecuted, not as a
    failure. Before batch 3-1 every integration test did exactly that, so a
    suite covering nothing at all was indistinguishable from a green one.

So the numbers come from the .trx, and the exit status encodes one question
only: did enough tests actually execute? Whether they *passed* is deliberately
not gated here — the integration suite is expected to be red until Gate 3, and
the workflow marks the test step continue-on-error for that reason. This script
is what stops that leniency from also excusing a suite that ran nothing.

Usage: summarise_trx.py <directory-containing-trx> [...]

Environment:
  MIN_INTEGRATION_TESTS  minimum executed tests required to exit 0 (default 1)
  GITHUB_STEP_SUMMARY    if set, a markdown summary is appended to this file
"""

import glob
import os
import sys
import xml.etree.ElementTree as ET

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}

# Outcomes the TRX schema uses for "this test did not run". NUnit's
# Assert.Ignore and [Ignore] both land on NotExecuted.
SKIPPED_OUTCOMES = {"NotExecuted", "Inconclusive", "Pending"}


def emit(line=""):
    """Print to the log and, on GitHub Actions, into the job summary."""
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def collect(paths):
    """Return (results, trx_files). results is a list of (name, outcome, message)."""
    trx_files = []
    for path in paths:
        if os.path.isdir(path):
            trx_files.extend(sorted(glob.glob(os.path.join(path, "*.trx"))))
        else:
            trx_files.append(path)

    results = []
    for trx in trx_files:
        root = ET.parse(trx).getroot()
        for element in root.findall(".//t:UnitTestResult", NS):
            message = element.find(".//t:Message", NS)
            results.append((
                element.get("testName", "<unnamed>"),
                element.get("outcome", "Unknown"),
                (message.text or "").strip() if message is not None else "",
            ))
    return results, trx_files


def main(argv):
    paths = argv[1:] or ["TestResults"]
    minimum = int(os.environ.get("MIN_INTEGRATION_TESTS", "1"))

    try:
        results, trx_files = collect(paths)
    except ET.ParseError as ex:
        emit(f"::error::Could not parse a .trx report: {ex}")
        return 1

    if not trx_files:
        emit(f"::error::No .trx report found under {', '.join(paths)}. "
             "The test run produced no record of itself.")
        return 1

    passed = [r for r in results if r[1] == "Passed"]
    skipped = [r for r in results if r[1] in SKIPPED_OUTCOMES]
    # Anything not passed and not skipped is a failure, including Timeout and
    # Aborted. Enumerating failure outcomes would let a new one pass silently.
    failed = [r for r in results if r[1] != "Passed" and r[1] not in SKIPPED_OUTCOMES]
    executed = len(passed) + len(failed)

    emit("## Integration test results")
    emit()
    emit("| total | executed | passed | failed | skipped |")
    emit("|---|---|---|---|---|")
    emit(f"| {len(results)} | {executed} | {len(passed)} | {len(failed)} | {len(skipped)} |")
    emit()

    if failed:
        emit("<details><summary>Failed tests</summary>")
        emit()
        for name, outcome, message in sorted(failed):
            first_line = message.splitlines()[0] if message else ""
            emit(f"- `{name}` — {outcome}: {first_line}")
        emit()
        emit("</details>")
        emit()

    if executed < minimum:
        emit(f"::error::Only {executed} test(s) executed, expected at least {minimum}. "
             "The suite skipped itself or the test host died mid-run — either way it "
             "is not testing anything.")
        return 1

    emit(f"{executed} test(s) executed (minimum {minimum}). "
         "Failures are not gated at this stage — see docs/PRODUCTION-PLAN.md, Gate 3.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
