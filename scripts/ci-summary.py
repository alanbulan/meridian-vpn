"""Report Go test outcomes without equating skipped tests with passes."""
import json
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
counts = {"pass": 0, "fail": 0, "skip": 0}
skipped = []
if source.exists():
    for line in source.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        action, test = event.get("Action"), event.get("Test")
        if test and action in counts:
            counts[action] += 1
            if action == "skip":
                skipped.append(f"- {event.get('Package')}: {test}")
summary = (
    "## Meridian test scope\n\n"
    f"Individual test/subtest events: {counts['pass']} passed, "
    f"{counts['fail']} failed, {counts['skip']} skipped.\n\n"
    "Build and unit-test results do not establish native GUI interaction, "
    "live VPN connectivity, intranet access, or route/DNS restoration. "
    "Windows/macOS VPN backends are not implemented. "
    "Artifacts are unsigned development binaries, not installers.\n\n"
)
if not source.exists():
    summary += "No test log was produced; tests are not verified.\n"
if skipped:
    summary += "### Skipped tests (not passes)\n\n" + "\n".join(skipped) + "\n"
print(summary)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write(summary)
