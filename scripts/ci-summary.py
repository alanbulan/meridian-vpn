"""Summarize Go's JSON stream without treating absent or incomplete checks as passes."""
import json
import os
import pathlib
import sys


def summarize(source):
    counts = {"pass": 0, "fail": 0, "skip": 0}
    packages = {}
    skipped = []
    errors = []
    events = 0
    if not source.is_file():
        errors.append("No test log was produced; tests are not verified.")
    else:
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("event is not an object")
            except (ValueError, TypeError):
                errors.append(f"Malformed JSON event at line {number}; test results are incomplete.")
                continue
            events += 1
            action, test, package = event.get("Action"), event.get("Test"), event.get("Package")
            if package:
                packages.setdefault(package, None)
                if not test and action in counts:
                    packages[package] = action
            if test and action in counts:
                counts[action] += 1
                if action == "skip":
                    skipped.append(f"- {package}: {test}")
        if not events:
            errors.append("The test log is empty; tests are not verified.")
        if not packages:
            errors.append("No package outcomes were recorded; tests are not verified.")
        for package, outcome in sorted(packages.items()):
            if outcome is None:
                errors.append(f"Incomplete package: {package} has no terminal outcome.")
            elif outcome == "fail":
                errors.append(f"Failed package: {package} (includes build/setup failures).")
    verified = not errors and not counts["fail"]
    summary = (
        "## Meridian test scope\n\n"
        f"Test-log status: {'completed without reported failures' if verified else 'FAILED OR NOT VERIFIED'}.\n\n"
        f"Individual test/subtest events: {counts['pass']} passed, "
        f"{counts['fail']} failed, {counts['skip']} skipped.\n\n"
        f"Package outcomes: {sum(v == 'pass' for v in packages.values())} passed, "
        f"{sum(v == 'fail' for v in packages.values())} failed, "
        f"{sum(v == 'skip' for v in packages.values())} skipped.\n\n"
        "Build and unit-test results do not establish native GUI interaction, "
        "live VPN connectivity, intranet access, or route/DNS restoration. "
        "Platform VPN support must be checked separately. "
        "Artifacts are unsigned development binaries, not installers.\n\n"
    )
    if errors:
        summary += "### Incomplete or failed checks\n\n" + "\n".join(f"- {e}" for e in errors) + "\n"
    if skipped:
        summary += "### Skipped tests (not passes)\n\n" + "\n".join(skipped) + "\n"
    return summary, verified


def main():
    source = pathlib.Path(sys.argv[1])
    summary, verified = summarize(source)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.with_name("test-summary.md").write_text(summary, encoding="utf-8")
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
    return 0 if verified else 1


if __name__ == "__main__":
    sys.exit(main())
