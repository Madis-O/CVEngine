#Report.py  Reporting for the CLI
# Everything that gets printed is here
import sys
from display import message_for, paint
from scoring import vuln_score


def status(text):
    if sys.stderr.isatty():
        sys.stderr.write(f"\r{text}\033[K")
        sys.stderr.flush()


def clear_status():
    if sys.stderr.isatty():
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()


def finding():
    status("CVEngine ][ firing up ... finding packages")


def checking(done, total):
    status(f"CVEngine ][ burning through ... {done}/{total}")


def clean():
    print("All clean, nothing to worry about ^^")


def unchecked(failures, after_report=False, show=10):
    noun = "package" if len(failures) == 1 else "packages"
    if after_report:
        print()
    print(f"Couldn't check {len(failures)} {noun}:")
    for error in failures[:show]:
        print(f"  {error.name} {error.version} - {error.reason}")
    if len(failures) > show:
        print(f"  ... and {len(failures) - show} more")


def discover_failed(error):
    print(f"Couldn't list {error.source} packages: {error.reason}")


def unreachable(error):
    print(f"Couldn't reach the database: {error.reason}")


def all_failed(failures):
    reasons = {error.reason for error in failures}
    if len(reasons) == 1:
        print(f"Every lookup failed: {reasons.pop()}")
    else:
        print("Every lookup failed, try again later")


def interrupted():
    print("Stopped, scan cancelled")


def coming_soon():
    print("not here yet sooorrryyyyyyyyyyyyyyy")


def no_packages():
    print("Couldn't find any packages to scan")


def scan_report(scanned, results):
    print(f"Scanned {scanned} packages, {len(results)} with problems")
    for score, name, version, fix in results:
        dot = " \033[32m•\033[0m" if fix else ""
        print()
        if score is None:
            print(f"CVSS n/a{dot}")
        else:
            print(paint(message_for(score), score))
            print()
            print(f"{paint(f'CVSS {score}', score)}{dot}")
        print(f"{name} {version} → {fix}" if fix else f"{name} {version}")


def package_report(name, version, vulns):
    scored = [(vuln, vuln_score(vuln)) for vuln in vulns]
    known = [score for _, score in scored if score is not None]
    top = max(known) if known else None
    if top is not None:
        print(paint(message_for(top), top))
        print(paint(f"CVSS {top}", top))
    print(f"Found {len(vulns)} problems in {name} {version}")
    for vuln, score in scored:
        label = paint(f"{score:>4}", score) if score is not None else " n/a"
        print(f"{label} - {vuln['id']} - {vuln.get('summary', 'no summary')}")


# got a headache rn fuck me, or blood pressure from the redbull. idk could be both/
