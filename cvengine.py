import argparse
import os
import platform
import questionary
import sys
from discover import DISCOVERERS
from display import message_for, paint
from osv import query_package
from scoring import top_score, vuln_score
from versions import fix_version

os.system("")
sys.stdout.reconfigure(encoding="utf-8")


def choose_scan():
    kind = questionary.select(
        "What are we scanning today?",
        choices=["Packages"],
    ).ask()
    if kind == "Packages":
        return questionary.select(
            "Which packages?",
            choices=["pip", "npm"] + (["apt"] if platform.system() == "Linux" else []),
        ).ask()
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?")
    parser.add_argument("version", nargs="?")
    args = parser.parse_args()

    if args.package is None:
        source = choose_scan()
        if source in DISCOVERERS:
            packages = DISCOVERERS[source]()
            if not packages:
                print("Couldn't find any packages to scan")
                raise SystemExit
            results = []
            for name, version, ecosystem in packages:
                vulns = query_package(name, version, ecosystem)
                if vulns:
                    results.append((top_score(vulns), name, version, fix_version(vulns, version, name, ecosystem)))
            results.sort(key=lambda row: row[0] if row[0] is not None else -1, reverse=True)
            if not results:
                print("All clean, nothing to worry about ^^")
                raise SystemExit
            print(f"Scanned {len(packages)} packages, {len(results)} with problems")
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
        raise SystemExit

    if args.version is None:
        parser.error("version is required with a package")

    vulns = query_package(args.package, args.version, "PyPI")

    if not vulns:
        print("All clean, nothing to worry about ^^")
    else:
        scored = [(vuln, vuln_score(vuln)) for vuln in vulns]
        known = [score for _, score in scored if score is not None]
        top = max(known) if known else None
        if top is not None:
            print(paint(message_for(top), top))
            print(paint(f"CVSS {top}", top))
        print(f"Found {len(vulns)} problems in {args.package} {args.version}")
        for vuln, score in scored:
            label = paint(f"{score:>4}", score) if score is not None else " n/a"
            print(f"{label} - {vuln['id']} - {vuln.get('summary', 'no summary')}")


if __name__ == "__main__":
    main()
