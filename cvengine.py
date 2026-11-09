import argparse
import os
import sys
import report
from discover import DISCOVERERS
from menu import choose_scan
from osv import query_many, query_package
from scoring import top_score
from versions import fix_version

os.system("")
sys.stdout.reconfigure(encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?")
    parser.add_argument("version", nargs="?")
    args = parser.parse_args()

    if args.package is None:
        source = choose_scan()
        if source in DISCOVERERS:
            report.finding()
            packages = DISCOVERERS[source]()
            if not packages:
                report.clear_status()
                report.no_packages()
                raise SystemExit
            try:
                answers = query_many(packages, report.checking)
            finally:
                report.clear_status()
            results = []
            failures = []
            for (name, version, ecosystem), (vulns, error) in zip(packages, answers):
                if error:
                    failures.append(error)
                elif vulns:
                    results.append((top_score(vulns), name, version, fix_version(vulns, version, name, ecosystem)))
            results.sort(key=lambda row: row[0] if row[0] is not None else -1, reverse=True)
            if results:
                report.scan_report(len(packages) - len(failures), results)
            elif not failures:
                report.clean()
            if failures:
                report.unchecked(failures, after_report=bool(results))
        raise SystemExit

    if args.version is None:
        parser.error("version is required with a package")

    vulns = query_package(args.package, args.version, "PyPI")

    if not vulns:
        report.clean()
    else:
        report.package_report(args.package, args.version, vulns)


if __name__ == "__main__":
    main()
