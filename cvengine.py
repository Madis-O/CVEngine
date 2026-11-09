import argparse
import os
import sys
import report
from discover import DISCOVERERS
from menu import choose_scan
from osv import query_package
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
            packages = DISCOVERERS[source]()
            if not packages:
                report.no_packages()
                raise SystemExit
            results = []
            for name, version, ecosystem in packages:
                vulns = query_package(name, version, ecosystem)
                if vulns:
                    results.append((top_score(vulns), name, version, fix_version(vulns, version, name, ecosystem)))
            results.sort(key=lambda row: row[0] if row[0] is not None else -1, reverse=True)
            if not results:
                report.clean()
                raise SystemExit
            report.scan_report(len(packages), results)
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
