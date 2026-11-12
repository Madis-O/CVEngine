#CVEngine.py  The central engine for the CLI, handles the flow of the program and calls other modules
# Basically the Central Engine. Menu -> find packages -> ask OSV -> print the verdicts. Will change up soon to be beyond packages.
import argparse
import os
import sys
import report
from discover import DISCOVERERS, DiscoverError
from menu import choose_folder, choose_scan
from osv import OSVError, check_reachable, query_many, query_package
from project import read_project
from scoring import top_score
from versions import fix_version

os.system("")
sys.stdout.reconfigure(encoding="utf-8")


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", nargs="?")
    parser.add_argument("version", nargs="?")
    args = parser.parse_args()

    if args.package is None:
        source = choose_scan()
        folder = choose_folder() if source == "folder" else None #new project folder scanning option here
        if source in DISCOVERERS or folder:
            report.finding()
            skipped = []
            try:
                if folder:
                    packages, skipped = read_project(folder)
                else:
                    packages = DISCOVERERS[source]()
            except DiscoverError as error:
                report.clear_status()
                report.discover_failed(error)
                raise SystemExit(1)
            if not packages:
                report.clear_status()
                if skipped:
                    report.unchecked(skipped)
                else:
                    report.no_packages()
                raise SystemExit
            try:
                check_reachable()
            except OSVError as error:
                report.clear_status()
                report.unreachable(error)
                raise SystemExit(1)
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
            if len(failures) == len(packages):
                report.all_failed(failures)
                raise SystemExit(1)
            if results:
                report.scan_report(len(packages) - len(failures), results)
            elif not failures and not skipped:
                report.clean()
            if failures or skipped:
                report.unchecked(failures + skipped, after_report=bool(results))
        raise SystemExit

    if args.version is None:
        parser.error("version is required with a package")

    try:
        vulns = query_package(args.package, args.version, "PyPI")
    except OSVError as error:
        report.unchecked([error])
        raise SystemExit(1)

    if not vulns:
        report.clean()
    else:
        report.package_report(args.package, args.version, vulns)


def main():
    try:
        run()
    except KeyboardInterrupt:
        report.clear_status()
        report.interrupted()
        raise SystemExit(130)


if __name__ == "__main__":
    main()
