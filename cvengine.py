import argparse
import functools
import math
import json
import os
import platform
import questionary
import re
import shutil
import subprocess
import sys
from cvss import CVSS4
from osv import query_package
from packaging.version import InvalidVersion, Version

os.system("")
sys.stdout.reconfigure(encoding="utf-8")

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

ANCHORS = [
    (1, (140, 140, 140)),
    (2, (190, 200, 90)),
    (4, (240, 210, 40)),
    (6, (240, 130, 30)),
    (8, (150, 0, 0)),
    (10, (220, 0, 0)),
]

MESSAGES = [
    (2, "You are just fine bucko"),
    (4, "Psh I don't know about you but I'd have a eye out and update"),
    (6, "I'd update if I were you..."),
    (8, "Yikes you should really update"),
    (10.1, "UPDATE NOW !! NOW !! NOW !! NOW !!"),
]


def roundup(value):
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_score(vector):
    parts = dict(item.split(":") for item in vector.split("/")[1:])
    changed = parts["S"] == "C"
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[parts["PR"]]
    iss = 1 - (1 - CIA[parts["C"]]) * (1 - CIA[parts["I"]]) * (1 - CIA[parts["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * AV[parts["AV"]] * AC[parts["AC"]] * pr * UI[parts["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploit), 10))
    return roundup(min(impact + exploit, 10))


def vuln_score(vuln):
    for entry in vuln.get("severity", []):
        if entry["type"] in ("CVSS_V3", "CVSS_V3.1", "CVSS_V3.0"):
            return cvss3_score(entry["score"])
    for entry in vuln.get("severity", []):
        if entry["type"] == "CVSS_V4":
            return float(CVSS4(entry["score"]).base_score)
    return None


def top_score(vulns):
    known = [score for score in map(vuln_score, vulns) if score is not None]
    return max(known) if known else None


def same_name(a, b, ecosystem):
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", a).lower() == re.sub(r"[-_.]+", "-", b).lower()
    return a == b


def deb_order(char):
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def deb_compare_part(a, b):
    digits = "0123456789"
    while a or b:
        i = 0
        while i < len(a) and a[i] not in digits:
            i += 1
        j = 0
        while j < len(b) and b[j] not in digits:
            j += 1
        for k in range(max(i, j)):
            ca = deb_order(a[k]) if k < i else 0
            cb = deb_order(b[k]) if k < j else 0
            if ca != cb:
                return -1 if ca < cb else 1
        a, b = a[i:], b[j:]
        i = 0
        while i < len(a) and a[i] in digits:
            i += 1
        j = 0
        while j < len(b) and b[j] in digits:
            j += 1
        na = int(a[:i] or 0)
        nb = int(b[:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
        a, b = a[i:], b[j:]
    return 0


@functools.total_ordering
class DebVersion:
    def __init__(self, text):
        self.text = text.strip()
        if not self.text:
            raise InvalidVersion("empty version")
        epoch, rest = self.text.split(":", 1) if ":" in self.text else ("0", self.text)
        if not epoch.isdigit():
            raise InvalidVersion(self.text)
        self.epoch = int(epoch)
        self.upstream, self.revision = rest.rsplit("-", 1) if "-" in rest else (rest, "")

    def compare(self, other):
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        result = deb_compare_part(self.upstream, other.upstream)
        if result:
            return result
        return deb_compare_part(self.revision, other.revision)

    def __eq__(self, other):
        return self.compare(other) == 0

    def __lt__(self, other):
        return self.compare(other) < 0

    def __str__(self):
        return self.text


def version_class(ecosystem):
    if ecosystem.startswith(("Debian", "Ubuntu")):
        return DebVersion
    return Version


def vuln_fix(vuln, version, name, ecosystem):
    parse = version_class(ecosystem)
    try:
        current = parse(version)
    except InvalidVersion:
        return None
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != ecosystem or not same_name(package.get("name", ""), name, ecosystem):
            continue
        for entry in affected.get("ranges", []):
            introduced = None
            for event in entry.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    try:
                        if parse(introduced) <= current < parse(event["fixed"]):
                            return parse(event["fixed"])
                    except InvalidVersion:
                        pass
    return None


def fix_version(vulns, version, name, ecosystem):
    fixes = [fix for fix in (vuln_fix(vuln, version, name, ecosystem) for vuln in vulns) if fix is not None]
    return max(fixes) if fixes else None


def blend(score):
    if score <= ANCHORS[0][0]:
        return ANCHORS[0][1]
    for (low, low_rgb), (high, high_rgb) in zip(ANCHORS, ANCHORS[1:]):
        if score <= high:
            t = (score - low) / (high - low)
            return tuple(round(a + (b - a) * t) for a, b in zip(low_rgb, high_rgb))
    return ANCHORS[-1][1]


def paint(text, score):
    r, g, b = blend(score)
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"


def message_for(score):
    for limit, text in MESSAGES:
        if score < limit:
            return text


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


def discover_pip():
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [(item["name"], item["version"], "PyPI") for item in json.loads(result.stdout)]


def os_ecosystem():
    info = {}
    with open("/etc/os-release") as handle:
        for line in handle:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                info[key] = value.strip('"')
    if info.get("ID") == "ubuntu":
        suffix = ":LTS" if "LTS" in info.get("VERSION", "") else ""
        return f"Ubuntu:{info['VERSION_ID']}{suffix}"
    if info.get("ID") == "debian":
        return f"Debian:{info['VERSION_ID'].split('.')[0]}"
    return None


def discover_apt():
    ecosystem = os_ecosystem()
    if ecosystem is None or shutil.which("dpkg-query") is None:
        return []
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Source}\t${Version}\t${db:Status-Status}\n"],
        capture_output=True,
        text=True,
    )
    found = {}
    for line in result.stdout.splitlines():
        package, source, version, status = line.split("\t")
        if status != "installed":
            continue
        name = package
        if source:
            match = re.match(r"(\S+)(?: \((.+)\))?$", source)
            name = match.group(1)
            if match.group(2):
                version = match.group(2)
        found[(name, version)] = None
    return [(name, version, ecosystem) for name, version in found]


def discover_npm():
    npm = shutil.which("npm")
    if npm is None:
        return []
    result = subprocess.run(
        [npm, "ls", "-g", "--json", "--depth=0"],
        capture_output=True,
        text=True,
    )
    dependencies = json.loads(result.stdout).get("dependencies", {})
    return [(name, info["version"], "npm") for name, info in dependencies.items() if "version" in info]


DISCOVERERS = {"pip": discover_pip, "npm": discover_npm, "apt": discover_apt}

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
