import argparse
import math
import os
import requests

os.system("")

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
    return None


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


def query_package(name, version, ecosystem):
    response = requests.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    )
    return response.json().get("vulns", [])


parser = argparse.ArgumentParser()
parser.add_argument("package")
parser.add_argument("version")
args = parser.parse_args()

vulns = query_package(args.package, args.version, "PyPI")

if not vulns:
    print("TODO: no vulns message")
else:
    scored = [(vuln, vuln_score(vuln)) for vuln in vulns]
    known = [score for _, score in scored if score is not None]
    top = max(known) if known else None
    if top is not None:
        print(paint(message_for(top), top))
        print(paint(f"CVSS {top}", top))
    print(f"TODO: header, {len(vulns)} found")
    for vuln, score in scored:
        label = paint(f"{score:>4}", score) if score is not None else " n/a"
        print(f"TODO: row - {label} - {vuln['id']} - {vuln.get('summary', 'no summary')}")
