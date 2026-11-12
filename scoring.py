#Scoring.py  Scoring for the CLI
# Does the CVSS math (v3 by hand, v4 with a library) to turn a vuln into a 0-10 number as CVSS has as standard
import math
from cvss import CVSS4
from cvss.exceptions import CVSSError

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def roundup(value):
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0

# kaaahhkkaaannkkeerrrr maat 
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

# ik krijg de tyfus van dit
def vuln_score(vuln):
    for entry in vuln.get("severity", []):
        try:
            if entry["type"] in ("CVSS_V3", "CVSS_V3.1", "CVSS_V3.0"):
                return cvss3_score(entry["score"])
        except (KeyError, ValueError, IndexError, TypeError, AttributeError):
            continue
    for entry in vuln.get("severity", []):
        try:
            if entry["type"] == "CVSS_V4":
                return float(CVSS4(entry["score"]).base_score)
        except (CVSSError, KeyError, ValueError, TypeError, AttributeError):
            continue
    return None


def top_score(vulns):
    known = [score for score in map(vuln_score, vulns) if score is not None]
    return max(known) if known else None

# fiiiinnnaallyyy, 11:19 PM completion