import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument("package")
parser.add_argument("version")
args = parser.parse_args()

response = requests.post(
    "https://api.osv.dev/v1/query",
    json={"version": args.version, "package": {"name": args.package, "ecosystem": "PyPI"}}
)

vulns = response.json().get("vulns", [])

if not vulns:
    print("TODO: no vulns message")
else:
    print(f"TODO: header, {len(vulns)} found")
    for vuln in vulns:
        print(f"TODO: row - {vuln['id']} - {vuln.get('summary', 'no summary')}")
