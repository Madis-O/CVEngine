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

print(response.json())
