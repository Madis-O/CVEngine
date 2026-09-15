import requests

package_name = "django"
package_version = "3.0.0"

response = requests.post(
    "https://api.osv.dev/v1/query",
    json={"version": package_version, "package": {"name": package_name, "ecosystem": "PyPI"}}
)

print(response.json())
