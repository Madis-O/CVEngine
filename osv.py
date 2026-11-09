import requests
from concurrent.futures import ThreadPoolExecutor

# Need to make my shit more modulize, makes building in the long term muuchh cleaner and easier to scale. fawk
def query_package(name, version, ecosystem):
    response = requests.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    )
    return response.json().get("vulns", [])


def query_many(packages, workers=10):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda package: query_package(*package), packages))
