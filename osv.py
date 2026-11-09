import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Need to make my shit more modulize, makes building in the long term muuchh cleaner and easier to scale. fawk
def query_package(name, version, ecosystem):
    response = requests.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    )
    return response.json().get("vulns", [])


def query_many(packages, on_progress=None, workers=10):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(query_package, *package) for package in packages]
        if on_progress:
            on_progress(0, len(packages))
        for done, _ in enumerate(as_completed(futures), start=1):
            if on_progress:
                on_progress(done, len(packages))
        return [future.result() for future in futures]
