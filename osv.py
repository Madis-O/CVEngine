#OSV.py  Query the OSV API for vulnerabilities
# Asks OSV.dev "is this package version fucked ??" and 10 lookups at once, retries when the internet is being stubborn
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

OSV_URL = "https://api.osv.dev/v1/query"
RETRY_STATUS = {429, 500, 502, 503, 504}


class OSVError(Exception):
    def __init__(self, name, version, reason):
        super().__init__(f"{name} {version}: {reason}")
        self.name = name
        self.version = version
        self.reason = reason


# Need to make my shit more modulize, makes building in the long term muuchh cleaner and easier to scale. fawk
def query_package(name, version, ecosystem, tries=3, timeout=10):
    reason = "unknown"
    for attempt in range(tries):
        try:
            response = requests.post(
                OSV_URL,
                json={"version": version, "package": {"name": name, "ecosystem": ecosystem}},
                timeout=timeout,
            )
            if response.status_code in RETRY_STATUS:
                reason = f"HTTP {response.status_code}, try again later"
            elif response.status_code >= 400:
                raise OSVError(name, version, f"HTTP {response.status_code}")
            else:
                return response.json().get("vulns", [])
        except requests.exceptions.Timeout:
            reason = "timed out, try again later"
        except requests.exceptions.ConnectionError:
            reason = "no connection, try again later"
        except ValueError:
            reason = "unreadable response, try again later"
        if attempt < tries - 1:
            time.sleep(2 ** attempt)
    raise OSVError(name, version, reason)


def check_reachable():
    query_package("pip", "1.0", "PyPI", tries=2, timeout=5)


def query_many(packages, on_progress=None, workers=10):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(query_package, *package) for package in packages]
        try:
            if on_progress:
                on_progress(0, len(packages))
            for done, _ in enumerate(as_completed(futures), start=1):
                if on_progress:
                    on_progress(done, len(packages))
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        answers = []
        for future in futures:
            try:
                answers.append((future.result(), None))
            except OSVError as error:
                answers.append((None, error))
        return answers
