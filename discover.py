import json
import re
import shutil
import subprocess
import sys

# Everything that finds packages lives here now for yeah modularity. Lekkah tachhh fijv bloodclat barkie werk hier maat
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


# Mainly Ubuntu and Debian for now, rpm and AUR are comin later. Linux is gonna be the death of me FUCK
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


# New source = write the function, add it here, dne. Thats the whole point of splitting this shit up
DISCOVERERS = {"pip": discover_pip, "npm": discover_npm, "apt": discover_apt}
