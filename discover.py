import json
import re
import shutil
import subprocess
import sys


class DiscoverError(Exception):
    def __init__(self, source, reason):
        super().__init__(f"{source}: {reason}")
        self.source = source
        self.reason = reason


# Everything that finds packages lives here now for yeah modularity. Lekkah tachhh fijv bloodclat barkie werk hier maat
def discover_pip():
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        raise DiscoverError("pip", "pip isn't available for this Python")
    try:
        return [(item["name"], item["version"], "PyPI") for item in json.loads(result.stdout)]
    except (ValueError, KeyError, TypeError):
        raise DiscoverError("pip", "pip gave unreadable output")


def read_os_release(source, path="/etc/os-release"):
    info = {}
    try:
        with open(path) as handle:
            for line in handle:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    info[key] = value.strip('"')
    except OSError:
        raise DiscoverError(source, f"couldn't read {path}")
    return info


def os_ecosystem(path="/etc/os-release"):
    info = read_os_release("apt", path)
    if info.get("ID") not in ("ubuntu", "debian"):
        raise DiscoverError("apt", f"{info.get('PRETTY_NAME', 'this distro')} isn't supported yet")
    if not info.get("VERSION_ID"):
        raise DiscoverError("apt", "deadass couldn't tell which release this is")
    if info["ID"] == "ubuntu":
        suffix = ":LTS" if "LTS" in info.get("VERSION", "") else ""
        return f"Ubuntu:{info['VERSION_ID']}{suffix}"
    return f"Debian:{info['VERSION_ID'].split('.')[0]}"


# Mainly Ubuntu and Debian for now, rpm and AUR are comin later. Linux is gonna be the death of me FUCK
def discover_apt():
    ecosystem = os_ecosystem()
    if shutil.which("dpkg-query") is None:
        raise DiscoverError("apt", "dpkg-query isn't installed")
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Source}\t${Version}\t${db:Status-Status}\n"],
            capture_output=True,
            text=True,
        )
    except OSError:
        raise DiscoverError("apt", "dpkg-query couldn't run")
    found = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        package, source, version, status = fields
        if status != "installed":
            continue
        name = package
        match = re.match(r"(\S+)(?: \((.+)\))?$", source) if source else None
        if match:
            name = match.group(1)
            if match.group(2):
                version = match.group(2)
        found[(name, version)] = None
    return [(name, version, ecosystem) for name, version in found]


RPM_NAMES = {"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}


def rpm_ecosystem(path="/etc/os-release"):
    info = read_os_release("rpm", path)
    if info.get("ID") not in RPM_NAMES:
        raise DiscoverError("rpm", f"{info.get('PRETTY_NAME', 'this distro')} isn't supported yet")
    if not info.get("VERSION_ID"):
        raise DiscoverError("rpm", "deadass couldn't tell which release this is")
    return f"{RPM_NAMES[info['ID']]}:{info['VERSION_ID'].split('.')[0]}"


def discover_rpm():
    ecosystem = rpm_ecosystem()
    if shutil.which("rpm") is None:
        raise DiscoverError("rpm", "rpm isn't installed")
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{SOURCERPM}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\n"],
            capture_output=True,
            text=True,
        )
    except OSError:
        raise DiscoverError("rpm", "rpm couldn't run")
    found = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        package, source, epoch, version = fields
        if source == "(none)":
            continue
        name = source[:-8] if source.endswith(".src.rpm") else source
        name = name.rsplit("-", 2)[0] if name.count("-") >= 2 else package
        found[(name, f"{epoch}:{version}" if epoch not in ("0", "(none)") else version)] = None
    return [(name, version, ecosystem) for name, version in found]


def discover_npm():
    npm = shutil.which("npm")
    if npm is None:
        raise DiscoverError("npm", "npm isn't installed")
    try:
        result = subprocess.run(
            [npm, "ls", "-g", "--json", "--depth=0"],
            capture_output=True,
            text=True,
        )
    except OSError:
        raise DiscoverError("npm", "npm couldn't run")
    try:
        dependencies = json.loads(result.stdout).get("dependencies", {})
        return [(name, info["version"], "npm") for name, info in dependencies.items() if "version" in info]
    except (ValueError, AttributeError, TypeError):
        raise DiscoverError("npm", "npm gave unreadable output")


# New source = write the function, add it here, dne. Thats the whole point of splitting this shit up
DISCOVERERS = {"pip": discover_pip, "npm": discover_npm, "apt": discover_apt, "rpm": discover_rpm}
