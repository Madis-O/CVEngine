# VERSIONS BRUHHHHH, lets hope modulation doesnt completelety break this shit.
import functools
import re
from packaging.version import InvalidVersion, Version


def same_name(a, b, ecosystem):
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", a).lower() == re.sub(r"[-_.]+", "-", b).lower()
    return a == b


def deb_order(char):
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256

# erm chatgbb erm fix my problems erm chatgbb what this mean. (fuck chat tho, seriously)
# jokes aside tho thank fuck for google. every devs best man istg ughhh
def deb_compare_part(a, b):
    digits = "0123456789"
    while a or b:
        i = 0
        while i < len(a) and a[i] not in digits:
            i += 1
        j = 0
        while j < len(b) and b[j] not in digits:
            j += 1
        for k in range(max(i, j)):
            ca = deb_order(a[k]) if k < i else 0
            cb = deb_order(b[k]) if k < j else 0
            if ca != cb:
                return -1 if ca < cb else 1
        a, b = a[i:], b[j:]
        i = 0
        while i < len(a) and a[i] in digits:
            i += 1
        j = 0
        while j < len(b) and b[j] in digits:
            j += 1
        na = int(a[:i] or 0)
        nb = int(b[:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
        a, b = a[i:], b[j:]
    return 0


@functools.total_ordering
class DebVersion:
    def __init__(self, text):
        self.text = text.strip()
        if not self.text:
            raise InvalidVersion("empty version")
        epoch, rest = self.text.split(":", 1) if ":" in self.text else ("0", self.text)
        if not epoch.isdigit():
            raise InvalidVersion(self.text)
        self.epoch = int(epoch)
        self.upstream, self.revision = rest.rsplit("-", 1) if "-" in rest else (rest, "")

    def compare(self, other):
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        result = deb_compare_part(self.upstream, other.upstream)
        if result:
            return result
        return deb_compare_part(self.revision, other.revision)

    def __eq__(self, other):
        return self.compare(other) == 0

    def __lt__(self, other):
        return self.compare(other) < 0

    def __str__(self):
        return self.text


def rpm_alnum(char):
    return char.isascii() and char.isalnum()

#Claude assisted with the following cus cmon, im lost atp with rpm comparison, straight alien language. besides i wanna stick to bare to keep it managed as most claud projects are just a throw in and hope it goes well one shot. i mean goes for everything but still.

def rpm_compare_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not rpm_alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not rpm_alnum(b[j]) and b[j] not in "~^":
            j += 1
        tilde_a = i < len(a) and a[i] == "~"
        tilde_b = j < len(b) and b[j] == "~"
        if tilde_a or tilde_b:
            if not tilde_a:
                return 1
            if not tilde_b:
                return -1
            i += 1
            j += 1
            continue
        caret_a = i < len(a) and a[i] == "^"
        caret_b = j < len(b) and b[j] == "^"
        if caret_a or caret_b:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not caret_a:
                return 1
            if not caret_b:
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        numeric = a[i].isdigit()
        check = str.isdigit if numeric else (lambda c: rpm_alnum(c) and not c.isdigit())
        end_a = i
        while end_a < len(a) and check(a[end_a]):
            end_a += 1
        end_b = j
        while end_b < len(b) and check(b[end_b]):
            end_b += 1
        part_a, part_b = a[i:end_a], b[j:end_b]
        if not part_a:
            return -1
        if not part_b:
            return 1 if numeric else -1
        if numeric:
            part_a, part_b = part_a.lstrip("0"), part_b.lstrip("0")
            if len(part_a) != len(part_b):
                return -1 if len(part_a) < len(part_b) else 1
        if part_a != part_b:
            return -1 if part_a < part_b else 1
        i, j = end_a, end_b
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


@functools.total_ordering
class RpmVersion:
    def __init__(self, text):
        self.text = text.strip()
        if not self.text:
            raise InvalidVersion("empty version")
        epoch, rest = self.text.split(":", 1) if ":" in self.text else ("0", self.text)
        if not epoch.isdigit():
            raise InvalidVersion(self.text)
        self.epoch = int(epoch)
        self.upstream, self.release = rest.rsplit("-", 1) if "-" in rest else (rest, "")

    def compare(self, other):
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        result = rpm_compare_part(self.upstream, other.upstream)
        if result:
            return result
        return rpm_compare_part(self.release, other.release)

    def __eq__(self, other):
        return self.compare(other) == 0

    def __lt__(self, other):
        return self.compare(other) < 0

    def __str__(self):
        return self.text


def version_class(ecosystem):
    if ecosystem.startswith(("Debian", "Ubuntu")):
        return DebVersion
    if ecosystem.startswith(("Rocky Linux", "AlmaLinux", "Red Hat", "SUSE", "openSUSE")):
        return RpmVersion
    return Version


def vuln_fix(vuln, version, name, ecosystem):
    parse = version_class(ecosystem)
    try:
        current = parse(version)
    except InvalidVersion:
        return None
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != ecosystem or not same_name(package.get("name", ""), name, ecosystem):
            continue
        for entry in affected.get("ranges", []):
            introduced = None
            for event in entry.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    try:
                        if parse(introduced) <= current < parse(event["fixed"]):
                            return parse(event["fixed"])
                    except InvalidVersion:
                        pass
    return None


def fix_version(vulns, version, name, ecosystem):
    fixes = [fix for fix in (vuln_fix(vuln, version, name, ecosystem) for vuln in vulns) if fix is not None]
    return max(fixes) if fixes else None

# i dont wanna touch this file ever again if it works it works. 