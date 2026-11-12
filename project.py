#Project.py  Read a project folder's dependency files and so on (this file is assisted by Claude, heavy lifiting done here)
import os
import re
from collections import namedtuple
from discover import DiscoverError

Unpinned = namedtuple("Unpinned", ["name", "version", "reason"])

LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
PINNED = re.compile(r"^===?\s*([^\s,*]+)$")

#thank you thank you thank you thank you claude blehhh
def read_requirements(path):
    try:
        with open(path, encoding="utf-8-sig") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError):
        raise DiscoverError("folder", f"couldn't read {path}")
    packages = []
    skipped = []
    for line in re.sub(r"\\[ \t]*\n", " ", text).splitlines():
        line = re.split(r"(?:^|\s)#", line)[0]
        line = line.split(";")[0]
        line = re.split(r"\s--", line)[0].strip()
        if not line or line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue
        match = LINE.match(line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2).strip()
        pinned = PINNED.match(spec)
        if pinned:
            packages.append((name, pinned.group(1), "PyPI"))
        else:
            skipped.append(Unpinned(name, spec or "any", "no exact version pinned"))
    return packages, skipped


# Same shit as discover.py but this one is for checking a project folder for dependency files and shit
READERS = {"requirements.txt": read_requirements}


def read_project(folder):
    folder = os.path.expanduser(folder)
    if not os.path.isdir(folder):
        raise DiscoverError("folder", f"{folder} isn't a folder")
    packages = []
    skipped = []
    found = False
    for filename, reader in READERS.items():
        path = os.path.join(folder, filename)
        if os.path.isfile(path):
            found = True
            more, less = reader(path)
            packages += more
            skipped += less
    if not found:
        raise DiscoverError("folder", f"no dependency files in {folder}")
    return packages, skipped
