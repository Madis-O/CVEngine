# CVEngine

I'll cut the bullshit, this is a long term project of mine. A CLI tool aimed at sysadmins and homelabbers that checks what's installed on your machine against known vulnerabilities and tells you straight up if you need to update.

**DISCLAIMER:** This project is for a strong majority made by hand, but AI assistance is present on the more so complex parts (Claude from Anthropic)

## What it does

- Finds your installed packages
- Looks them up online on [OSV.dev](https://osv.dev) API
- Scores every problem with CVSS (1 to 10 and scales with grey to blood red)
- Tells you straight the level of CVSS score and if you should update ASAP or it can hold off a bit
- Shows the version to update to when a fix exists (the green dot)

## What it can scan

| Source | Works on | Status |
|---|---|---|
| pip | Windows, Linux | Working (tested) |
| npm (global) | Windows, Linux | Working (tested) |
| apt | Ubuntu, Debian | Working, tested in WSL Ubuntu |
| rpm | Rocky, AlmaLinux | Written but untested on a real box (no VM yet) |
| Project Folder | anywhere | Not built yet, coming soom tho |
| Fedora, Arch / AUR | | Not supported yet, OSV doesn't cover them so I need another way ay caramba |

## Install

Needs Python 3.

```bash
git clone https://github.com/Madis-O/CVEngine.git
cd CVEngine
pip install .
```

Proper installers are coming later, first I'm perfecting the product yk the whole line but i promise good product :3

## Use

Run it with ease and pick what to scan with arrow keys:

```bash
cvng
```

`cvengine` does the same thing.

Or check one pip package directly:

```bash
cvng django 3.0.0
```

## Heads up

- It needs internet. If the database can't be reached it says so and stops so no search
- Some packages can't be checked sometimes. It finishes the scan anyway and lists which ones it couldn't check and tells you
- It's a long term project, expect a mess in places. komt goed


**The structure of this README is also provided by claude as I am no .MD connoisseur, I am transperant with my AI usage so yk what is done by who**