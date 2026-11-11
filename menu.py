import platform
import shutil
import questionary


def choose_scan():
    kind = questionary.select(
        "What are we scanning today ??",
        choices=["Packages", "A Project Folder"],
    ).ask()
    if kind == "Packages":
        choices = ["pip", "npm"]
        if platform.system() == "Linux":
            if shutil.which("dpkg-query"):
                choices.append("apt")
            if shutil.which("rpm"):
                choices.append("rpm")
        return questionary.select("Which packages ??", choices=choices).ask()
    if kind == "A Project Folder":
        return "folder"
    return None
