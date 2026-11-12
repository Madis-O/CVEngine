#Menu.py  Menu for the CLI
# The arrow key menus where you pick what to scan. Only shows options that actually work on your machine considering cross compatibility.
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

#The new project folder scanning option is here, shit will scan your requirements.txt file and check all the packages in there.

def choose_folder():
    return questionary.path("Which folder ??", default=".").ask()
