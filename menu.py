import platform
import questionary


def choose_scan():
    kind = questionary.select(
        "What are we scanning today ??",
        choices=["Packages"],
    ).ask()
    if kind == "Packages":
        return questionary.select(
            "Which packages ??",
            choices=["pip", "npm"] + (["apt"] if platform.system() == "Linux" else []),
        ).ask()
    return None
