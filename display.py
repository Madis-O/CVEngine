#Display.py   Output formatting for the CLI
# The pretty part. Turns a CVSS score into a color (grey -> blood red scaling with the score) and picks the blunt message that goes with it
ANCHORS = [
    (1, (140, 140, 140)),
    (2, (190, 200, 90)),
    (4, (240, 210, 40)),
    (6, (240, 130, 30)),
    (8, (150, 0, 0)),
    (10, (220, 0, 0)),
]

MESSAGES = [
    (0.1, "(None) no risk"),
    (4.0, "(Low) negligible risk"),
    (7.0, "(Medium) update when you can"),
    (9.0, "(High) update soon"),
    (10.1, "(Critical) Update now"),
]



def blend(score):
    if score <= ANCHORS[0][0]:
        return ANCHORS[0][1]
    for (low, low_rgb), (high, high_rgb) in zip(ANCHORS, ANCHORS[1:]):
        if score <= high:
            t = (score - low) / (high - low)
            return tuple(round(a + (b - a) * t) for a, b in zip(low_rgb, high_rgb))
    return ANCHORS[-1][1]


def paint(text, score):
    r, g, b = blend(score)
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"


def message_for(score):
    for limit, text in MESSAGES:
        if score < limit:
            return text
