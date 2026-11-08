# meow meow meow guess i start with this bullshit :3
ANCHORS = [
    (1, (140, 140, 140)),
    (2, (190, 200, 90)),
    (4, (240, 210, 40)),
    (6, (240, 130, 30)),
    (8, (150, 0, 0)),
    (10, (220, 0, 0)),
]

MESSAGES = [
    (2, "You are just fine bucko"),
    (4, "Psh I don't know about you but I'd have a eye out and update"),
    (6, "I'd update if I were you..."),
    (8, "Yikes you should really update"),
    (10.1, "UPDATE NOW !! NOW !! NOW !! NOW !!"),
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
