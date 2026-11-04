#!/usr/bin/env python3
"""Render demo/transcript.txt as a terminal-typing GIF (PIL, DejaVuSansMono)."""
from PIL import Image, ImageDraw, ImageFont

W, H = 880, 520
BG = (18, 18, 24)
FG = (220, 220, 220)
DIM = (150, 150, 160)
GREEN = (120, 220, 130)
YELLOW = (235, 200, 100)
RED = (240, 110, 110)
CYAN = (120, 200, 230)

font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 15)

lines = open("demo/transcript.txt").read().splitlines()

def color_for(line: str):
    if line.startswith("$"):
        return GREEN
    if line.startswith("DENY"):
        return RED
    if line.startswith("REVIEW"):
        return YELLOW
    if line.startswith("ALLOW"):
        return GREEN
    if line.strip().startswith("[high]"):
        return (240, 150, 150)
    if line.strip().startswith("[medium]"):
        return (235, 200, 130)
    if line.strip().startswith("[low]"):
        return DIM
    if line.startswith("signals:"):
        return CYAN
    return FG

# Build frames: type each line char-by-char (fast), pause on verdict lines.
frames = []
canvas: list[tuple[str, tuple]] = []  # (text, color)

# Title card (3s): what the demo shows
title = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(title)
d.text((14, 120), "extverify — verify before you install", font=bold, fill=GREEN)
d.text((14, 170), "1. 29/10 incident shape (recorded fixture)  -> DENY", font=font, fill=FG)
d.text((14, 200), "2. live: esbenp.prettier-vscode               -> REVIEW", font=font, fill=FG)
d.text((14, 230), "3. pin -> verify --json (repack detection)   -> pin matches", font=font, fill=FG)
d.text((14, 300), "zero-dep CLI · no model · no account", font=font, fill=DIM)
for _ in range(50):
    frames.append(title.copy())

def render(typed_suffix=""):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = 14
    for text, color in canvas:
        d.text((14, y), text, font=bold if text.startswith(("$", "DENY", "REVIEW", "ALLOW")) else font, fill=color)
        y += 21
        if y > H - 30:
            break
    if typed_suffix:
        last_color = canvas[-1][1] if canvas else FG
        d.text((14 + int(font.getlength(canvas[-1][0])) if canvas else 14, y - 21 if canvas else 14),
               typed_suffix, font=font, fill=last_color)
    # cursor
    d.rectangle([14, H - 24, 22, H - 12], fill=GREEN)
    return img

for line in lines:
    color = color_for(line)
    # type the line
    step = max(1, len(line) // 12)
    for i in range(0, len(line) + 1, step):
        canvas_tmp = canvas + [(line[:i], color)]
        # render with partial line
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        y = 14
        for j, (text, c) in enumerate(canvas_tmp):
            f = bold if text.startswith(("$", "DENY", "REVIEW", "ALLOW")) else font
            d.text((14, y), text, font=f, fill=c)
            y += 21
            if y > H - 30:
                break
        d.rectangle([14, H - 24, 22, H - 12], fill=GREEN)
        frames.append(img)
    canvas.append((line, color))
    if line.startswith(("DENY", "REVIEW", "ALLOW", "---")):
        # hold the verdict frame a beat
        for _ in range(14):
            frames.append(frames[-1].copy())

# final hold
for _ in range(30):
    frames.append(frames[-1].copy())

frames[0].save(
    "demo/extverify-demo.gif",
    save_all=True,
    append_images=frames[1:],
    duration=60,
    loop=0,
)
print(f"frames={len(frames)} size={__import__('os').path.getsize('demo/extverify-demo.gif')}")
