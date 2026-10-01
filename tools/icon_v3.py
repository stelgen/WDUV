#!/usr/bin/env python3
"""icon_v3.py — builds the WDUV logo from the authentic Windows Vista
Defender shield (extracted from system resources, archive.org
'windows-vista-and-7-icons-and-resources'/Shield.ico) + a Vista-style green
update badge at the bottom-right.

The shield asset belongs to Microsoft (extracted from Windows Vista); used
here as an homage for a non-commercial interoperability tool.

Usage: python3 tools/icon_v3.py <shield.ico> [out_dir]
"""
import math
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

S = 256          # native shield frame size
OUT_SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

GREEN_DARK = (0x38, 0x8E, 0x28)
GREEN_LIGHT = (0x7C, 0xC2, 0x3A)


def update_badge(size):
    """White glossy disc + two green circular arrows (Windows Update style)."""
    Sb = max(size * 4, 64)
    b = Image.new("RGBA", (Sb, Sb), (0, 0, 0, 0))
    d = ImageDraw.Draw(b)
    rim = max(2, Sb // 40)
    d.ellipse([rim, rim, Sb - rim, Sb - rim], fill=(252, 253, 255, 255),
              outline=(96, 108, 124, 255), width=max(2, Sb // 46))
    # soft top gloss
    gloss = Image.new("RGBA", (Sb, Sb), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gloss)
    gd.ellipse([int(Sb * 0.07), int(-Sb * 0.28), int(Sb * 0.93), int(Sb * 0.58)],
               fill=(255, 255, 255, 160))
    gloss = gloss.filter(ImageFilter.GaussianBlur(Sb // 30))
    disc = Image.new("L", (Sb, Sb), 0)
    ImageDraw.Draw(disc).ellipse([rim + 1, rim + 1, Sb - rim - 1, Sb - rim - 1], fill=255)
    b.paste(gloss, (0, 0), disc)

    # two green arcs with arrowheads
    cx = cy = Sb / 2
    r = Sb * 0.295
    thick = int(Sb * 0.125)
    for a0, a1, col in ((-155, -25, GREEN_LIGHT), (25, 155, GREEN_DARK)):
        d.arc([cx - r, cy - r, cx + r, cy + r], start=a0, end=a1, fill=col, width=thick)

    def head(angle_deg, col):
        a = math.radians(angle_deg)
        tip = (cx + (r + thick * 0.62) * math.cos(a), cy + (r + thick * 0.62) * math.sin(a))
        s = Sb * 0.085
        t1 = (tip[0] - s * 1.15 * math.cos(a - 0.42), tip[1] - s * 1.15 * math.sin(a - 0.42))
        t2 = (tip[0] - s * 0.30 * math.cos(a), tip[1] - s * 0.30 * math.sin(a))
        t3 = (tip[0] - s * 0.62 * math.cos(a + 1.02), tip[1] - s * 0.62 * math.sin(a + 1.02))
        d.polygon([tip, t1, t2, t3], fill=col)
    head(-30, GREEN_LIGHT)
    head(150, GREEN_DARK)
    return b.resize((size, size), Image.LANCZOS)


def compose(shield_path, out_dir):
    shield = Image.open(shield_path)
    # pick the largest frame
    try:
        sizes = sorted(shield.info.get("sizes", [(shield.size[0], shield.size[1])]),
                       key=lambda s: -(s[0] * s[1]))
        shield.size = sizes[0]
    except Exception:
        pass
    shield = shield.convert("RGBA")
    if shield.size != (S, S):
        shield = shield.resize((S, S), Image.LANCZOS)

    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    canvas.alpha_composite(shield)

    badge_size = int(S * 0.46)
    badge = update_badge(badge_size)
    # halo ring so the badge separates from the shield
    halo = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    pad = int(S * 0.012)
    bx, by = S - badge_size - int(S * 0.012), S - badge_size - int(S * 0.012)
    hd.ellipse([bx - pad, by - pad, bx + badge_size + pad, by + badge_size + pad],
               fill=(245, 247, 250, 255))
    canvas.alpha_composite(halo)
    canvas.alpha_composite(badge, (bx, by))

    os.makedirs(out_dir, exist_ok=True)
    png = os.path.join(out_dir, "logo.png")
    canvas.save(png)
    ico = os.path.join(out_dir, "logo.ico")
    canvas.save(ico, sizes=[(s, s) for s in OUT_SIZES])
    # hero-size for the landing page (upscaled smoothly)
    canvas.resize((512, 512), Image.LANCZOS).save(os.path.join(out_dir, "logo@512.png"))
    print("written:", png, ico)
    return png, ico


if __name__ == "__main__":
    shield = sys.argv[1] if len(sys.argv) > 1 else "Shield.ico"
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "assets")
    compose(shield, out)
