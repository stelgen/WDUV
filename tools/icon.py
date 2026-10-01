#!/usr/bin/env python3
"""icon.py — generates the project logo: a Vista-era Windows Defender style
glossy quadrant shield with a green "update" arrows badge (Aero look).

Drawn from scratch (no Microsoft assets), supersampled 4x for smoothness.
Outputs assets/logo.ico (multi-size) and assets/logo.png (1024 px).

Usage: python3 tools/icon.py [out_dir]
"""
import math
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

S = 1024  # supersampled canvas
OUT_SIZES = [16, 24, 32, 48, 64, 128, 256]

# Windows-flag quadrant colours (Vista era), light->dark vertical ramps.
QUADS = [
    ((0xF2, 0x54, 0x4B), (0xC8, 0x1F, 0x25)),  # red    (top-left)
    ((0x8C, 0xD6, 0x3F), (0x53, 0x8F, 0x10)),  # green  (top-right)
    ((0x4F, 0xA8, 0xE8), (0x0C, 0x62, 0xB4)),  # blue   (bottom-left)
    ((0xFF, 0xD1, 0x4F), (0xE8, 0x9C, 0x00)),  # yellow (bottom-right)
]
RIM_OUT = [(0xEE, 0xF3, 0xF9), (0x9A, 0xA7, 0xB4)]   # silver rim ramp
RIM_IN = [(0xFF, 0xFF, 0xFF), (0xC7, 0xCF, 0xD8)]


def bezier(p0, p1, p2, p3, steps=64):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def shield_path(cx=0.5, top=0.085, bottom=0.915, halfw=0.34):
    """Classic shield: flat top with rounded corners, curved flanks to a
    bottom point."""
    L = (cx - halfw, top)
    R = (cx + halfw, top)
    # corners rounded via short cubics
    pts = []
    pts += bezier((cx - halfw + 0.075, top), (cx - halfw, top), (cx - halfw, top + 0.03), (cx - halfw, top + 0.09))
    pts += bezier((cx - halfw, top + 0.35), (cx - halfw, 0.55), (cx - 0.17, 0.72), (cx, bottom))
    pts += bezier((cx + 0.17, 0.72), (cx + halfw, 0.55), (cx + halfw, top + 0.35), (cx + halfw, top + 0.09))
    pts += bezier((cx + halfw, top + 0.03), (cx + halfw, top), (cx + halfw - 0.075, top), (cx + halfw - 0.075, top))
    pts += [(cx - halfw + 0.075, top)]
    return pts


def vgrad(size, top, bottom):
    """Vertical gradient image (RGB)."""
    w, h = size
    img = Image.new("RGB", (1, h))
    for y in range(h):
        t = y / max(1, h - 1)
        img.putpixel((0, y), tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return img.resize((w, h))


def mask_from_poly(size, pts):
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).polygon([(x * size[0], y * size[1]) for x, y in pts], fill=255)
    return m


def build_base():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    pts = shield_path()
    mask = mask_from_poly((S, S), pts)

    # ---- silver rim (outer shield) ----
    rim = vgrad((S, S), RIM_OUT[0], RIM_OUT[1]).convert("RGBA")
    img.paste(rim, (0, 0), mask)

    # ---- inner shield, slightly inset ----
    inner_pts = shield_path(cx=0.5, top=0.115, bottom=0.885, halfw=0.305)
    inner_mask = mask_from_poly((S, S), inner_pts)

    # quadrants: 2x2 grid clipped by the inner shield
    mid = int(S * 0.5)
    quad_boxes = [
        (0, 0, mid, mid),        # top-left  (red)
        (mid, 0, S, mid),        # top-right (green)
        (0, mid, mid, S),        # bottom-left  (blue)
        (mid, mid, S, S),        # bottom-right (yellow)
    ]
    quads = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    for box, (c1, c2) in zip(quad_boxes, QUADS):
        wq = box[2] - box[0]
        hq = box[3] - box[1]
        g = vgrad((max(wq, 1), max(hq, 1)), c1, c2).convert("RGBA")
        quads.paste(g, (box[0], box[1]))
    img.paste(quads, (0, 0), inner_mask)

    # thin white separators between quadrants
    d = ImageDraw.Draw(img)
    sep = max(3, S // 340)
    d.rectangle([mid - sep, int(S * 0.10), mid + sep, int(S * 0.90)], fill=(255, 255, 255, 235))
    d.rectangle([int(S * 0.17), mid - sep, int(S * 0.83), mid + sep], fill=(255, 255, 255, 235))

    # re-clip separators to the shield
    seps = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    seps.paste(img.crop((0, 0, S, S)), (0, 0))
    clipped = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    clipped.paste(seps, (0, 0), inner_mask)
    img.alpha_composite(clipped)

    # ---- gloss: big soft highlight across the upper half ----
    gloss = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gloss)
    gd.ellipse([int(-S * 0.25), int(-S * 0.42), int(S * 1.05), int(S * 0.62)], fill=(255, 255, 255, 92))
    gloss = gloss.filter(ImageFilter.GaussianBlur(S // 40))
    clip = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    clip.paste(gloss, (0, 0), inner_mask)
    img.alpha_composite(clip)

    # subtle inner top edge highlight
    edge = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ed = ImageDraw.Draw(edge)
    ed.line([(int(S * 0.22), int(S * 0.115)), (int(S * 0.78), int(S * 0.115))], fill=(255, 255, 255, 170), width=max(2, S // 400))
    img.alpha_composite(edge)

    # ---- drop shadow (for standalone PNG use) ----
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sh_pts = [(x, y + 0.018) for x, y in pts]
    sd.polygon([(x * S, y * S) for x, y in sh_pts], fill=(10, 15, 25, 110))
    shadow = shadow.filter(ImageFilter.GaussianBlur(S // 60))
    base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    base.alpha_composite(shadow)
    base.alpha_composite(img)
    return base, pts, mask, inner_mask


def update_badge(size):
    """Glossy silver disc with two green circular arrows (Windows-Update
    style) — drawn at `size` px."""
    Sb = size * 4
    b = Image.new("RGBA", (Sb, Sb), (0, 0, 0, 0))
    d = ImageDraw.Draw(b)
    # disc
    d.ellipse([2, 2, Sb - 2, Sb - 2], fill=(252, 253, 255, 255), outline=(120, 132, 148, 255), width=max(2, Sb // 42))
    gloss = Image.new("RGBA", (Sb, Sb), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gloss)
    gd.ellipse([int(Sb * 0.06), int(-Sb * 0.25), int(Sb * 0.94), int(Sb * 0.55)], fill=(255, 255, 255, 150))
    gloss = gloss.filter(ImageFilter.GaussianBlur(Sb // 28))
    disc_mask = Image.new("L", (Sb, Sb), 0)
    ImageDraw.Draw(disc_mask).ellipse([4, 4, Sb - 4, Sb - 4], fill=255)
    b.paste(gloss, (0, 0), disc_mask)

    # two green arrows forming a circle
    green1, green2 = (0x38, 0x8E, 0x28), (0x6C, 0xB8, 0x2F)
    cx = cy = Sb / 2
    r = Sb * 0.30
    thick = int(Sb * 0.115)
    # arcs (top: 200..340 deg, bottom: 20..160 deg)
    for a0, a1, col in ((-160, -20, green2), (20, 160, green1)):
        d.arc([cx - r, cy - r, cx + r, cy + r], start=a0, end=a1, fill=col, width=thick)
    # arrowheads
    def head(angle_deg, col):
        a = math.radians(angle_deg)
        tip = (cx + (r + thick * 0.55) * math.cos(a), cy + (r + thick * 0.55) * math.sin(a))
        # triangle roughly perpendicular to the arc tangent
        s = Sb * 0.085
        t1 = (tip[0] - s * 1.05 * math.cos(a - 0.5), tip[1] - s * 1.05 * math.sin(a - 0.5))
        t2 = (tip[0] - s * 0.25 * math.cos(a), tip[1] - s * 0.25 * math.sin(a))
        t3 = (tip[0] - s * 0.55 * math.cos(a + 1.05), tip[1] - s * 0.55 * math.sin(a + 1.05))
        d.polygon([tip, t1, t2, t3], fill=col)
    head(-38, green2)
    head(142, green1)
    return b.resize((size, size), Image.LANCZOS)


def compose(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    base, pts, mask, inner_mask = build_base()

    # badge: bottom-right, ~38% of shield height
    badge = update_badge(int(S * 0.44))
    bx = int(S * 0.585)
    by = int(S * 0.585)
    # small white halo ring under the badge
    halo = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.ellipse([bx - 10, by - 10, bx + badge.size[0] + 10, by + badge.size[1] + 10],
               fill=(250, 251, 253, 255))
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.alpha_composite(base)
    img.alpha_composite(halo)
    img.alpha_composite(badge, (bx, by))

    png_path = os.path.join(out_dir, "logo.png")
    img.save(png_path)

    ico_path = os.path.join(out_dir, "logo.ico")
    img.save(ico_path, sizes=[(s, s) for s in OUT_SIZES])
    print("written:", png_path, ico_path)
    return png_path, ico_path


if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "assets")
    compose(out_dir)
