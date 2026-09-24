#!/usr/bin/env python3
"""
Prodigy Stego Hunter v3.0
Automated CTF Image Steganography Framework

Usage:
    python prodigy.py <image> [options]

Examples:
    python prodigy.py challenge.png
    python prodigy.py challenge.jpg -w rockyou.txt -f "HTB\\{.*?\\}" -o report.txt
    python prodigy.py challenge.png -i -nb
    python prodigy.py challenge.jpg -v --no-xor -j out.json
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import math
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from collections import Counter
from datetime import datetime
from pathlib import Path

# ─── Dependencies ────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    )
except ImportError:
    print("[!] Missing: rich  →  pip install rich")
    sys.exit(1)

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

console = Console()

# ─── Constants ───────────────────────────────────────────────
DEFAULT_WORDLIST   = Path("/usr/share/wordlists/rockyou.txt")

# Flag patterns tried automatically when -f is not supplied
FLAG_BANK = [
    r"flag\{[^}\n]{1,200}\}",
    r"FLAG\{[^}\n]{1,200}\}",
    r"HTB\{[^}\n]{1,200}\}",
    r"CTF\{[^}\n]{1,200}\}",
    r"picoCTF\{[^}\n]{1,200}\}",
    r"picoctf\{[^}\n]{1,200}\}",
    r"THM\{[^}\n]{1,200}\}",
    r"tryhackme\{[^}\n]{1,200}\}",
    r"[A-Za-z0-9_]{2,20}\{[^}\n]{3,200}\}",
]

COMMON_PASSWORDS = [
    "", "password", "123456", "12345678", "123456789", "12345", "1234",
    "admin", "root", "toor", "flag", "secret", "stego", "steganography",
    "hidden", "ctf", "challenge", "letmein", "qwerty", "qwerty123",
    "hunter2", "test", "guest", "user", "pass", "steghide", "steg",
    "ctf123", "flag123", "superman", "iloveyou", "trustno1", "sunshine",
    "princess", "welcome", "abc123", "monkey", "dragon", "master",
    "shadow", "killer", "1q2w3e4r", "password1", "sunshine1", "football",
    "baseball", "whatever", "computer", "michael", "jordan", "harley",
    "ranger", "daniel", "andrew", "matthew", "jessica", "ashley",
    "thomas", "robert", "access", "flower", "cheese", "chicken",
    "summer", "winter", "spring", "autumn", "matrix", "starwars",
    "batman", "pokemon", "nintendo", "gaming", "hacker", "cyber",
    "security", "exploit", "payload", "shell", "0day", "1337", "leet",
    "buffalo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
]

# ─── Banner Art (braille skull) ──────────────────────────────
BANNER_ART = r"""⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠿⠻⠟⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠋⣡⣴⣶⣿⣿⣿⣿⣟⡲⣶⢤⢈⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⣩⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣌⣿⢯⡷⣆⡀⠘⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⢿⣿⣿⣌⢾⣿⣷⣮⡹⣆⠀⢒⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡎⣿⣿⣧⢻⣯⢿⡆⠙⢎⢻⣷⠈⢃⠀⢰⡛⣿⣿⣿⢋⣵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⡿⣻⣿⣿⣟⡏⣰⣿⢿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⡇⣿⠘⣿⣿⣇⢻⡎⣷⡘⣎⢳⡹⡁⠛⠡⠀⠆⣿⣿⣿⣦⡸⣿⣿⢟⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢱⣿⣿⣼⣿⣿⣿⢾⣿⡧⣿⣿⣿⡇⢿⢸⣇⢪⢿⠿⠆⢧⠸⠇⣛⣂⠁⠙⠀⢠⠀⠸⡍⣿⣿⣿⣿⣮⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣼⣿⡇⣿⣿⣿⣣⢼⣿⡇⢿⢸⣿⣿⠸⠇⣃⠀⠤⢘⣀⣤⣤⣿⣿⡿⠟⠀⠀⠀⠀⢸⣃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡁⣿⡿⣇⣿⣽⡏⣿⢸⣿⢧⠸⡎⢟⡭⠀⠃⠀⠀⠀⠀⢺⣿⣿⣿⣿⢀⢰⣄⡀⢳⠀⢰⡩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⡇⡇⠏⣿⠁⣿⡄⣿⡎⣇⠣⢈⠀⠀⣠⣶⢸⣿⣴⡎⣿⣿⣿⣿⣿⣮⣛⣡⠸⢘⠠⠃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⡇⡗⠀⣿⠀⡋⠁⢸⣷⡹⣆⢹⣆⠀⠿⣿⣷⣭⣯⣴⣿⣿⣿⣿⣷⢹⣿⣿⣷⠈⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⢧⠇⠀⡟⠀⢳⢛⡄⢿⣧⢻⡌⢿⣿⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⢀⠘⢦⡀⠛⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠿⢡⠟⣜⡄⠂⣿⠀⠄⢪⡳⠌⢿⣇⢳⡌⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢛⣃⡻⣿⡟⠨⠘⢦⣌⣑⠀⠉⠛⠛⢁⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣏⣿⣿⣿⣨⡮⠟⢀⢣⢸⡘⡘⣷⠉⠛⡈⢿⣧⠹⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⡿⢊⡄⠀⠀⠢⣬⣭⣭⣭⣥⣶⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠔⡸⢸⡆⢷⠡⠘⠁⡇⡇⠘⢿⣷⡘⢆⠙⠻⠿⠿⣿⣿⣿⣿⣿⣿⠟⢱⠸⠁⠻⢶⣶⣄⠛⢿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣷⣦⠿⢿⣿⣿⣿⡿⢿⣰⠞⡼⢣⣿⠁⢀⠳⡁⡘⠠⠇⠚⠊⠹⢿⣮⡱⢌⡻⢷⣶⡄⠰⠲⠶⣄⠺⠀⡠⢁⠡⣆⠨⠻⣿⡄⠀⣉⠁⠀⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⡍⠘⣝⣿⣛⡽⠛⣩⢞⣵⡿⠁⡀⡍⠐⠉⠢⣀⠀⠀⠀⠀⡶⣝⡻⢦⣉⡒⠭⠁⠀⠀⠀⠀⠐⠊⢴⡌⢒⠉⠶⣦⡘⣿⡄⠀⢚⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣦⣀⠐⣒⣚⣭⣶⠿⠋⢀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢠⣤⣬⣛⠿⣷⣶⣶⣶⠆⣦⠀⠀⠀⠀⠀⢀⡾⣛⡛⣿⣝⢷⡮⠃⠀⠘⡂⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⠞⡡⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⣮⡻⣿⣿⣿⣷⣶⡮⠁⠈⠛⣇⠀⠀⠀⠀⠀⠠⡟⠻⠮⠛⠂⠁⠀⠀⠀⢅⣋⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡛⠋⠁⠬⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠈⠻⣶⣿⣿⣿⡟⠸⠄⠁⠀⠌⠣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⢴⣦⢤⣀⠀⠀⠀⠀⠀⠀⠀⠨⣝⡻⠃⡈⠥⠀⠀⠰⢬⣍⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡛⣿⣿⣿⣛⣿⣿⣿⣿⣿
⣿⡿⣻⣿⣿⣿⢿⣿⣿⡿⠟⠁⠀⠀⠀⠙⣷⡻⡇⠀⠀⠀⠀⠀⠀⠀⠈⠁⠋⠀⠀⠁⠀⠀⠀⠐⣊⣴⠀⠀⠀⠀⠀⠀⣰⣶⣰⣶⡀⠀⠀⠘⠄⣛⣶⣿⣿⣿⣿⣿⣿
⣿⣷⣝⣿⣿⣏⣾⣿⡟⠀⠀⠀⠀⠀⠀⠀⠹⣿⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠻⣿⣧⠀⠀⠀⠀⠀⠻⢿⣿⡿⠃⠀⠀⠀⠀⠃⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣷⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠙⣿⡆⠀⠀⠀⠀⠀⠀⠋⠀⠒⠀⠀⠀⠀⠘⠃⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡂⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣇⣀⢀⣀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⡀⠀⠘⢾⣿⡇⠀⠀⠀⠀⠈⠉⠁⢀⡀⠄⠀⠀⠀⠀⠉⢏⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡗⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⠀⠈⢿⣿⠀⠀⠀⢲⡶⠂⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡟⠹⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡇⠐⠆⠘⣿⡄⠀⠀⢼⡇⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠩⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢟⡃⠀⠀⢰⣿⡇⠀⠀⠀⠻⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢙⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠿⠧⠀⠀⠀⢀⠀⠀⠀⠀⠀⢰⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠘⢛⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣎⣿
⣿⣿⣿⣿⣿⣿⣷⡘⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢓⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⠀⠀⠀⣘⡛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿
⣿⣿⣿⣿⣿⣿⣿⣷⡜⠇⠀⠀⠀⠀⠀⠀⠀⠀⢸⢰⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠘⠀⣽⣿⡇⠀⠀⠀⠀⠀⢐⣢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⠳
⣿⣿⣿⣿⣿⣿⣿⡿⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⡘⣒⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⢾⣿⠇⠀⠀⠀⠀⠀⢎⣷⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏"""

BANNER_STOPS = [
    (0.00, (0,   255, 220)),
    (0.35, (80,  140, 255)),
    (0.70, (200,  70, 220)),
    (1.00, (255, 180,  80)),
]

def _lerp(a, b, t): return int(a + (b - a) * t)

def _gradient_at(t):
    t = max(0.0, min(1.0, t))
    for i in range(len(BANNER_STOPS) - 1):
        p1, c1 = BANNER_STOPS[i]
        p2, c2 = BANNER_STOPS[i + 1]
        if p1 <= t <= p2:
            span = (p2 - p1) or 1.0
            local = (t - p1) / span
            return (_lerp(c1[0], c2[0], local),
                    _lerp(c1[1], c2[1], local),
                    _lerp(c1[2], c2[2], local))
    return BANNER_STOPS[-1][1]

def print_banner(console):
    term_w = console.size.width
    term_h = console.size.height

    if term_w < 40 or term_h < 16:
        console.print("[bold cyan]⚡ Prodigy Stego Hunter v3.0 ⚡[/bold cyan]")
        console.print("[dim]Recon · Extract · Analyze · Conquer[/dim]\n")
        return

    lines = [l for l in BANNER_ART.splitlines()]
    while lines and not lines[0].strip(): lines.pop(0)
    while lines and not lines[-1].strip(): lines.pop()
    if not lines: return

    art_h = len(lines)
    art_w = max(len(l) for l in lines)
    max_h = max(6, term_h - 8)
    max_w = max(30, term_w - 2)

    if art_h > max_h:
        step = art_h / max_h
        lines = [lines[min(int(i * step), art_h - 1)] for i in range(max_h)]
        art_h = len(lines)
    if art_w > max_w:
        crop = (art_w - max_w) // 2
        lines = [l[crop:crop + max_w] for l in lines]
        art_w = max_w

    text = Text()
    denom_w = max(1, art_w - 1)
    denom_h = max(1, art_h - 1)
    for y, line in enumerate(lines):
        pad = max(0, (term_w - len(line)) // 2)
        if pad: text.append(" " * pad)
        for x, ch in enumerate(line):
            if ch.isspace():
                text.append(ch); continue
            t = (x / denom_w) * 0.65 + (y / denom_h) * 0.35
            r, g, b = _gradient_at(t)
            text.append(ch, style=f"rgb({r},{g},{b})")
        text.append("\n")
    console.print(text)

    subtitle = "⚡  P R O D I G Y   S T E G O   H U N T E R  ⚡"
    sub = Text()
    sub_pad = max(0, (term_w - len(subtitle)) // 2)
    sub.append(" " * sub_pad)
    denom_s = max(1, len(subtitle) - 1)
    for i, ch in enumerate(subtitle):
        r, g, b = _gradient_at(i / denom_s)
        sub.append(ch, style=f"bold rgb({r},{g},{b})")
    console.print(sub)

    tagline = "v3.0  ·  Recon · Decode · Extract · Crack"
    tag_pad = max(0, (term_w - len(tagline)) // 2)
    console.print(f"[dim]{' ' * tag_pad}{tagline}[/dim]\n")


# ─── Standalone helpers ──────────────────────────────────────
def entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parse_png_chunks(path: Path):
    try:
        with open(path, "rb") as f:
            if f.read(8) != b"\x89PNG\r\n\x1a\n": return
            while True:
                header = f.read(8)
                if len(header) < 8: break
                length, ctype = struct.unpack(">I4s", header)
                if length > 50_000_000: break
                data = f.read(length); f.read(4)
                yield ctype.decode("latin-1", errors="replace"), data
                if ctype == b"IEND": break
    except Exception:
        return


def find_trailing_data(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except Exception:
        return b""
    suffix = path.suffix.lower()
    if suffix == ".png":
        idx = data.rfind(b"IEND")
        if idx != -1 and idx + 8 < len(data): return data[idx + 8:]
    elif suffix in (".jpg", ".jpeg"):
        idx = data.rfind(b"\xff\xd9")
        if idx != -1 and idx + 2 < len(data): return data[idx + 2:]
    elif suffix == ".gif":
        idx = data.rfind(b"\x3b")
        if idx != -1 and idx + 1 < len(data): return data[idx + 1:]
    return b""


def try_decode_chain(data: bytes, depth: int = 3):
    """Recursive decode: base64 → zlib → gzip → hex. Returns [(method, bytes)]."""
    out = []
    if depth <= 0 or not data:
        return out

    # zlib
    try:
        d = zlib.decompress(data)
        out.append(("zlib", d))
        out.extend(try_decode_chain(d, depth - 1))
    except Exception: pass

    # gzip
    try:
        d = gzip.decompress(data)
        out.append(("gzip", d))
        out.extend(try_decode_chain(d, depth - 1))
    except Exception: pass

    # base64
    try:
        txt = data.decode("ascii", errors="ignore").strip()
        if len(txt) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", txt):
            d = base64.b64decode(txt, validate=False)
            out.append(("base64", d))
            out.extend(try_decode_chain(d, depth - 1))
    except Exception: pass

    # hex
    try:
        txt = data.decode("ascii", errors="ignore").strip().replace("\n", "").replace(" ", "")
        if len(txt) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", txt) and len(txt) % 2 == 0:
            d = bytes.fromhex(txt)
            out.append(("hex", d))
            out.extend(try_decode_chain(d, depth - 1))
    except Exception: pass

    return out


def xor_brute(data: bytes, patterns, max_keys: int = 256):
    """Try single-byte XOR 1..255; return [(key, decoded_str)] with pattern hits."""
    hits = []
    sample = data[:2048]
    for k in range(1, min(max_keys, 256)):
        xored = bytes(b ^ k for b in sample)
        try:
            txt = xored.decode("latin-1")
        except Exception:
            continue
        for p in patterns:
            if re.search(p, txt):
                hits.append((k, txt[:500]))
                break
    return hits


def rotate_bits(data: bytes, patterns):
    """Try bit rotation 1..7 on the whole bitstream; look for patterns."""
    hits = []
    bits = "".join(f"{b:08b}" for b in data[:4096])
    for r in range(1, 8):
        rot = bits[r:] + bits[:r]
        n = (len(rot) // 8) * 8
        try:
            b = bytes(int(rot[i:i+8], 2) for i in range(0, n, 8))
            txt = b.decode("latin-1", errors="ignore")
        except Exception:
            continue
        for p in patterns:
            if re.search(p, txt):
                hits.append((r, txt[:500]))
                break
    return hits


# ─── Main engine ─────────────────────────────────────────────
class Prodigy:
    def __init__(self, args):
        self.image       = Path(args.image).resolve()
        self.wordlist    = Path(args.wordlist).resolve() if args.wordlist else DEFAULT_WORDLIST
        self.basic_only  = args.info
        self.skip_brute  = args.no_brute
        self.skip_xor    = args.no_xor
        self.verbose     = args.verbose
        self.output_file = Path(args.output).resolve() if args.output else None
        self.json_file   = Path(args.json).resolve() if args.json else None
        self.timeout     = args.timeout
        self.early_exit  = not args.no_early_exit
        self.max_depth   = args.recursive

        if args.flag_format:
            self.patterns = [args.flag_format]
        else:
            self.patterns = list(FLAG_BANK)

        self.flags:    set[str]              = set()
        self.findings: list[tuple[str, str]] = []
        self.module_status: list[tuple[str, str]] = []   # (module, status)
        self.artifacts_dir = self.image.parent / "prodigy_artifacts"
        self.start_time = datetime.now()
        self.found_flag = False

    # ── early exit check ─────────────────────────────────────
    def _early_stop(self) -> bool:
        return self.found_flag and self.early_exit

    # ── recording ────────────────────────────────────────────
    def _harvest(self, text: str, source: str = ""):
        """Scan text with all patterns; add new flags; return count found."""
        count = 0
        for pat in self.patterns:
            for m in re.findall(pat, text):
                if m not in self.flags:
                    self.flags.add(m)
                    self.found_flag = True
                    tag = f" ({source})" if source else ""
                    console.print(
                        f"  [bold green]⚑ FLAG{tag}:[/bold green] [green]{m}[/green]")
                    count += 1
        return count

    def _record(self, tool: str, output):
        if not output: return
        text = str(output).strip()
        self.findings.append((tool, text[:8000]))
        self._harvest(text, tool)

        # passphrase from stegseek
        for m in re.finditer(r'found passphrase:\s*"?(.*?)"?\s*$', text, re.I | re.M):
            p = m.group(1).strip()
            key = f"PASSPHRASE: {p}"
            if key not in self.flags:
                self.flags.add(key)
                self.found_flag = True
                console.print(f"  [bold yellow]🔑 PASSPHRASE:[/bold yellow] [yellow]{p}[/yellow]")

        # auto-decode attempt on string-like content
        try:
            self._auto_decode(text, tool)
        except Exception:
            pass

        if self.verbose:
            console.print(Panel(text[:3000], title=f"[dim]{tool}[/dim]",
                                border_style="dim", expand=False))

    def _auto_decode(self, text: str, source: str):
        """Try chained decode + XOR brute on any base64/hex blocks in text."""
        # check whole text as bytes first
        blobs = []
        blobs.extend(re.findall(r"[A-Za-z0-9+/=]{20,}", text))
        blobs.extend(re.findall(r"\b[0-9a-fA-F]{24,}\b", text))
        if not blobs: return

        for blob in blobs[:5]:
            try:
                raw = base64.b64decode(blob, validate=False) \
                    if re.fullmatch(r"[A-Za-z0-9+/=]+", blob) \
                    else bytes.fromhex(blob)
            except Exception:
                continue

            # chained decodes
            for method, decoded in try_decode_chain(raw, depth=3):
                try:
                    dtext = decoded.decode("latin-1", errors="ignore")
                except Exception:
                    continue
                self._harvest(dtext, f"{source}/{method}")

            # XOR brute
            for key, xtext in xor_brute(raw, self.patterns):
                self._harvest(xtext, f"{source}/xor-{key}")

    def _run(self, cmd, timeout=None):
        if not shutil.which(cmd[0]): return None
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout or self.timeout, errors="ignore")
            return (r.stdout or "") + "\n" + (r.stderr or "")
        except subprocess.TimeoutExpired:
            return f"[timeout after {timeout or self.timeout}s]"
        except Exception as e:
            return f"[error: {e}]"

    def _section(self, num, total, title):
        console.print(f"\n[bold cyan]▶ [{num}/{total}] {title}[/bold cyan]")

    def _ok(self, msg):   console.print(f"  [green]✓[/green] {msg}")
    def _warn(self, msg): console.print(f"  [yellow]![/yellow] {msg}")
    def _fail(self, msg): console.print(f"  [red]✗[/red] {msg}")
    def _info(self, msg): console.print(f"  [dim]•[/dim] {msg}")
    def _skip(self, msg): console.print(f"  [magenta]↷[/magenta] [dim]{msg}[/dim]")

    def _mark(self, name: str, status: str):
        self.module_status.append((name, status))

    # ────────────────────────────────────────────────────────
    # SCAN MODULES
    # ────────────────────────────────────────────────────────
    def scan_recon(self):
        self._section(1, 11, "File Reconnaissance")
        out = self._run(["file", "-b", str(self.image)])
        if out:
            self._ok(f"file: {out.strip()}")
            self._record("file", out)

        try:
            data = self.image.read_bytes()
            ent = entropy(data[: 2 * 1024 * 1024])
            self._info(f"size: {len(data):,} bytes    entropy: {ent:.3f}")
            if ent > 7.9:
                self._warn("very high entropy — file may be encrypted/compressed")
        except Exception as e:
            self._fail(f"read failed: {e}")

        trailer = find_trailing_data(self.image)
        if trailer:
            self._warn(f"trailing data after EOF: {len(trailer)} bytes")
            self._info(f"preview: {trailer[:80]!r}")
            self.artifacts_dir.mkdir(exist_ok=True)
            (self.artifacts_dir / "trailing_data.bin").write_bytes(trailer)
            self._ok(f"saved → {self.artifacts_dir / 'trailing_data.bin'}")
            for marker in (b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"flag{"):
                if marker in trailer:
                    self._warn(f"marker {marker!r} found in trailing data")
            # harvest + auto-decode trailing data
            self._record("trailing-data", trailer[:2000].decode("latin-1", errors="replace"))
            for method, decoded in try_decode_chain(trailer, depth=3):
                self._harvest(decoded.decode("latin-1", errors="ignore"),
                              f"trailing/{method}")
        else:
            self._ok("no trailing data after EOF")

        self._mark("Recon", "done")

    def scan_metadata(self):
        self._section(2, 11, "Metadata & Text Chunks")
        if shutil.which("exiftool"):
            out = self._run(["exiftool", "-a", "-G1", str(self.image)])
            if out:
                self._record("exiftool", out)
                self._ok("exiftool metadata collected")
                for line in out.splitlines():
                    if re.search(r"(comment|description|title|author|usercomment|xpcomment)",
                                 line, re.I):
                        self._info(line.strip()[:160])
        else:
            self._warn("exiftool not installed")

        if self.image.suffix.lower() == ".png":
            found = False
            for ctype, data in parse_png_chunks(self.image):
                if ctype in ("tEXt", "zTXt", "iTXt"):
                    found = True
                    try:
                        text = data.split(b"\x00", 1)[-1].decode("latin-1", errors="replace")
                    except Exception:
                        text = repr(data[:200])
                    self._info(f"{ctype}: {text[:200]}")
                    self._record(f"png-{ctype}", text)
            if not found:
                self._ok("no PNG text chunks")

        if shutil.which("exiftool") and self.image.suffix.lower() in (".jpg", ".jpeg", ".tif", ".tiff"):
            thumb = self.artifacts_dir / "exif_thumbnail.jpg"
            self.artifacts_dir.mkdir(exist_ok=True)
            out = self._run(["exiftool", "-b", "-ThumbnailImage", str(self.image)])
            if out and len(out) > 100 and not out.startswith("["):
                try:
                    thumb.write_bytes(out.encode("latin-1"))
                    self._ok(f"EXIF thumbnail extracted → {thumb}")
                except Exception:
                    pass

        self._mark("Metadata", "done")

    def scan_strings(self):
        self._section(3, 11, "String Extraction + XOR Brute")
        out = self._run(["strings", "-n", "5", str(self.image)])
        if not out:
            self._fail("strings not available")
            self._mark("Strings", "unavailable")
            return

        hits = [l for l in out.splitlines() if any(re.search(p, l) for p in self.patterns)]
        if hits:
            self._ok(f"{len(hits)} flag-like string(s) found")
            for h in hits[:20]:
                console.print(f"      [green]{h.strip()}[/green]")

        markers = [m for m in out.splitlines()
                   if re.search(r"(flag|ctf|key|pass|secret|admin|root)", m, re.I)][:20]
        if markers:
            self._info(f"{len(markers)} keyword hits (showing 20):")
            for m in markers:
                console.print(f"      [dim]{m.strip()[:120]}[/dim]")

        # XOR brute over the raw strings payload
        raw = out.encode("latin-1", errors="ignore")
        xhits = xor_brute(raw, self.patterns)
        if xhits:
            self._ok(f"XOR brute found {len(xhits)} candidate(s)")
            for k, txt in xhits[:3]:
                self._harvest(txt, f"strings/xor-{k}")

        self._record("strings", "\n".join(hits or markers))
        self._mark("Strings", "done")

    def scan_binwalk(self):
        self._section(4, 11, "Embedded File Detection (binwalk)")
        if not shutil.which("binwalk"):
            self._warn("binwalk not installed")
            self._mark("Binwalk", "unavailable")
            return

        out = self._run(["binwalk", str(self.image)], timeout=60)
        extracted_count = 0
        if out:
            self._record("binwalk", out)
            sigs = [l for l in out.splitlines() if re.match(r"^\d+", l.strip())]
            if sigs:
                self._warn(f"{len(sigs)} embedded signature(s)")
                for s in sigs[:8]:
                    self._info(s.strip()[:140])
            else:
                self._ok("no embedded signatures")

        if not self.basic_only:
            extract_dir = self.artifacts_dir / "binwalk"
            self.artifacts_dir.mkdir(exist_ok=True)
            self._run(["binwalk", "-e", "--directory", str(extract_dir), str(self.image)],
                      timeout=120)
            if extract_dir.exists():
                for p in extract_dir.rglob("*"):
                    if p.is_file():
                        extracted_count += 1
                        self._scan_extracted(p)
                self._ok(f"extracted {extracted_count} file(s) → {extract_dir}")

        self._mark("Binwalk", f"{extracted_count} files" if extracted_count else "done")

    def _scan_extracted(self, path: Path, depth: int = 1):
        """Recursively scan an extracted file for flags."""
        if depth > self.max_depth: return
        try:
            data = path.read_bytes()
        except Exception:
            return

        # direct scan
        try:
            text = data.decode("latin-1", errors="ignore")
        except Exception:
            text = ""
        self._harvest(text, f"extracted:{path.name}")

        # chained decode
        for method, decoded in try_decode_chain(data, depth=3):
            self._harvest(decoded.decode("latin-1", errors="ignore"),
                          f"extracted:{path.name}/{method}")

        # XOR brute
        for k, txt in xor_brute(data, self.patterns):
            self._harvest(txt, f"extracted:{path.name}/xor-{k}")

    def scan_png_integrity(self):
        self._section(5, 11, "PNG Structure Check")
        if self.image.suffix.lower() != ".png":
            self._skip("not a PNG")
            self._mark("PNG Check", "skipped")
            return
        if not shutil.which("pngcheck"):
            self._warn("pngcheck not installed")
            self._mark("PNG Check", "unavailable")
            return
        out = self._run(["pngcheck", "-v", str(self.image)])
        if out:
            self._record("pngcheck", out)
            self._ok("pngcheck complete")
            for line in out.splitlines():
                if re.search(r"(error|warning|extra|unknown)", line, re.I):
                    self._warn(line.strip())
        self._mark("PNG Check", "done")

    def scan_lsb(self):
        self._section(6, 11, "LSB / Bit-Plane Analysis")
        if shutil.which("zsteg") and not self.basic_only:
            out = self._run(["zsteg", "-a", str(self.image)], timeout=180)
            if out:
                self._record("zsteg", out)
                self._ok("zsteg -a complete")
        elif not self.basic_only:
            self._warn("zsteg not installed (gem install zsteg)")

        if not (HAS_NUMPY and HAS_PIL):
            self._warn("numpy/PIL missing — skipping custom LSB")
            self._mark("LSB", "partial")
            return

        try:
            img = Image.open(self.image).convert("RGBA")
            arr = np.array(img)

            for order_name, reverse in (("LSB-first", False), ("MSB-first", True)):
                bits = (arr[:, :, :4] & 1).flatten().astype(np.uint8)
                if reverse:
                    bits = bits.reshape(-1, 8)[:, ::-1].flatten()
                n = (len(bits) // 8) * 8
                data = np.packbits(bits[:n]).tobytes()
                preview = data[:4096].decode("latin-1", errors="ignore")
                self._record(f"custom-LSB-{order_name}", preview)
                self._harvest(preview, f"lsb-{order_name}")

                # chained decode
                for method, decoded in try_decode_chain(data[:16384], depth=3):
                    self._harvest(decoded.decode("latin-1", errors="ignore"),
                                  f"lsb-{order_name}/{method}")

                # XOR brute
                for k, txt in xor_brute(data[:4096], self.patterns):
                    self._harvest(txt, f"lsb-{order_name}/xor-{k}")

                # bit rotation
                for r, txt in rotate_bits(data[:2048], self.patterns):
                    self._harvest(txt, f"lsb-{order_name}/rot{r}")

            self._ok("custom LSB extraction complete (2 orders)")
            self._mark("LSB", "done")
        except Exception as e:
            self._fail(f"custom LSB failed: {e}")
            self._mark("LSB", "error")

    def scan_visuals(self):
        self._section(7, 11, "Visual Artifacts (bit-planes, channels, XOR)")
        if not (HAS_NUMPY and HAS_PIL):
            self._warn("numpy/PIL missing — skipping visual dumps")
            self._mark("Visuals", "unavailable")
            return
        self.artifacts_dir.mkdir(exist_ok=True)
        try:
            img = Image.open(self.image).convert("RGB")
            arr = np.array(img)

            for i, cname in enumerate("RGB"):
                z = np.zeros_like(arr)
                z[:, :, i] = arr[:, :, i]
                Image.fromarray(z).save(self.artifacts_dir / f"channel_{cname}.png")

            for ch, cname in enumerate("RGB"):
                for bit in range(8):
                    plane = ((arr[:, :, ch] >> bit) & 1).astype(np.uint8) * 255
                    Image.fromarray(plane).save(self.artifacts_dir / f"bit{bit}_{cname}.png")
            self._ok(f"24 bit-planes + 3 channels → {self.artifacts_dir}/")

            if not self.skip_xor:
                r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]
                pairs = {"R^G": r ^ g, "G^B": g ^ b, "R^B": r ^ b, "R^G^B": r ^ g ^ b}
                for name, res in pairs.items():
                    safe = name.replace("^", "_")
                    Image.fromarray(res.astype(np.uint8)).save(
                        self.artifacts_dir / f"xor_{safe}.png")
                inv = 255 - arr
                Image.fromarray(inv.astype(np.uint8)).save(self.artifacts_dir / "inverted.png")
                self._ok("XOR composites + inverted generated")
            self._mark("Visuals", "done")
        except Exception as e:
            self._fail(f"visual dump failed: {e}")
            self._mark("Visuals", "error")

    def scan_gif_frames(self):
        self._section(8, 11, "GIF Frame Extraction")
        if self.image.suffix.lower() != ".gif":
            self._skip("not a GIF")
            self._mark("GIF", "skipped")
            return
        if not HAS_PIL:
            self._warn("PIL missing")
            self._mark("GIF", "unavailable")
            return
        try:
            img = Image.open(self.image)
            self.artifacts_dir.mkdir(exist_ok=True)
            frames_dir = self.artifacts_dir / "gif_frames"
            frames_dir.mkdir(exist_ok=True)
            n = 0
            while True:
                try:
                    img.seek(n)
                    img.convert("RGBA").save(frames_dir / f"frame_{n:03d}.png")
                    n += 1
                except EOFError:
                    break
            self._ok(f"{n} frame(s) extracted → {frames_dir}")
            self._mark("GIF", f"{n} frames")
        except Exception as e:
            self._fail(f"GIF extraction failed: {e}")
            self._mark("GIF", "error")

    def scan_archive_crack(self):
        self._section(9, 11, "Embedded Archive Cracking")
        if self.basic_only:
            self._skip("basic mode")
            self._mark("Archive", "skipped")
            return
        if not self.wordlist or not self.wordlist.exists():
            self._warn("no wordlist available for archive cracking")
            self._mark("Archive", "no wordlist")
            return

        # find any archives we already extracted or embedded in the image
        candidates = []
        if self.artifacts_dir.exists():
            candidates.extend(
                list(self.artifacts_dir.rglob("*.zip")) +
                list(self.artifacts_dir.rglob("*.rar")) +
                list(self.artifacts_dir.rglob("*.7z"))
            )
        # also try carving from raw image
        try:
            raw = self.image.read_bytes()
            if b"PK\x03\x04" in raw:
                zips_dir = self.artifacts_dir / "carved_zips"
                zips_dir.mkdir(parents=True, exist_ok=True)
                idx = 0
                pos = 0
                while True:
                    pos = raw.find(b"PK\x03\x04", pos)
                    if pos == -1: break
                    end = raw.find(b"PK\x05\x06", pos)
                    if end != -1:
                        end += 22
                        zf = zips_dir / f"carved_{idx}.zip"
                        zf.write_bytes(raw[pos:end])
                        candidates.append(zf)
                        idx += 1
                    pos += 4
                if idx:
                    self._ok(f"carved {idx} zip candidate(s) from image")
        except Exception:
            pass

        if not candidates:
            self._info("no embedded archives found")
            self._mark("Archive", "none")
            return

        cracked_any = False
        for arch in candidates[:10]:
            self._info(f"trying: {arch.name}")
            pwd = self._crack_single_archive(arch)
            if pwd is not None:
                self._ok(f"cracked {arch.name} with [bold]{pwd if pwd else '(empty)'}[/bold]")
                self.flags.add(f"ARCHIVE-PASS: {pwd if pwd else '(empty)'}")
                cracked_any = True
                # extract and rescan
                out_dir = arch.parent / f"{arch.stem}_extracted"
                out_dir.mkdir(exist_ok=True)
                self._extract_zip(arch, pwd or "", out_dir)
                for p in out_dir.rglob("*"):
                    if p.is_file():
                        self._scan_extracted(p)
        self._mark("Archive", "cracked" if cracked_any else "none found")

    def _crack_single_archive(self, arch: Path):
        """Try empty then wordlist. Return password or None."""
        try:
            import zipfile
            if not zipfile.is_zipfile(arch): return None
            with zipfile.ZipFile(arch) as zf:
                names = zf.namelist()
                if not names: return None
                target = names[0]
                # empty first
                try:
                    zf.read(target, pwd=b"")
                    return ""
                except Exception:
                    pass
                # wordlist
                try:
                    words = self.wordlist.read_text(errors="ignore").splitlines()
                except Exception:
                    return None
                for w in words:
                    w = w.strip()
                    if not w: continue
                    try:
                        zf.read(target, pwd=w.encode())
                        return w
                    except Exception:
                        continue
        except Exception:
            return None
        return None

    def _extract_zip(self, arch: Path, pwd: str, out_dir: Path):
        try:
            import zipfile
            with zipfile.ZipFile(arch) as zf:
                zf.extractall(out_dir, pwd=pwd.encode() if pwd else None)
        except Exception:
            pass

    def scan_steghide_quick(self):
        self._section(10, 11, "Steghide — Quick-Win Passwords")
        if not shutil.which("steghide"):
            self._warn("steghide not installed")
            self._mark("Steghide Quick", "unavailable")
            return
        if self.image.suffix.lower() not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
            self._skip(f"steghide may not support {self.image.suffix}")

        out_file = self.artifacts_dir / "steghide_out"
        self.artifacts_dir.mkdir(exist_ok=True)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Trying common passwords...",
                                     total=len(COMMON_PASSWORDS))
            for pwd in COMMON_PASSWORDS:
                if out_file.exists():
                    try: out_file.unlink()
                    except Exception: pass
                try:
                    r = subprocess.run(
                        ["steghide", "extract", "-sf", str(self.image),
                         "-p", pwd, "-f", "-xf", str(out_file)],
                        capture_output=True, text=True, timeout=8
                    )
                    if r.returncode == 0 and out_file.exists():
                        progress.stop()
                        pwd_disp = pwd if pwd else "(empty)"
                        self._ok(f"passphrase cracked: [bold]{pwd_disp}[/bold]")
                        self.flags.add(f"PASSPHRASE: {pwd_disp}")
                        self.found_flag = True
                        data = out_file.read_bytes()
                        text = data.decode("latin-1", errors="ignore")
                        self._record("steghide-quick", f"pwd={pwd_disp}\n{text}")
                        # chained decode + xor on payload
                        for method, dec in try_decode_chain(data, depth=3):
                            self._harvest(dec.decode("latin-1", errors="ignore"),
                                          f"steghide/{method}")
                        for k, txt in xor_brute(data, self.patterns):
                            self._harvest(txt, f"steghide/xor-{k}")
                        self._mark("Steghide Quick", f"cracked: {pwd_disp}")
                        return
                except subprocess.TimeoutExpired:
                    pass
                progress.advance(task)

        self._info("no match in common list")
        self._mark("Steghide Quick", "no hit")

    def scan_brute_force(self):
        self._section(11, 11, "Steghide Brute Force (wordlist)")
        if self.skip_brute:
            self._skip("--no-brute")
            self._mark("Brute Force", "skipped")
            return
        if not self.wordlist:
            self._warn("no wordlist")
            self._mark("Brute Force", "no wordlist")
            return
        if not self.wordlist.exists():
            self._warn(f"wordlist not found: {self.wordlist}")
            self._mark("Brute Force", "wordlist missing")
            return

        self._info(f"wordlist: {self.wordlist}")

        if shutil.which("stegseek"):
            self._ok("using stegseek (recommended)")
            out_file = self.image.parent / f"{self.image.name}.out"
            if out_file.exists():
                try: out_file.unlink()
                except Exception: pass
            cmd = ["stegseek", "--crack", str(self.image), str(self.wordlist)]
            with console.status("[cyan]stegseek cracking...", spinner="dots"):
                out = self._run(cmd, timeout=3600)
            if out:
                self._record("stegseek", out)
                if re.search(r"found passphrase", out, re.I):
                    self._ok("stegseek finished successfully")
                    self.found_flag = True
                else:
                    self._warn("stegseek completed without a hit")
            if out_file.exists():
                data = out_file.read_bytes()
                text = data.decode("latin-1", errors="ignore")
                self._record("stegseek-extracted", text)
                self._ok(f"extracted payload → {out_file}")
                for method, dec in try_decode_chain(data, depth=3):
                    self._harvest(dec.decode("latin-1", errors="ignore"),
                                  f"stegseek/{method}")
                for k, txt in xor_brute(data, self.patterns):
                    self._harvest(txt, f"stegseek/xor-{k}")
            self._mark("Brute Force", "done")
            return

        if not shutil.which("steghide"):
            self._warn("neither stegseek nor steghide available")
            self._mark("Brute Force", "unavailable")
            return

        self._warn("stegseek missing — using slow steghide loop")
        try:
            passwords = [p.strip() for p in
                         self.wordlist.read_text(errors="ignore").splitlines()
                         if p.strip()]
        except Exception as e:
            self._fail(f"could not read wordlist: {e}")
            self._mark("Brute Force", "error")
            return

        if not passwords:
            self._fail("wordlist empty")
            self._mark("Brute Force", "empty")
            return

        out_file = self.artifacts_dir / "brute_out"
        self.artifacts_dir.mkdir(exist_ok=True)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task(f"[cyan]Cracking {len(passwords)} words...",
                                     total=len(passwords))
            for pwd in passwords:
                if out_file.exists():
                    try: out_file.unlink()
                    except Exception: pass
                try:
                    r = subprocess.run(
                        ["steghide", "extract", "-sf", str(self.image),
                         "-p", pwd, "-f", "-xf", str(out_file)],
                        capture_output=True, text=True, timeout=8
                    )
                    if r.returncode == 0 and out_file.exists():
                        progress.stop()
                        self._ok(f"PASSPHRASE FOUND: [bold]{pwd}[/bold]")
                        self.flags.add(f"PASSPHRASE: {pwd}")
                        self.found_flag = True
                        data = out_file.read_bytes()
                        text = data.decode("latin-1", errors="ignore")
                        self._record("steghide-brute", f"pwd={pwd}\n{text}")
                        for method, dec in try_decode_chain(data, depth=3):
                            self._harvest(dec.decode("latin-1", errors="ignore"),
                                          f"steghide/{method}")
                        for k, txt in xor_brute(data, self.patterns):
                            self._harvest(txt, f"steghide/xor-{k}")
                        self._mark("Brute Force", f"cracked: {pwd}")
                        return
                except subprocess.TimeoutExpired:
                    pass
                progress.advance(task)

        self._warn("no passphrase matched")
        self._mark("Brute Force", "no hit")

    # ── outputs ──────────────────────────────────────────────
    def write_report(self):
        if not self.output_file: return
        lines = [
            "=" * 72,
            "Prodigy Stego Hunter v3.0 — Analysis Report",
            "=" * 72,
            f"Target : {self.image}",
            f"Started: {self.start_time.isoformat()}",
            f"Ended  : {datetime.now().isoformat()}",
            f"Early exit: {self.early_exit}   Flag found: {self.found_flag}",
            "",
            "=== FLAGS / PASSPHRASES ===",
        ]
        if self.flags:
            for f in sorted(self.flags): lines.append(f"  ⚑ {f}")
        else:
            lines.append("  (none)")
        lines += ["", "=== MODULE STATUS ==="]
        for name, status in self.module_status:
            lines.append(f"  {name:<18} {status}")
        lines += ["", "=== RAW FINDINGS ==="]
        for tool, out in self.findings:
            lines.append(f"\n----- {tool} -----")
            lines.append(out)
        try:
            self.output_file.write_text("\n".join(lines), encoding="utf-8")
            console.print(f"\n[green]✓ Report written → {self.output_file}[/green]")
        except Exception as e:
            console.print(f"[red]✗ could not write report: {e}[/red]")

    def write_json(self):
        if not self.json_file: return
        payload = {
            "target": str(self.image),
            "started": self.start_time.isoformat(),
            "ended": datetime.now().isoformat(),
            "flags": sorted(self.flags),
            "found_flag": self.found_flag,
            "modules": [{"name": n, "status": s} for n, s in self.module_status],
            "findings": [{"tool": t, "output": o[:4000]} for t, o in self.findings],
        }
        try:
            self.json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"[green]✓ JSON written → {self.json_file}[/green]")
        except Exception as e:
            console.print(f"[red]✗ could not write JSON: {e}[/red]")

    def print_summary_table(self):
        table = Table(title="Run Summary", border_style="cyan", show_lines=False)
        table.add_column("Module", style="cyan")
        table.add_column("Status", style="white")
        for name, status in self.module_status:
            style = "green" if "cracked" in status or status == "done" else \
                    "yellow" if "skip" in status or "none" in status or "no " in status else \
                    "red" if "error" in status or "unavailable" in status else "white"
            table.add_row(name, f"[{style}]{status}[/{style}]")
        console.print(table)

    # ── orchestrator ─────────────────────────────────────────
    def run(self):
        if not self.image.exists():
            console.print(f"[red]✗ Image not found: {self.image}[/red]")
            sys.exit(1)
        if not HAS_PIL:
            console.print("[yellow]! Pillow not installed — some features skipped[/yellow]")
        if not HAS_NUMPY:
            console.print("[yellow]! NumPy not installed — some features skipped[/yellow]")

        console.print(Panel.fit(
            f"[bold]Target     :[/bold] {self.image}\n"
            f"[bold]Mode       :[/bold] {'Basic (-i)' if self.basic_only else 'Full'}\n"
            f"[bold]Wordlist   :[/bold] {self.wordlist} "
            f"{'[dim](exists)[/dim]' if self.wordlist.exists() else '[red](not found)[/red]'}\n"
            f"[bold]Flag pats  :[/bold] {len(self.patterns)} pattern(s)\n"
            f"[bold]Early exit :[/bold] {self.early_exit}   "
            f"[bold]Recursive:[/bold] {self.max_depth}\n"
            f"[bold]Timeout    :[/bold] {self.timeout}s   "
            f"[bold]Verbose   :[/bold] {self.verbose}",
            title="[cyan]Session[/cyan]", border_style="cyan"))

        # Ordered scan list — early exit checked between each
        scans = [
            self.scan_recon,
            self.scan_metadata,
            self.scan_strings,
            self.scan_binwalk,
            self.scan_png_integrity,
            self.scan_lsb,
            self.scan_visuals,
            self.scan_gif_frames,
        ]
        if not self.basic_only:
            scans += [self.scan_archive_crack, self.scan_steghide_quick, self.scan_brute_force]

        try:
            for scan in scans:
                if self._early_stop():
                    console.print(
                        "\n[bold yellow]⚡ Early exit — flag already captured, "
                        "skipping remaining scans[/bold yellow]")
                    break
                scan()
        except KeyboardInterrupt:
            console.print("\n[yellow]! Interrupted — printing partial results[/yellow]")

        # ── FINAL FLAG PANEL ──
        console.print()
        if self.flags:
            body = "\n".join(f"  [bold green]⚑[/bold green] [green]{f}[/green]"
                             for f in sorted(self.flags))
            console.print(Panel(body,
                                title="[bold green]  ⚑  FLAGS FOUND  ⚑  [/bold green]",
                                border_style="bold green", padding=(1, 2)))
        else:
            console.print(Panel(
                "[yellow]No flags matched the current patterns.[/yellow]\n\n"
                "  • Try a different format:  [cyan]-f \"HTB\\{.*?\\}\"[/cyan]\n"
                "  • Supply a wordlist:       [cyan]-w /path/to/wordlist.txt[/cyan]\n"
                "  • Inspect artifacts:       [cyan]prodigy_artifacts/[/cyan]\n"
                "  • Disable early exit:      [cyan]--no-early-exit[/cyan]\n"
                "  • Deep recursion:          [cyan]--recursive 3[/cyan]",
                title="[yellow]  No flag detected  [/yellow]",
                border_style="yellow", padding=(1, 2)))

        self.print_summary_table()

        if self.artifacts_dir.exists():
            console.print(f"[dim]Artifacts → {self.artifacts_dir}[/dim]")

        self.write_report()
        self.write_json()
        elapsed = (datetime.now() - self.start_time).total_seconds()
        console.print(f"[dim]Elapsed: {elapsed:.1f}s[/dim]\n")


# ─── CLI ─────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="prodigy",
        description="Prodigy Stego Hunter v3.0 — automated CTF image steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python prodigy.py img.png\n"
            "  python prodigy.py img.jpg -w rockyou.txt -f \"HTB\\{.*?\\}\"\n"
            "  python prodigy.py img.png -i -nb -o report.txt\n"
            "  python prodigy.py img.jpg --no-xor --no-brute -v -j out.json\n"
        ))
    p.add_argument("image", help="Path to the challenge image")
    p.add_argument("-w", "--wordlist", metavar="FILE", default=None,
                   help=f"Wordlist (default: {DEFAULT_WORDLIST})")
    p.add_argument("-i", "--info", action="store_true",
                   help="Basic scan only (skip steghide/brute/archive)")
    p.add_argument("-f", "--flag-format", metavar="REGEX", default=None,
                   help="Custom regex (overrides the built-in flag bank)")
    p.add_argument("-o", "--output", metavar="FILE", default=None,
                   help="Write full text report")
    p.add_argument("-j", "--json", metavar="FILE", default=None,
                   help="Write JSON report")
    p.add_argument("-nb", "--no-banner", action="store_true",
                   help="Suppress the banner")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every tool's raw output")
    p.add_argument("--no-early-exit", action="store_true",
                   help="Continue all scans even after a flag is found")
    p.add_argument("--no-brute", action="store_true",
                   help="Skip the wordlist brute-force stage")
    p.add_argument("--no-xor", action="store_true",
                   help="Skip XOR channel composite generation")
    p.add_argument("--recursive", type=int, default=2,
                   help="Recursion depth for extracted files (default: 2)")
    p.add_argument("--timeout", type=int, default=180,
                   help="Per-tool timeout in seconds (default: 180)")
    return p


def main():
    args = build_parser().parse_args()
    if not args.no_banner:
        print_banner(console)
    try:
        Prodigy(args).run()
    except KeyboardInterrupt:
        console.print("\n[red]✗ Interrupted[/red]")
        sys.exit(130)


if __name__ == "__main__":
    main()