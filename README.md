# Prodigy Stego Hunter v3.0 💀⚡

**An automated CTF image steganography framework** — finds hidden flags in PNG, JPG, GIF, BMP, and TIFF files by running 11+ specialized scanners, decoding chains, brute-forcing passphrases, and cracking embedded archives.

```
    ____            _ _             
   |  _ \ _ __ ___ | (_) __ _ _   _ 
   | |_) | '__/ _ \| | |/ _` | | | |
   |  __/| | | (_) | | | (_| | |_| |
   |_|   |_|  \___/|_|_|\__, |\__, |
                        |___/ |___/ 
        ⚡ Prodigy Stego Hunter v3.0 ⚡
```

---

## Table of Contents

1. [What It Does](#-what-it-does)
2. [Quick Start](#-quick-start)
3. [Installation](#-installation)
4. [Usage — Every Option Explained](#-usage--every-option-explained)
5. [Real-World Examples](#-real-world-examples)
6. [The 11 Scan Modules](#-the-11-scan-modules)
7. [Understanding the Output](#-understanding-the-output)
8. [Artifacts Folder](#-artifacts-folder)
9. [Troubleshooting](#-troubleshooting)
10. [FAQ](#-faq)
11. [How It Works Under the Hood](#-how-it-works-under-the-hood)

---

## 🎯 What It Does

Point it at any image from a CTF challenge. It automatically:

- ✅ **Reads every byte** — file type, size, entropy, trailing data
- ✅ **Extracts metadata** — EXIF, PNG text chunks, comments
- ✅ **Dumps strings** — looking for `flag{...}`, `HTB{...}`, etc.
- ✅ **Finds embedded files** — ZIPs, other images, anything binwalk detects
- ✅ **Checks LSB stego** — bit-plane analysis via zsteg + custom Python
- ✅ **Generates visual artifacts** — 24 bit-planes, XOR composites, channel isolations
- ✅ **Cracks steghide** — common passwords first, then full wordlist via stegseek
- ✅ **Cracks embedded ZIPs** — with rockyou or your custom wordlist
- ✅ **Chains decoders** — base64 → zlib → gzip → hex, recursively
- ✅ **Brute-forces XOR** — tries all 255 single-byte keys on every extracted string
- ✅ **Exits early** — stops the moment a flag is found

**Runs 11 checks in seconds** that would take you 15–30 minutes manually.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install rich pillow numpy

# 2. Run it
python main.py challenge.png
```

That's it. The script auto-uses `/usr/share/wordlists/rockyou.txt` for brute-forcing and looks for `flag{...}` patterns.

**If you see this at the end, you won:**

```
╭─────────  ⚑  FLAGS FOUND  ⚑  ─────────╮
│                                        │
│   ⚑ flag{1_l0v3_st3g0}                 │
│   ⚑ PASSPHRASE: hunter2                │
│                                        │
╰────────────────────────────────────────╯
```

---

## 📦 Installation

### Required Python packages

```bash
pip install rich pillow numpy
```

| Package | Used for |
|---------|----------|
| `rich` | Colored output, progress bars, banners |
| `pillow` | Reading/writing images |
| `numpy` | Fast pixel math, bit-plane extraction |

### Recommended external tools

Install these to unlock every feature. Missing tools just get skipped — the script never crashes.

```bash
# Debian / Ubuntu / Kali
sudo apt update
sudo apt install -y binwalk exiftool steghide pngcheck ruby file strings

# zsteg — the best LSB scanner for PNG/BMP
sudo gem install zsteg
```

| Tool | Purpose | Without it |
|------|---------|-----------|
| `binwalk` | Detects/extracts embedded files | Skips embedded-file detection |
| `exiftool` | Deep metadata reader | Falls back to PNG chunk parser |
| `steghide` | Extracts steghide payloads | Skips steghide cracking |
| `pngcheck` | Validates PNG structure | Skips PNG integrity check |
| `zsteg` | Enumerates all LSB combinations | Uses slower custom LSB only |
| `file` | Identifies real file type | Standard on Linux |
| `strings` | Extracts printable text | Skips string scan |

### Optional (but highly recommended)

**`stegseek`** — cracks steghide passwords **100× faster** than the Python fallback (millions of passwords/sec vs ~1/sec).

```bash
# Download the latest release binary from:
# https://github.com/RickdeJager/stegseek/releases
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
sudo dpkg -i stegseek_0.6-1.deb

# Verify
stegseek --version
```

Without `stegseek`, the script still works — it uses a slow Python loop over `steghide`.

---

## ⚙ Usage — Every Option Explained

### Basic syntax

```bash
python main.py <image> [options]
```

### All options

| Flag | Long form | Description | Default |
|------|-----------|-------------|---------|
| `<image>` | — | **Required.** Path to the challenge image | — |
| `-w` | `--wordlist FILE` | Wordlist for steghide/ZIP brute-force | `/usr/share/wordlists/rockyou.txt` |
| `-i` | `--info` | **Basic scan only** — skip steghide/brute/archive | off |
| `-f` | `--flag-format REGEX` | Custom flag pattern | Auto-detects 9 formats |
| `-o` | `--output FILE` | Write full text report | none |
| `-j` | `--json FILE` | Write JSON report | none |
| `-nb` | `--no-banner` | Suppress the ASCII banner | off |
| `-v` | `--verbose` | Print every tool's raw output | off |
| `--no-early-exit` | — | Keep scanning after finding a flag | off |
| `--no-brute` | — | Skip wordlist brute-force | off |
| `--no-xor` | — | Skip XOR composite generation | off |
| `--recursive N` | — | Rescan extracted files up to N levels deep | `2` |
| `--timeout N` | — | Per-tool timeout (seconds) | `180` |

### Flag-by-flag deep dive

#### `-w / --wordlist FILE`

Supply a custom wordlist for:
- **steghide** passphrase brute-force
- **ZIP archive** password cracking

```bash
python main.py challenge.jpg -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

If you don't pass `-w`, the script defaults to `/usr/share/wordlists/rockyou.txt`. If that file doesn't exist, the wordlist stage is skipped silently.

#### `-i / --info` — Basic Mode

Skip the time-consuming cracking stages. Great for quick recon:

```bash
python main.py challenge.png -i
```

**What still runs:** file recon, metadata, strings, binwalk, PNG check, LSB, visual dumps, GIF frames.
**What gets skipped:** archive cracking, steghide cracking, brute force.

#### `-f / --flag-format REGEX`

By default, the script auto-detects **9 common flag formats**:

```
flag{...}    FLAG{...}    HTB{...}      CTF{...}     picoCTF{...}
picoctf{...} THM{...}     tryhackme{...} <anything>{...}
```

For a custom format, pass a regex:

```bash
# HTB flags
python main.py challenge.png -f "HTB\{.*?\}"

# Two-word flags separated by underscore
python main.py challenge.png -f "[A-Z]+_[A-Z]+_\{.*?\}"

# Flag with no braces (rare)
python main.py challenge.png -f "FLAG-[A-Z0-9]{16}"
```

> **Tip:** Wrap the regex in double quotes so your shell doesn't mangle the braces.

#### `-o / --output FILE` — Text Report

Writes a full analysis report containing:
- Timestamps
- Every flag/passphrase found
- Every module's status
- Raw output from every tool

```bash
python main.py challenge.png -o writeup.txt
```

Perfect for pasting into a CTF writeup.

#### `-j / --json FILE` — JSON Report

Machine-readable output for CI, automation, or dashboards:

```bash
python main.py challenge.png -j result.json
```

JSON structure:

```json
{
  "target": "/ctf/challenge.png",
  "started": "2025-01-15T14:22:01",
  "ended": "2025-01-15T14:22:47",
  "flags": ["flag{...}", "PASSPHRASE: hunter2"],
  "found_flag": true,
  "modules": [
    {"name": "Recon", "status": "done"},
    {"name": "Brute Force", "status": "cracked: hunter2"}
  ],
  "findings": [...]
}
```

#### `-nb / --no-banner`

Suppress the ASCII skull banner. Useful for:
- Scripting / piping to files
- Running inside other tools
- Reducing noise in CI logs

```bash
python main.py challenge.png -nb -i > scan.log
```

#### `-v / --verbose`

Print every tool's **raw output** in a bordered panel. Floods your terminal but sometimes the flag is buried in there.

```bash
python main.py challenge.png -v -o verbose.txt
```

#### `--no-early-exit`

**By default**, the script stops the moment a flag is captured — saving you minutes on big wordlists.

```bash
# Default: early exit enabled
python main.py challenge.png -w rockyou.txt
# → finds flag in module 3, skips modules 4-11

# Full report even after finding a flag
python main.py challenge.png -w rockyou.txt --no-early-exit
# → runs all 11 modules regardless
```

Use `--no-early-exit` when writing a writeup and you want the complete tool log.

#### `--no-brute` / `--no-xor`

Skip specific slow stages:

```bash
python main.py huge_image.png --no-brute    # no wordlist loop
python main.py giant_image.jpg --no-xor     # no XOR composite rendering
```

XOR composites add ~2 seconds per megapixel; skip on huge images unless needed.

#### `--recursive N`

Controls how deep the script rescans extracted files. Default `2` means:

```
image.png                     ← level 0
├── binwalk extracted files   ← level 1
│   └── zip contents          ← level 2
│       └── (stops here)
```

Increase for deeply-nested challenges:

```bash
python main.py challenge.png --recursive 5
```

#### `--timeout N`

Per-tool timeout in seconds. Default `180`. Increase for:
- Huge images (bit-plane rendering)
- Big wordlists with slow steghide
- Slow disks

```bash
python main.py huge.png --timeout 600
```

---

## 💡 Real-World Examples

### Scenario 1 — You have no idea what's in the file

```bash
python main.py mystery.png
```

Runs everything. Uses `rockyou.txt`. Prints all flags found.

### Scenario 2 — Standard HackTheBox challenge

```bash
python main.py challenge.jpg -w /usr/share/wordlists/rockyou.txt -f "HTB\{.*?\}"
```

Uses HTB flag format, cracks steghide with rockyou.

### Scenario 3 — CTF writeup, need full tool log

```bash
python main.py challenge.png --no-early-exit -v -o writeup.txt
```

Skips nothing, verbose output, saves text report.

### Scenario 4 — Quick triage of 20 images

```bash
for img in images/*.png; do
    python main.py "$img" -i -nb >> triage.log
done
```

Basic scans only, no banner, appended to one log.

### Scenario 5 — Custom flag format with JSON for automation

```bash
python main.py challenge.png -f "CTF\{[a-z0-9_]+\}" -j result.json

# Then extract flags with jq
jq -r '.flags[]' result.json
```

### Scenario 6 — Suspect steghide with a non-rockyou password

```bash
python main.py challenge.jpg \
    -w ~/custom_wordlist.txt \
    --timeout 600
```

### Scenario 7 — Huge image, need speed

```bash
python main.py huge_4k_image.png -i --no-xor --no-brute
```

Only recon, metadata, strings, LSB — skips visuals and cracking.

---

## 🔬 The 11 Scan Modules

The script runs these in order. Early exit triggers after any successful flag capture.

### 1. File Reconnaissance
- `file` — real type detection (catches `.jpg` that's actually a PNG)
- Size + Shannon entropy (high entropy = encrypted/compressed data present)
- **Trailing data check** — bytes after `IEND` (PNG), `FFD9` (JPG), `3B` (GIF)
- **Chained decoding** of any trailing data (base64 → zlib → gzip → hex)

### 2. Metadata & Text Chunks
- `exiftool -a -G1` — full metadata dump
- **PNG chunk parser** — pure-Python reader for `tEXt`, `zTXt`, `iTXt`
- **EXIF thumbnail extraction** — some flags hide in the JPEG thumbnail

### 3. String Extraction + XOR Brute
- `strings -n 5` — all printable strings ≥5 chars
- Pattern match every line against flag regexes
- Keyword filter: `flag`, `ctf`, `key`, `pass`, `secret`, `admin`, `root`
- **XOR brute force** — tries all 255 single-byte keys on the strings blob

### 4. Embedded File Detection (binwalk)
- `binwalk` signature scan — finds ZIP/PNG/JPG/gzip inside the image
- `binwalk -e` — auto-extracts everything to `prodigy_artifacts/binwalk/`
- Each extracted file gets recursively rescanned

### 5. PNG Structure Check
- `pngcheck -v` — validates PNG structure
- Flags unknown chunks, CRC errors, extra data

### 6. LSB / Bit-Plane Analysis
- `zsteg -a` — enumerates every bit-plane × channel × bit-order combo
- **Custom LSB** — pure Python RGBA extraction:
  - LSB-first order
  - MSB-first order
  - Chained decode on extracted stream
  - XOR brute on extracted stream
  - Bit rotation (tries 1..7 bit shifts)

### 7. Visual Artifacts
- **3 channel isolations** (R, G, B alone)
- **24 bit-planes** (8 bits × 3 channels)
- **4 XOR composites** (R^G, G^B, R^B, R^G^B)
- **Inverted image**

All saved to `prodigy_artifacts/` for manual inspection.

### 8. GIF Frame Extraction
- Extracts every frame to `prodigy_artifacts/gif_frames/`
- Displays like a flipbook often reveal text

### 9. Embedded Archive Cracking
- Finds ZIPs — either from binwalk or by carving `PK\x03\x04` markers
- Tries empty password first
- Then brute-forces with your wordlist
- Extracts and rescans archive contents

### 10. Steghide — Quick-Win Passwords
- Tries **80+ common passwords** in under a second
- Empty password, `password`, `admin`, `flag`, etc.
- Stops on first success

### 11. Steghide Brute Force
- If `stegseek` installed: uses it (millions of passwords/sec)
- Otherwise: slow Python loop over `steghide`
- Wordlist: `-w` argument or `/usr/share/wordlists/rockyou.txt`

---

## 📺 Understanding the Output

### Section header

```
▶ [3/11] String Extraction + XOR Brute
```

Number `3` of `11` total modules. If early exit triggers, later numbers are skipped.

### Result lines

| Symbol | Meaning |
|--------|---------|
| `✓` **green** | Success — this worked |
| `!` **yellow** | Warning — worth a look |
| `✗` **red** | Failure — tool missing or error |
| `•` **dim** | Informational detail |
| `↷` **magenta** | Skipped (not applicable) |
| `⚑ FLAG` **bold green** | A flag pattern was matched |
| `🔑 PASSPHRASE` **bold yellow** | A password was cracked |

### Final summary table

```
╭─────────────── Run Summary ───────────────╮
│ Module            Status                  │
├───────────────────────────────────────────┤
│ Recon             done                    │
│ Metadata          done                    │
│ Strings           done                    │
│ Binwalk           2 files                 │
│ PNG Check         skipped                 │
│ LSB               done                    │
│ Visuals           done                    │
│ GIF               skipped                 │
│ Archive           cracked                 │
│ Steghide Quick    cracked: hunter2        │
│ Brute Force       skipped                 │
╰───────────────────────────────────────────╯
```

### Final flag panel

Green panel = **win**:

```
╭─────────  ⚑  FLAGS FOUND  ⚑  ─────────╮
│                                        │
│   ⚑ flag{1_l0v3_st3g0}                 │
│   ⚑ PASSPHRASE: hunter2                │
│                                        │
╰────────────────────────────────────────╯
```

Yellow panel = no flag matched. Includes next-step hints.

---

## 📁 Artifacts Folder

Everything the script extracts or generates goes to `prodigy_artifacts/` next to your image:

```
prodigy_artifacts/
├── channel_R.png             ← red channel only
├── channel_G.png             ← green channel only
├── channel_B.png             ← blue channel only
├── bit0_R.png … bit7_B.png   ← 24 bit-planes
├── xor_R_G.png               ← R XOR G
├── xor_G_B.png
├── xor_R_B.png
├── xor_R_G_B.png
├── inverted.png              ← 255 - image
├── trailing_data.bin         ← bytes after EOF marker
├── exif_thumbnail.jpg        ← embedded JPEG thumbnail
├── steghide_out              ← steghide payload (if found)
├── brute_out                 ← brute-force payload (if found)
├── binwalk/                  ← binwalk-extracted files
├── carved_zips/              ← ZIPs carved from raw stream
└── gif_frames/               ← GIF frames (if input was GIF)
```

**Open these in an image viewer** — a surprising number of CTF challenges put the flag in a bit-plane as visible text.

---

## 🛠 Troubleshooting

### "command not found" for a tool

Not a problem — the script skips missing tools gracefully. To install:

```bash
sudo apt install binwalk exiftool steghide pngcheck
sudo gem install zsteg
```

### "No flags found" but you know there's a flag

Try these in order:

```bash
# 1. Basic scan with verbose output
python main.py challenge.png -i -v -o full.txt

# 2. Look inside the artifacts folder manually
ls prodigy_artifacts/
# Open bit-planes in an image viewer

# 3. Try the full scan with --no-early-exit
python main.py challenge.png --no-early-exit -o full.txt

# 4. Custom flag format
python main.py challenge.png -f "your_regex_here"

# 5. Deeper recursion
python main.py challenge.png --recursive 5
```

### Steghide brute force is super slow

Install `stegseek` (100× faster):

```bash
# See: https://github.com/RickdeJager/stegseek/releases
```

Or skip it entirely:

```bash
python main.py challenge.png --no-brute
```

### "very high entropy" warning

Not necessarily bad. High entropy just means the file contains compressed/encrypted data — usually a hint that there's an embedded ZIP or image.

### Banner looks garbled

Your terminal doesn't support braille characters or truecolor. Options:

1. Use a modern terminal (Windows Terminal, iTerm2, Kitty, Alacritty)
2. Set `TERM=xterm-256color`
3. Use `-nb` to skip the banner

### Script crashes on huge image

```bash
python main.py huge.png --no-xor --no-brute --timeout 600
```

Or run in basic mode:

```bash
python main.py huge.png -i
```

### Wrong flag format detected

Pass an explicit regex:

```bash
python main.py challenge.png -f "HTB\{[A-Za-z0-9_]+\}"
```

---

## ❓ FAQ

**Q: Will it find every flag?**
A: No tool can. It catches **~80% of typical CTF challenges** — metadata, LSB, steghide, embedded files, XOR. Challenges requiring:
- XOR against a *specific* cover image (no way to guess)
- Visual puzzles (pixel rearrangement, hidden text in tiny image)
- Palette-index manipulation in GIFs
- Custom encryption

...will need manual analysis. The script generates artifacts (bit-planes, XOR composites) that make manual analysis easy.

**Q: Does it modify my image?**
A: Never. All extracted files go to `prodigy_artifacts/`. Your original is untouched.

**Q: Can I use this outside of CTFs?**
A: Yes — for steganalysis on any image you own. Be aware of laws in your jurisdiction around analyzing images that aren't yours.

**Q: Why does it exit early?**
A: To save time. If you're running on a big wordlist and the flag is found in module 3, there's no reason to keep cracking for 20 minutes. Override with `--no-early-exit`.

**Q: What's the difference between the quick password list and the wordlist?**
A:
- **Quick list:** 80 passwords built into the script. Runs in <2 seconds.
- **Wordlist:** Full brute-force, usually `rockyou.txt` (14M passwords). Can take minutes to hours.

**Q: Does it work on Windows/Mac?**
A: Yes, if the external tools are installed. On Windows, use WSL2 or install `exiftool`, `binwalk`, `steghide` via package managers.

**Q: My steghide-cracked payload isn't a flag**

Sometimes the steghide payload is another file (a ZIP, a text file, another image). The script automatically:
1. Scans it as text
2. Runs chained decoders on it
3. XOR-brute-forces it
4. If it looks like an archive, adds it to the archive-cracking queue

If you extracted a file (not text), look in `prodigy_artifacts/steghide_out`.

**Q: How do I add my own flag format permanently?**
Edit `FLAG_BANK` near the top of `main.py`:

```python
FLAG_BANK = [
    r"flag\{[^}\n]{1,200}\}",
    r"HTB\{[^}\n]{1,200}\}",
    r"YOUR_PATTERN_HERE\{[^}\n]{1,200}\}",  # ← add here
    # ...
]
```

---

## 🔩 How It Works Under the Hood

### Pipeline with early exit

```
Start
  │
  ├─> Banner
  ├─> Session info panel
  │
  ├─> for scan in [11 modules]:
  │     if flag_found AND early_exit: break
  │     scan()
  │
  ├─> Final flag panel
  ├─> Summary table
  ├─> Write reports (-o / -j)
  └─> Elapsed time
```

### Flag harvesting

Every tool's output is fed through `_record()`, which:
1. Stores it for the report
2. Runs **all flag regexes** on it
3. Extracts steghide passphrases
4. Runs `_auto_decode()`:
   - Finds base64/hex blobs
   - Chains decoders recursively
   - XOR-brute-forces the raw bytes
   - Recursively harvests decoded text

New flags trigger `found_flag = True`, which enables the early exit.

### Recursive scanning

Extracted files (from binwalk, ZIPs, EXIF thumbnails) get rescanned via `_scan_extracted()`, up to `--recursive` levels deep. Each level re-runs:
- Text harvest
- Chained decode
- XOR brute force

### Safety

- All subprocess calls use argument lists (never `shell=True`)
- 30-second default timeout per tool
- Try/except around every external call
- Ctrl-C prints partial results and exits cleanly

---

## 📚 Credits & Reference

| Tool | Author | Purpose |
|------|--------|---------|
| zsteg | zed-0xff | LSB bit-plane enumeration |
| binwalk | ReFirmLabs | Embedded file detection |
| steghide | Stefan Hetzl | JPEG/BMP/WAV stego |
| stegseek | Rick de Jager | Fast steghide cracker |
| exiftool | Phil Harvey | Metadata extraction |
| pngcheck | Alexander Lehmann | PNG structure validation |
| rich | Textualize | Terminal formatting |

---

## 📄 License

MIT — use freely, modify freely, ship freely.

---

**Happy flag hunting.** 🎨💀⚡

*If this tool helped you place in a CTF, you owe the community a writeup.*
