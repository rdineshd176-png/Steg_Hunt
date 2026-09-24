# Steg Hunt

Prodigy Stego Hunter is an automated CTF image steganography framework. It scans challenge images for hidden flags, metadata, embedded files, encoded payloads, bit-plane data, and password-protected steganographic content.

## Features

- File reconnaissance, entropy checks, and trailing-data detection
- PNG metadata and text-chunk inspection
- String extraction, chained decoding, XOR brute force, and bit rotation checks
- Optional `binwalk`, `pngcheck`, and `zsteg` integration
- Custom LSB and visual bit-plane extraction with generated artifacts
- GIF frame extraction
- ZIP archive and Steghide password cracking
- Text and JSON reports

## Requirements

Python 3.10 or newer is recommended. Install the Python dependencies with:

```bash
pip install rich pillow numpy
```

Some scan stages require external tools installed separately:

- `exiftool`
- `binwalk`
- `pngcheck`
- `zsteg`
- `steghide` or `stegseek`

## Usage

```bash
python main.py <image> [options]
```

Examples:

```bash
python main.py challenge.png
python main.py challenge.jpg -w rockyou.txt -f "HTB\\{.*?\\}" -o report.txt
python main.py challenge.png -i --no-brute
python main.py challenge.jpg -v --no-xor -j out.json
```

Run `python main.py --help` to see all available options.

## Output

Generated artifacts are stored in `prodigy_artifacts/` next to the target image. Reports can be written with `-o` for text output or `-j` for JSON output.

## Responsible Use

Use this tool only on images and systems you own or are explicitly authorized to analyze, such as CTF challenges and lab environments.
