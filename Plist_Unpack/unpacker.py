#!/usr/bin/env python3
import os
import argparse
from pathlib import Path
from typing import Iterator, Tuple
from xml.etree import ElementTree
from PIL import Image
import json

# -----------------------
# Parsing helpers
# -----------------------
def tree_to_dict(tree):
    d = {}
    for index, item in enumerate(tree):
        if item.tag == 'key':
            nxt = tree[index + 1]
            if nxt.tag == 'string':
                d[item.text] = nxt.text
            elif nxt.tag == 'true':
                d[item.text] = True
            elif nxt.tag == 'false':
                d[item.text] = False
            elif nxt.tag == 'integer':
                d[item.text] = int(nxt.text)
            elif nxt.tag == 'dict':
                d[item.text] = tree_to_dict(nxt)
    return d

def _to_list_nums(s: str):
    # "{x,y}" -> [int(x), int(y)], robust to spaces/floats
    parts = s.replace('{', '').replace('}', '').split(',')
    return [int(float(p.strip())) for p in parts]

def frames_from_plist(plist_path: Path):
    # Handle common UTF-8 w/ odd characters gracefully
    root = ElementTree.fromstring(plist_path.read_text(encoding="utf-8", errors="ignore"))
    plist_dict = tree_to_dict(root[0])

    for k, v in plist_dict['frames'].items():
        frame = dict(v)

        # Normalize TexturePacker/Cocos format 3 keys to v2-like
        if plist_dict.get("metadata", {}).get("format") == 3:
            frame['frame'] = frame['textureRect']
            frame['rotated'] = frame['textureRotated']
            frame['sourceSize'] = frame['spriteSourceSize']
            frame['offset'] = frame.get('spriteOffset', '{0,0}')

        rectlist = _to_list_nums(frame['frame'])  # [x, y, w, h]
        rotated = bool(frame['rotated'])

        # When rotated, w/h in the atlas are swapped relative to the crop box
        w = rectlist[3] if rotated else rectlist[2]
        h = rectlist[2] if rotated else rectlist[3]
        x0, y0 = rectlist[0], rectlist[1]
        box = (x0, y0, x0 + w, y0 + h)

        real_w, real_h = _to_list_nums(frame['sourceSize'])
        if rotated:
            # Some TP exporters store sourceSize swapped when rotated; guard both ways
            real_w, real_h = real_h, real_w
        real_size = [real_w, real_h]

        off_x, off_y = _to_list_nums(frame.get('offset', '{0,0}'))
        # TexturePacker offsets are typically y-up; invert y when not rotated
        if rotated:
            # With rotated frames, the sign interplay differs; keep consistent placement
            result_box = (
                int((real_size[0] - w) / 2 + off_x),
                int((real_size[1] - h) / 2 + off_y),
                int((real_size[0] + w) / 2 + off_x),
                int((real_size[1] + h) / 2 + off_y),
            )
        else:
            result_box = (
                int((real_size[0] - w) / 2 + off_x),
                int((real_size[1] - h) / 2 - off_y),
                int((real_size[0] + w) / 2 + off_x),
                int((real_size[1] + h) / 2 - off_y),
            )

        yield k, {
            'box': box,
            'real_sizelist': real_size,
            'result_box': result_box,
            'rotated': rotated,
        }

def frames_from_json(json_path: Path):
    with json_path.open("r", encoding="utf-8", errors="ignore") as jf:
        data = json.load(jf)

    for k, v in data['frames'].items():
        fx = int(float(v["frame"]["x"]))
        fy = int(float(v["frame"]["y"]))
        fw = int(float(v["frame"]["h"] if v['rotated'] else v["frame"]["w"]))
        fh = int(float(v["frame"]["w"] if v['rotated'] else v["frame"]["h"]))

        rw = int(float(v["sourceSize"]["h"] if v['rotated'] else v["sourceSize"]["w"]))
        rh = int(float(v["sourceSize"]["w"] if v['rotated'] else v["sourceSize"]["h"]))

        yield k, {
            'box': (fx, fy, fx + fw, fy + fh),
            'real_sizelist': [rw, rh],
            'result_box': (
                int((rw - fw) / 2),
                int((rh - fh) / 2),
                int((rw + fw) / 2),
                int((rh + fh) / 2),
            ),
            'rotated': bool(v['rotated']),
        }

# -----------------------
# Core extraction
# -----------------------
def gen_from_data(base: Path, data_ext: str, search_root: Path, out_root: Path | None):
    """
    Process a single pair (base + .png + .plist/.json). Returns sprite count.
    """
    png_path = base.with_suffix(".png")
    data_path = base.with_suffix(data_ext)
    if not png_path.exists() or not data_path.exists():
        print(f"[SKIP] Missing pair for: {base}")
        return 0

    big_image = Image.open(png_path)
    frames = frames_from_plist(data_path) if data_ext == ".plist" else frames_from_json(data_path)

    if out_root:
        try:
            rel = base.relative_to(search_root)
        except Exception:
            rel = Path(base.name)
        outdir = out_root / rel
    else:
        outdir = base if base.is_dir() else base.parent / base.name

    outdir.mkdir(parents=True, exist_ok=True)

    count = 0
    for name, frame in frames:
        try:
            # 1) Crop from the atlas
            crop = big_image.crop(frame['box'])  # (x0,y0,x1,y1)

            # 2) Undo atlas rotation on the CHUNK, not the canvas
            if frame['rotated']:
                # TexturePacker stores rotated 90° CW; undo with CCW
                crop = crop.transpose(Image.ROTATE_90)

            # 3) Create the destination canvas (untrimmed size)
            result_image = Image.new('RGBA', frame['real_sizelist'], (0, 0, 0, 0))

            # 4) Paste at the computed offset; use crop as its own alpha mask
            dest_xy = frame['result_box'][:2]
            result_image.paste(crop, dest_xy, crop)

            # 5) Save
            outfile = (outdir / name).with_suffix(".png")
            # legacy quirk you had earlier:
            outfile = Path(str(outfile).replace('gift_', ''))
            outfile.parent.mkdir(parents=True, exist_ok=True)
            result_image.save(outfile)

            count += 1
        except Exception as e:
            print(f"[WARN] Skipped {name}: {e}")

    return count

def iter_pairs(root: Path, mode: str) -> Iterator[Tuple[Path, str]]:
    """
    Yield (base_without_ext, data_ext) for each valid pair under root.
    mode: 'plist', 'json', or 'auto'
    """
    exts = {'.plist', '.json'} if mode == 'auto' else {f".{mode}"}
    for dirpath, _, files in os.walk(root):
        names = set(files)
        for fname in files:
            stem, ext = os.path.splitext(fname)
            ext = ext.lower()
            if ext in exts and (stem + ".png") in names:
                yield Path(dirpath) / stem, ext

# -----------------------
# CLI
# -----------------------
def _sanitize_path(p: str | None) -> Path | None:
    if not p:
        return None
    s = p.strip().strip('"').strip("'")
    return Path(s).resolve()

def main():
    ap = argparse.ArgumentParser(description="Unpack sprites from TexturePacker/Cocos data (recursive).")
    ap.add_argument("path", help="Path to a file (base name) or a directory.")
    ap.add_argument("--ext", choices=["auto", "plist", "json"], default="auto",
                    help="Data extension to process. Default: auto (both).")
    ap.add_argument("--out", type=str, default=None,
                    help="Optional output root. If set, outputs mirror the relative structure under this folder. (quotes OK)")
    args = ap.parse_args()

    p = Path(args.path).resolve()
    out_root = _sanitize_path(args.out)
    total = 0

    if p.is_dir():
        seen_pairs = 0
        for base, data_ext in iter_pairs(p, args.ext):
            total += gen_from_data(base, data_ext, search_root=p, out_root=out_root) or 0
            seen_pairs += 1
        if seen_pairs == 0:
            print("[INFO] No matching {plist/json}+png pairs found under", p)
    else:
        # single base (without ext) still supported
        base = p.with_suffix('') if p.suffix in ('.plist', '.json', '.png') else p
        processed = False
        for data_ext in (['.' + args.ext] if args.ext in ('plist', 'json') else ['.plist', '.json']):
            if base.with_suffix(data_ext).exists() and base.with_suffix(".png").exists():
                search_root = base.parent  # preserve relative from here
                total += gen_from_data(base, data_ext, search_root=search_root, out_root=out_root) or 0
                processed = True
                break
        if not processed:
            print(f"[ERR] Missing pair: need {base}.png and {base}.plist|.json")

    print(f"\n[SUMMARY] Total sprites extracted: {total}")

if __name__ == "__main__":
    main()
