#!/usr/bin/env python3
import os
import argparse
from pathlib import Path
from typing import Iterable, Tuple
from xml.etree import ElementTree
from PIL import Image

# ---------- helpers ----------

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
                try:
                    d[item.text] = int(nxt.text)
                except Exception:
                    d[item.text] = nxt.text
            elif nxt.tag == 'dict':
                d[item.text] = tree_to_dict(nxt)
    return d

def _to_list_nums(s: str):
    # "{x,y}" -> [int(x), int(y)] (robust to spaces/floats)
    parts = s.replace('{', '').replace('}', '').split(',')
    return [int(float(p.strip())) for p in parts]

def frames_from_plist(plist_path: Path) -> Iterable[Tuple[str, dict]]:
    """
    Yield per-sprite metadata. Any malformed entry is warned and skipped.
    """
    try:
        xml_text = plist_path.read_text(encoding="utf-8", errors="ignore")
        root = ElementTree.fromstring(xml_text)
    except Exception as e:
        print(f"[WARN] Failed to parse XML in {plist_path.name}: {e}")
        return

    try:
        plist_dict = tree_to_dict(root[0])
        frames = plist_dict['frames']
    except Exception as e:
        print(f"[WARN] Missing/invalid 'frames' dict in {plist_path.name}: {e}")
        return

    fmt3 = (plist_dict.get("metadata", {}) or {}).get("format") == 3

    for k, v in frames.items():
        try:
            frame = dict(v)  # shallow copy

            if fmt3:
                frame['frame'] = frame['textureRect']
                frame['rotated'] = frame['textureRotated']
                frame['sourceSize'] = frame['spriteSourceSize']
                frame['offset'] = frame.get('spriteOffset', '{0,0}')

            rect = _to_list_nums(frame['frame'])  # [x, y, w, h]
            rotated = bool(frame['rotated'])

            # For rotated entries, atlas stores width/height swapped for the crop box
            w = rect[3] if rotated else rect[2]
            h = rect[2] if rotated else rect[3]
            x0, y0 = rect[0], rect[1]
            box = (x0, y0, x0 + w, y0 + h)

            # Source (untrimmed) size; many exporters keep it unrotated dimensions
            src_w, src_h = _to_list_nums(frame['sourceSize'])
            if rotated:
                # Some TP flavors effectively swap these when rotated; guard by swapping
                src_w, src_h = src_h, src_w
            sizelist = [src_w, src_h]

            off_x, off_y = _to_list_nums(frame.get('offset', '{0,0}'))

            if rotated:
                # With rotated frames we keep sign as-is for y to maintain placement
                result_box = (
                    int((src_w - w) / 2 + off_x),
                    int((src_h - h) / 2 + off_y),
                    int((src_w + w) / 2 + off_x),
                    int((src_h + h) / 2 + off_y),
                )
            else:
                # Classic TexturePacker: invert y-offset when not rotated
                result_box = (
                    int((src_w - w) / 2 + off_x),
                    int((src_h - h) / 2 - off_y),
                    int((src_w + w) / 2 + off_x),
                    int((src_h + h) / 2 - off_y),
                )

            yield k, {'box': box, 'size': sizelist, 'rotated': rotated, 'result_box': result_box}

        except Exception as e:
            print(f"[WARN] Skipped malformed frame '{k}' in {plist_path.name}: {e}")
            continue

# ---------- core ----------

def extract_plist_pair(plist_path: Path, search_root: Path, out_root: Path | None) -> int:
    png_path = plist_path.with_suffix(".png")
    if not png_path.exists():
        print(f"[SKIP] No PNG for {plist_path.name}")
        return 0

    # determine output dir
    if out_root:
        try:
            rel = plist_path.with_suffix('').relative_to(search_root)
        except Exception:
            rel = Path(plist_path.stem)
        outdir = out_root / rel
    else:
        outdir = plist_path.with_suffix('')
    outdir.mkdir(parents=True, exist_ok=True)

    # open atlas (defensively)
    try:
        big = Image.open(png_path)
    except Exception as e:
        print(f"[WARN] Could not open {png_path.name}: {e}")
        return 0

    count = 0
    for name, meta in frames_from_plist(plist_path) or []:
        try:
            crop = big.crop(meta['box'])

            # IMPORTANT: undo rotation on the chunk first (not the canvas)
            if meta['rotated']:
                # Atlas stored 90° CW; undo with CCW
                crop = crop.transpose(Image.ROTATE_90)

            result = Image.new('RGBA', meta['size'], (0, 0, 0, 0))

            # Prefer 2-tuple top-left paste using crop as its own mask
            try:
                x0, y0 = meta['result_box'][0], meta['result_box'][1]
                result.paste(crop, (x0, y0), crop)
            except Exception:
                # Fallback to 4-tuple if needed
                result.paste(crop, meta['result_box'], crop)

            out = (outdir / name).with_suffix(".png")
            out = Path(str(out).replace('gift_', ''))  # legacy quirk
            out.parent.mkdir(parents=True, exist_ok=True)
            result.save(out)
            count += 1

        except Exception as e:
            print(f"[WARN] Skipped {plist_path.name}:{name}: {e}")
            continue

    print(f"[OK] {count} sprites -> {outdir} (from {plist_path.name} + {png_path.name})")
    return count

def walk_and_extract(root: Path, out_root: Path | None) -> int:
    total = 0
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if fname.lower().endswith(".plist"):
                total += extract_plist_pair(Path(dirpath) / fname, search_root=root, out_root=out_root)
    if total == 0:
        print("[INFO] No .plist+.png pairs found under", root)
    print(f"\n[SUMMARY] Total sprites extracted: {total}")
    return total

# ---------- CLI ----------

def _sanitize_path(p: str | None) -> Path | None:
    if not p:
        return None
    s = p.strip().strip('"').strip("'")
    return Path(s).resolve()

def main():
    ap = argparse.ArgumentParser(description="Extract sprites from .plist + .png pairs (recursive, error-tolerant).")
    ap.add_argument("path", help="File (.plist or base) or directory.")
    ap.add_argument("--out", type=str, default=None,
                    help="Optional output root. If set, outputs mirror the relative structure under this folder. (quotes OK)")
    args = ap.parse_args()

    target = Path(args.path).resolve()
    out_root = _sanitize_path(args.out)

    if target.is_dir():
        walk_and_extract(target, out_root=out_root)
    else:
        plist = target if target.suffix.lower() == ".plist" else target.with_suffix(".plist")
        if plist.exists():
            search_root = plist.parent
            total = extract_plist_pair(plist, search_root=search_root, out_root=out_root)
            print(f"\n[SUMMARY] Total sprites extracted: {total}")
        else:
            print(f"[ERR] Not a .plist and no matching {target.with_suffix('.plist')} found")

if __name__ == "__main__":
    main()
