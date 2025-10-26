#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bsymg_full_pipeline_parallel.py  —  Parallel + Diagnostic

What’s new:
  • Loud run header: shows jobs, paths, key bytes
  • For every file: [start], [wrote-basis size=..], [basisu-ok kept=N], [kept size=..]
  • Cleans basisu clutter by default (keeps only "*_unpacked_rgba_*.png")
  • Optional --keep PATTERN (glob, repeatable) to preserve more outputs
  • Catches worker exceptions and logs them
  • Verifies sizes: no more silent 0 KB

Usage (recommended):
  python bsymg_full_pipeline_parallel.py ^
    "C:/assets" ^
    --out-dir "C:/OUT" ^
    --key-file "C:/xor_key_hit_0.bin" ^
    --rename-basis --transcode-basis --process-luac ^
    --jobs 8 --verbose
"""

from pathlib import Path
import argparse, os, sys, csv, shutil, subprocess, tempfile, fnmatch, multiprocessing
from typing import Optional, List, Tuple, Dict
from concurrent.futures import ProcessPoolExecutor, as_completed

# ---------- Constants ----------
PNG_XOR_KEY_FALLBACK = (b"// Dump Ref object memory leaks if (__refAllocationList.empty()) { log([memory] All Ref objects "
                        b"successfully cleaned up (no leaks detected).\n); } else { log([memory] WARNING: %d Ref objects still "
                        b"active in memory.\n, (int)__refAllocationList.size()); for (const auto& ref : __refAllocationList) { "
                        b"CC_ASSERT(ref); const char* type = typeid(*ref).name(); log([memory] LEAK: Ref object %s still active "
                        b"with reference count %d.\n, (type ? type : ), ref->getReferenceCount()); }}")

LUAC_SIGN = b"applicationWillEnterForeground"
LUAC_XXTEA_KEY = b"applicationDidEnterBackground"

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
BASIS_MAGIC = b"BASIS"
BASISENC_MAGIC = b"BASISENC"

DEFAULT_KEEP_PATTERNS = ["*_unpacked_rgba_BC3_RGBA_*.png"]  # keep only composite RGBA by default

# ---------- Utils ----------
def safe_makedirs(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def head_bytes(path: Path, n: int) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except Exception:
        return b""

def is_png_magic(b: bytes) -> bool:
    return b.startswith(PNG_MAGIC)

def atomic_write_bytes(target: Path, data: bytes):
    safe_makedirs(target.parent)
    tmp = target.with_name(f".{target.name}.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)

def file_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except Exception:
        return -1

# ---------- XXTEA ----------
def _to_u32_list(b: bytes):
    n = len(b); pad = (-n) & 3
    b2 = b + b"\0"*pad
    return [int.from_bytes(b2[i:i+4], "little") for i in range(0, len(b2), 4)], n

def _from_u32_list(v, orig_len):
    out = bytearray()
    for x in v:
        out += (x & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out[:orig_len])

def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    if not data: return data
    v, orig = _to_u32_list(data)
    k, _ = _to_u32_list((key + b"\0"*16)[:16])
    n = len(v)
    if n < 2: return data
    DELTA = 0x9E3779B9
    rounds = 6 + 52 // n
    summ = (rounds * DELTA) & 0xFFFFFFFF
    while summ:
        e = (summ >> 2) & 3
        for p in range(n-1, -1, -1):
            z = v[p-1] if p > 0 else v[n-1]
            y = v[p]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((summ ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
        summ = (summ - DELTA) & 0xFFFFFFFF
    return _from_u32_list(v, orig)

# ---------- XOR helpers ----------
def xor_first_n(data: bytes, key: bytes, n: int) -> bytes:
    if not data: return data
    n = min(len(data), n)
    out = bytearray(data); kl = len(key)
    for i in range(n):
        out[i] ^= key[i % kl]
    return bytes(out)

def xor_basisenc_payload_strip_header(raw: bytes, key: bytes, window: int) -> bytes:
    """XOR bytes [8 : 8+window) then return data WITHOUT the 8-byte BASISENC tag."""
    if not raw.startswith(BASISENC_MAGIC) or len(raw) <= 8:
        return raw
    hdr_len = 8
    end = min(len(raw) - hdr_len, window)
    out = bytearray(raw)
    kl = len(key)
    for i in range(end):
        out[hdr_len + i] ^= key[i % kl]
    return bytes(out[8:])  # strip tag

# ---------- basisu ----------
def find_basisu_exe() -> Optional[str]:
    exe = shutil.which("basisu")
    if exe:
        return exe
    # As a fallback, try local exe (Windows)
    cand = Path("./basisu.exe")
    return str(cand) if cand.exists() else None

def transcode_basis_keep_patterns(basis_file: Path, keep_patterns: List[str], verbose=False) -> Tuple[bool, List[Path], str]:
    """
    Run basisu -unpack. Then delete outputs not matching keep_patterns.
    Returns (ok, kept_paths, raw_log_excerpt)
    """
    exe = find_basisu_exe()
    if not exe:
        return False, [], "[transcode-skip] basisu not found on PATH"

    cwd = basis_file.parent
    cmd = [exe, "-file", str(basis_file), "-unpack"]
    if verbose:
        print(f"[basisu] {' '.join(cmd)} (cwd={cwd})")

    # capture output so we can show a short excerpt
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    except Exception as e:
        return False, [], f"[transcode-error] {e}"

    out_text = (cp.stdout or "") + (cp.stderr or "")
    if cp.returncode != 0:
        return False, [], out_text.strip()[:4000]

    # Collect outputs, then prune
    kept: List[Path] = []
    for item in cwd.iterdir():
        if not item.is_file():
            continue
        name = item.name
        # keep only files starting with this stem
        if not name.startswith(basis_file.stem + "_"):
            continue
        # apply keep filters
        keep = False
        for patt in keep_patterns:
            if fnmatch.fnmatch(name, patt):
                keep = True
                break
        if keep:
            kept.append(item)
        else:
            # remove extra clutter (dds, ktx, non-kept pngs)
            try: item.unlink()
            except Exception: pass

    return True, kept, out_text.strip()[:2000]

# ---------- Worker ----------
def process_one(args: Dict) -> Tuple[str, str, str, str, str]:
    """
    Returns (source, dest, action, reason, extras) for CSV.
    Extras contains kept file paths or error snippets.
    """
    src_path = Path(args["src"])
    dst_root = Path(args["dst_root"]) if args["dst_root"] else None
    rel = Path(args["rel"])
    xor_key = args["xor_key_bytes"]
    windows = args["windows"]
    keep_patterns = args["keep_patterns"]
    rename_basis = args["rename_basis"]
    transcode_basis = args["transcode_basis"]
    process_pngs = args["process_pngs"]
    process_luac = args["process_luac"]
    verbose = args["verbose"]

    dst_path = (dst_root / rel) if dst_root else src_path

    print(f"[start] {src_path}")

    # PNG pass-through or mirror
    h = head_bytes(src_path, 16)
    if is_png_magic(h):
        if dst_root:
            try:
                safe_makedirs(dst_path.parent)
                shutil.copy2(src_path, dst_path)
                print(f"[mirrored-png] {dst_path} size={file_size(dst_path)}")
            except Exception as e:
                print(f"[error] copy png {src_path}: {e}")
                return (str(src_path), str(dst_path), "error", f"copy_fail:{e}", "")
        return (str(src_path), str(dst_path), "skip", "already_png", "")

    is_basisenc = h.startswith(BASISENC_MAGIC)
    is_basis    = h.startswith(BASIS_MAGIC)

    # BASIS/BASISENC
    if is_basisenc or is_basis:
        try:
            raw = src_path.read_bytes()
        except Exception as e:
            print(f"[error] read {src_path}: {e}")
            return (str(src_path), "", "error", f"read_fail:{e}", "")

        # choose output name, rename .png -> .basis if requested
        write_path = dst_path
        if rename_basis and write_path.suffix.lower() == ".png":
            write_path = write_path.with_suffix(".basis")
        safe_makedirs(write_path.parent)

        if is_basisenc:
            # Try windows until one transcodes OK (or until we decide the first is fine if no transcode)
            for win in windows:
                fixed_no_hdr = xor_basisenc_payload_strip_header(raw, xor_key, win)
                try:
                    atomic_write_bytes(write_path, fixed_no_hdr)
                    try: shutil.copystat(src_path, write_path)
                    except Exception: pass
                    print(f"[wrote-basis] {write_path} size={file_size(write_path)} win=0x{win:02X}")
                except Exception as e:
                    print(f"[error] write {write_path}: {e}")
                    return (str(src_path), str(write_path), "error", f"write_fail:{e}", "")

                if transcode_basis:
                    ok, kept, log_excerpt = transcode_basis_keep_patterns(write_path, keep_patterns, verbose=verbose)
                    if ok:
                        for k in kept:
                            print(f"[kept] {k} size={file_size(k)}")
                        return (str(src_path), str(write_path), "basis_detected",
                                f"BASISENC+xor;win=0x{win:02X}", ";".join(str(p) for p in kept))
                    else:
                        print(f"[basisu-fail] {write_path} win=0x{win:02X}\n{log_excerpt}")
                        # try next win
                else:
                    return (str(src_path), str(write_path), "basis_detected",
                            f"BASISENC+xor;win=0x{win:02X}", "")

            # none worked
            return (str(src_path), str(write_path), "basis_detected", "all_windows_failed", "")
        else:
            # Plain BASIS: mirror/copy and (optionally) transcode
            try:
                if dst_root:
                    shutil.copy2(src_path, write_path)
                elif write_path != src_path:
                    shutil.copy2(src_path, write_path)
                try: shutil.copystat(src_path, write_path)
                except Exception: pass
                print(f"[mirrored-basis] {write_path} size={file_size(write_path)}")
            except Exception as e:
                print(f"[error] copy basis {src_path}: {e}")
                return (str(src_path), str(write_path), "error", f"copy_fail:{e}", "")
            if transcode_basis:
                ok, kept, log_excerpt = transcode_basis_keep_patterns(write_path, keep_patterns, verbose=verbose)
                if ok:
                    for k in kept:
                        print(f"[kept] {k} size={file_size(k)}")
                    return (str(src_path), str(write_path), "basis_detected", "BASIS", ";".join(str(p) for p in kept))
                else:
                    print(f"[basisu-fail] {write_path}\n{log_excerpt}")
                    return (str(src_path), str(write_path), "basis_detected", "BASIS;transcode_failed", "")
            return (str(src_path), str(write_path), "basis_detected", "BASIS", "")

    # PNG XOR fix for non-basis, non-png
    if process_pngs:
        try:
            raw = src_path.read_bytes()
        except Exception as e:
            print(f"[error] read {src_path}: {e}")
            return (str(src_path), "", "error", f"read_fail:{e}", "")
        cand = xor_first_n(raw, xor_key, 200)
        if is_png_magic(cand):
            try:
                safe_makedirs(dst_path.parent)
                atomic_write_bytes(dst_path, cand)
                try: shutil.copystat(src_path, dst_path)
                except Exception: pass
                print(f"[png-fixed] {dst_path} size={file_size(dst_path)} mode=xor200")
            except Exception as e:
                print(f"[error] write png {dst_path}: {e}")
                return (str(src_path), str(dst_path), "error", f"write_fail:{e}", "")
            return (str(src_path), str(dst_path), "png_fixed", "xor200", "")
        cand2 = xor_first_n(raw, xor_key, 512)
        if is_png_magic(cand2):
            try:
                safe_makedirs(dst_path.parent)
                atomic_write_bytes(dst_path, cand2)
                try: shutil.copystat(src_path, dst_path)
                except Exception: pass
                print(f"[png-fixed] {dst_path} size={file_size(dst_path)} mode=xor512")
            except Exception as e:
                print(f"[error] write png {dst_path}: {e}")
                return (str(src_path), str(dst_path), "error", f"write_fail:{e}", "")
            return (str(src_path), str(dst_path), "png_fixed", "xor512", "")

    # .luac (optional)
    if process_luac and src_path.suffix.lower() == ".luac":
        try:
            raw = src_path.read_bytes()
        except Exception as e:
            print(f"[error] read {src_path}: {e}")
            return (str(src_path), "", "error", f"read_fail:{e}", "")
        if raw.startswith(LUAC_SIGN):
            payload = raw[len(LUAC_SIGN):]
            try:
                dec = xxtea_decrypt(payload, LUAC_XXTEA_KEY)
            except Exception as e:
                print(f"[error] xxtea {src_path}: {e}")
                return (str(src_path), "", "error", f"xxtea_fail:{e}", "")
            try:
                safe_makedirs(dst_path.parent)
                atomic_write_bytes(dst_path, dec)
                try: shutil.copystat(src_path, dst_path)
                except Exception: pass
                print(f"[luac] {dst_path} size={file_size(dst_path)}")
            except Exception as e:
                print(f"[error] write luac {dst_path}: {e}")
                return (str(src_path), str(dst_path), "error", f"write_fail:{e}", "")
            return (str(src_path), str(dst_path), "luac_decrypted", "", "")

    # Mirror untouched if out_dir
    if dst_root:
        try:
            safe_makedirs(dst_path.parent)
            shutil.copy2(src_path, dst_path)
            print(f"[mirrored] {dst_path} size={file_size(dst_path)}")
            return (str(src_path), str(dst_path), "none", "no_action_copied", "")
        except Exception as e:
            print(f"[error] copy {src_path}: {e}")
            return (str(src_path), str(dst_path), "error", f"copy_fail:{e}", "")

    return (str(src_path), str(dst_path), "none", "no_action", "")

# ---------- Walk & parallel ----------
def gather_files(root: Path) -> List[Path]:
    files = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            files.append(Path(dirpath) / n)
    return files

def main():
    ap = argparse.ArgumentParser(description="Parallel: XOR-fix BASISENC (strip header), transcode via basisu (keep only selected outputs); PNG XOR fix; optional .luac.")
    ap.add_argument("scan_root", help="Root folder to scan (recursive)")
    ap.add_argument("--out-dir", help="Mirror outputs into this folder (recommended)")
    ap.add_argument("--key-file", help="Raw XOR key bytes file from the .so (recommended)")
    ap.add_argument("--rename-basis", action="store_true", help="Rename .png -> .basis for Basis headers")
    ap.add_argument("--transcode-basis", action="store_true", help="Run basisu and keep only selected outputs")
    ap.add_argument("--keep", action="append", help="Glob(s) to keep (default only *_unpacked_rgba_*.png). Repeatable.")
    ap.add_argument("--process-pngs", action="store_true", default=True, help="Attempt PNG XOR fix (default ON)")
    ap.add_argument("--no-process-pngs", dest="process_pngs", action="store_false")
    ap.add_argument("--process-luac", action="store_true", help="Strip sign + XXTEA-decrypt for .luac files")
    ap.add_argument("--jobs", type=int, default=max(1, multiprocessing.cpu_count()), help="Parallel workers (default: CPU count)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = Path(args.scan_root).resolve()
    if not root.exists():
        print(f"[init] scan_root does not exist: {root}")
        sys.exit(1)

    out_root = Path(args.out_dir).resolve() if args.out_dir else None
    if out_root:
        safe_makedirs(out_root)

    xor_key = PNG_XOR_KEY_FALLBACK
    if args.key_file:
        key_path = Path(args.key_file).resolve()
        if not key_path.exists():
            print(f"[init] key file not found: {key_path}")
            sys.exit(1)
        xor_key = key_path.read_bytes()

    keep_patterns = args.keep if args.keep else DEFAULT_KEEP_PATTERNS
    windows = [0xC8, 0x100]

    print(f"[init] root={root}")
    print(f"[init] out_dir={out_root if out_root else '(in-place)'}")
    print(f"[init] jobs={args.jobs} transcode={args.transcode_basis} rename_basis={args.rename_basis}")
    print(f"[init] key_bytes={len(xor_key)} keep={keep_patterns}")

    all_files = gather_files(root)
    print(f"[init] discovered {len(all_files)} files")

    jobs: List[Dict] = []
    for p in all_files:
        rel = p.relative_to(root)
        jobs.append(dict(
            src=str(p),
            dst_root=str(out_root) if out_root else "",
            rel=str(rel),
            xor_key_bytes=xor_key,
            windows=windows,
            keep_patterns=keep_patterns,
            rename_basis=args.rename_basis,
            transcode_basis=args.transcode_basis,
            process_pngs=args.process_pngs,
            process_luac=args.process_luac,
            verbose=args.verbose,
        ))

    # Run
    results: List[Tuple[str,str,str,str,str]] = []
    csv_path = (out_root if out_root else root) / "bsymg_results.csv"

    # Windows note: protect entry point for multiprocessing
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [ex.submit(process_one, j) for j in jobs]
        for f in as_completed(futs):
            try:
                row = f.result()
            except Exception as e:
                row = ("", "", "error", f"worker_exception:{e}", "")
            results.append(row)

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source","dest","action","reason","extras"])
        w.writerows(results)

    print(f"[complete] {len(results)} files processed, log: {csv_path}")

if __name__ == "__main__":
    main()
