"""
Vivisect Metrics Collector
Runs Vivisect on a binary and outputs a metrics JSON.
Uses BB iteration for complete call edge coverage.
"""
import sys
import os
import json
import time
import hashlib

sys.stdout.reconfigure(encoding="utf-8")

SAMPLES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../tests/e2e/xrefer-test/samples")
)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def collect(binary_path):
    import vivisect
    import vivisect.const as vc

    t0 = time.time()
    vw = vivisect.VivWorkspace()
    vw.loadFromFile(binary_path)
    vw.analyze()
    elapsed = round(time.time() - t0, 3)

    funcs = vw.getFunctions()
    func_set = set(funcs)

    # imports
    imports = vw.getImports()
    import_names = {imp[3]: imp[0] for imp in imports}

    # call edges via BB iteration (critical fix — getXrefsFrom on func_va alone misses edges)
    callers_index = {}
    for func_va in funcs:
        try:
            for bb_va, bb_size, bb_funcs in vw.getFunctionBlocks(func_va):
                offset = bb_va
                end = bb_va + bb_size
                while offset < end:
                    for from_va, to_va, rtype, rinfo in vw.getXrefsFrom(offset):
                        if to_va in func_set and to_va != func_va:
                            callers_index.setdefault(to_va, set()).add(func_va)
                    try:
                        ltype, linfo, lsize, lva = vw.getLocation(offset)
                        offset += lsize if lsize > 0 else 1
                    except Exception:
                        offset += 1
        except Exception:
            pass

    call_edges = sum(len(v) for v in callers_index.values())

    # strings — format-aware decode
    all_strings = []
    for ltype_check in [vc.LOC_STRING, vc.LOC_UNI]:
        try:
            for va, size, ltype, linfo in vw.getLocations(ltype=ltype_check):
                try:
                    raw = vw.readMemory(va, size)
                    if ltype_check == vc.LOC_UNI:
                        s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                    else:
                        s = raw.decode("utf-8", errors="replace").rstrip("\x00")
                    if len(s) >= 5:
                        all_strings.append(s)
                except Exception:
                    pass
        except Exception:
            pass

    image_base = vw.getMemoryMaps()[0][0]

    # entry points
    entry_points = []
    try:
        for ep in vw.getEntryPoints():
            entry_points.append(hex(ep))
    except Exception:
        entry_points = [hex(image_base)]

    return {
        "backend": "vivisect",
        "binary": binary_path,
        "sha256": sha256(binary_path),
        "analysis_time_seconds": elapsed,
        "metrics": {
            "functions_count": len(funcs),
            "entry_points_count": len(entry_points),
            "entry_points": entry_points[:5],
            "image_base": hex(image_base),
            "imports_count": len(import_names),
            "import_names": list(import_names.keys())[:10],
            "strings_count": len(all_strings),
            "string_samples": all_strings[:5],
            "call_edges_count": call_edges,
            "artifacts_count": len(import_names) + len(all_strings),
        },
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Collect Vivisect metrics for a binary")
    parser.add_argument("--sha256", help="SHA256 of sample in xrefer-test suite")
    parser.add_argument("--binary", help="Direct path to binary")
    parser.add_argument("--out", help="Output JSON path (default: print to stdout)")
    args = parser.parse_args()

    if args.sha256:
        binary_path = os.path.join(SAMPLES_DIR, args.sha256, "binary")
    elif args.binary:
        binary_path = args.binary
    else:
        print("ERROR: provide --sha256 or --binary", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(binary_path):
        print(f"ERROR: binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    try:
        result = collect(binary_path)
    except Exception as e:
        result = {
            "backend": "vivisect",
            "binary": binary_path,
            "error": str(e),
            "metrics": {},
        }

    out = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Written to {args.out}")
    else:
        print(out)


if __name__ == "__main__":
    main()
