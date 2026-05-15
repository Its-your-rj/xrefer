"""
SMDA Metrics Collector
Runs SMDA on a binary and outputs a metrics JSON.
Used for comparison against Ghidra ground truth.
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
    from smda.Disassembler import Disassembler

    t0 = time.time()
    report = Disassembler().disassembleFile(binary_path)
    elapsed = round(time.time() - t0, 3)

    funcs = list(report.getFunctions())
    func_set = {f.offset for f in funcs}

    # imports via apirefs
    imports = {}
    for f in funcs:
        for addr, name in f.apirefs.items():
            imports[name] = f.offset

    # call edges via outrefs
    call_edges = 0
    for f in funcs:
        for instr_va, targets in f.outrefs.items():
            for t in targets:
                if t in func_set and t != f.offset:
                    call_edges += 1

    # strings via stringrefs
    strings = {}
    for f in funcs:
        if f.stringrefs:
            for addr, s in f.stringrefs.items():
                if len(s) >= 5:
                    strings[s] = f.offset

    # entry point
    try:
        ep = report.base_addr + report.oep
    except Exception:
        ep = report.base_addr

    return {
        "backend": "smda",
        "binary": binary_path,
        "sha256": sha256(binary_path),
        "arch": f"{report.architecture} {report.bitness}-bit",
        "format": "PE" if report.bitness == 32 or "pe" in binary_path.lower() else "ELF",
        "analysis_time_seconds": elapsed,
        "metrics": {
            "functions_count": len(funcs),
            "entry_points_count": 1,
            "entry_point_va": hex(ep),
            "image_base": hex(report.base_addr),
            "imports_count": len(imports),
            "import_names": sorted(imports.keys())[:10],
            "strings_count": len(strings),
            "string_samples": list(strings.keys())[:5],
            "call_edges_count": call_edges,
            "artifacts_count": len(imports) + len(strings),
        },
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Collect SMDA metrics for a binary")
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
            "backend": "smda",
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
