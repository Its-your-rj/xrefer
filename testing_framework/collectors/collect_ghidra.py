"""
Ghidra Metrics Collector (Ground Truth)
Runs Ghidra via pyghidra on a binary and outputs a metrics JSON.
This is the ground truth all other backends are compared against.
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
    import pyghidra

    t0 = time.time()
    with pyghidra.open_program(binary_path) as flat_api:
        elapsed = round(time.time() - t0, 3)
        program = flat_api.getCurrentProgram()

        # image base
        image_base = program.getImageBase().getOffset()

        # functions (exclude external)
        func_mgr = program.getFunctionManager()
        funcs = [f for f in func_mgr.getFunctions(True) if not f.isExternal()]
        func_count = len(funcs)

        # entry points
        sym_table = program.getSymbolTable()
        entry_points = []
        for sym in sym_table.getAllSymbols(True):
            if sym.isExternalEntryPoint():
                entry_points.append(hex(sym.getAddress().getOffset()))

        # imports
        ext_mgr = program.getExternalManager()
        import_names = []
        seen = set()
        for sym in sym_table.getExternalSymbols():
            loc = ext_mgr.getExternalLocation(sym)
            if loc:
                name = loc.getLabel() or sym.getName()
                if name and name not in seen:
                    import_names.append(name)
                    seen.add(name)

        # strings
        listing = program.getListing()
        strings = []
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            if data.hasStringValue():
                val = data.getValue()
                if val and isinstance(val, str) and len(val) >= 5:
                    strings.append(val)

        # call edges via xrefs
        ref_mgr = program.getReferenceManager()
        memory = program.getMemory()
        call_edges = 0
        func_addrs = set()
        for f in funcs:
            func_addrs.add(f.getEntryPoint().getOffset())

        for f in funcs:
            refs = ref_mgr.getReferencesFrom(f.getEntryPoint())
            for ref in refs:
                to_addr = ref.getToAddress()
                if to_addr and to_addr.isMemoryAddress():
                    if memory.getBlock(to_addr) is not None:
                        if to_addr.getOffset() in func_addrs:
                            call_edges += 1

    return {
        "backend": "ghidra",
        "binary": binary_path,
        "sha256": sha256(binary_path),
        "analysis_time_seconds": elapsed,
        "metrics": {
            "functions_count": func_count,
            "entry_points_count": len(entry_points) if entry_points else 1,
            "entry_points": entry_points[:5],
            "image_base": hex(image_base),
            "imports_count": len(import_names),
            "import_names": import_names[:10],
            "strings_count": len(strings),
            "string_samples": strings[:5],
            "call_edges_count": call_edges,
            "artifacts_count": len(import_names) + len(strings),
        },
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Collect Ghidra ground truth metrics")
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
            "backend": "ghidra",
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
