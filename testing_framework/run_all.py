"""
Run All Collectors
Runs SMDA, Vivisect, and Ghidra on all 28 xrefer-test samples.
Saves one JSON per backend per sample in results/
Usage: python run_all.py [--backend smda|vivisect|ghidra|all]
"""
import sys
import os
import json
import subprocess
import argparse

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(__file__)
SAMPLES_DIR = os.path.abspath(os.path.join(BASE_DIR, "../tests/e2e/xrefer-test/samples"))
SAMPLES_JSONL = os.path.abspath(os.path.join(BASE_DIR, "../tests/e2e/xrefer-test/samples.jsonl"))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
COLLECTORS_DIR = os.path.join(BASE_DIR, "collectors")


def load_samples():
    samples = []
    with open(SAMPLES_JSONL, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def run_collector(backend, sha256, description, tags):
    binary_path = os.path.join(SAMPLES_DIR, sha256, "binary")
    if not os.path.exists(binary_path):
        print(f"  [SKIP] Binary not found: {sha256[:16]}...")
        return

    out_dir = os.path.join(RESULTS_DIR, backend)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{sha256}.json")

    if os.path.exists(out_path):
        print(f"  [SKIP] Already collected: {sha256[:16]}... ({backend})")
        return

    collector = os.path.join(COLLECTORS_DIR, f"collect_{backend}.py")
    print(f"  Running {backend} on {description[:40]}...", end=" ", flush=True)

    result = subprocess.run(
        [sys.executable, collector, "--sha256", sha256, "--out", out_path],
        capture_output=True, text=True, timeout=300
    )

    if result.returncode == 0:
        print("OK")
    else:
        print(f"ERROR: {result.stderr[:100]}")
        error_data = {
            "backend": backend,
            "sha256": sha256,
            "description": description,
            "error": result.stderr[:500],
            "metrics": {}
        }
        with open(out_path, "w") as f:
            json.dump(error_data, f, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default="all",
                        choices=["smda", "vivisect", "ghidra", "all"],
                        help="Which backend to run")
    parser.add_argument("--tags", help="Filter samples by tag (e.g. lang:rust)")
    args = parser.parse_args()

    samples = load_samples()

    if args.tags:
        samples = [s for s in samples if args.tags in s.get("tags", [])]

    backends = ["smda", "vivisect", "ghidra"] if args.backend == "all" else [args.backend]

    print(f"\nxrefer Testing Framework")
    print(f"{'='*60}")
    print(f"Samples : {len(samples)}")
    print(f"Backends: {', '.join(backends)}")
    print(f"{'='*60}\n")

    for sample in samples:
        sha = sample["id"]
        desc = sample.get("description", sha[:16])
        tags = sample.get("tags", [])
        lang = next((t for t in tags if t.startswith("lang:")), "unknown")
        fmt = "PE" if "format:exe" in tags else "ELF"

        print(f"\n[{lang.upper()} | {fmt}] {desc}")
        print(f"  SHA256: {sha[:32]}...")

        for backend in backends:
            run_collector(backend, sha, desc, tags)

    print(f"\n{'='*60}")
    print("Collection complete. Run compare.py to generate HTML report.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
