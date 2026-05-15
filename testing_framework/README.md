# xrefer Testing Framework
# GSoC 2026 — Backend Evaluation (SMDA vs Vivisect vs Ghidra)

## Purpose
Evaluate SMDA and Vivisect as pure-Python backends for xrefer,
using Ghidra as ground truth across 28 real binaries.

## Sample Set (28 binaries from xrefer-test)
| Language | Count | Format | Baselines |
|----------|-------|--------|-----------|
| C        | 6     | ELF    | hello world, fibonacci, strings, fileio, crypto, inputvalidation |
| C++      | 5     | ELF    | hello world, fibonacci, fileio, crypto, inputvalidation |
| Go       | 6     | ELF    | hello world, fibonacci, fileio, crypto, inputvalidation, networking |
| Rust     | 8     | ELF    | hello world, fibonacci, fileio, crypto, inputvalidation, networking + 2 itw |
| Malware  | 3     | PE     | PMA Lab 21-01, ALPHV BlackCat, Rust ITW |

## Metrics Collected Per Binary
1. functions_count — total functions discovered
2. entry_points_count — number of entry points
3. imports_count — total imports resolved
4. strings_count — strings found (min length 5)
5. call_edges_count — function→function edges
6. artifacts_count — imports + strings combined
7. analysis_time_seconds — backend speed

## Usage

### Run a single backend on one sample
```bash
python collectors/collect_smda.py --sha256 <sha256>
python collectors/collect_vivisect.py --sha256 <sha256>
python collectors/collect_ghidra.py --sha256 <sha256>
```

### Run all backends on all 28 samples
```bash
python run_all.py --backend all
```

### Run one backend only
```bash
python run_all.py --backend smda
python run_all.py --backend vivisect
python run_all.py --backend ghidra
```

### Filter by language
```bash
python run_all.py --backend all --tags lang:rust
```

### Generate HTML comparison report
```bash
python compare.py
# Opens: report/comparison_report.html
```

## Folder Structure
```
testing_framework/
├── collectors/
│   ├── collect_smda.py      SMDA collector
│   ├── collect_vivisect.py  Vivisect collector (with BB iteration fix)
│   └── collect_ghidra.py    Ghidra ground truth collector
├── results/
│   ├── ghidra/              one JSON per sample
│   ├── smda/                one JSON per sample
│   └── vivisect/            one JSON per sample
├── report/
│   └── comparison_report.html  generated HTML report
├── run_all.py               batch runner
├── compare.py               comparison + HTML generator
└── README.md
```

## Workflow (VM + Windows)
- **Program on Windows** (VS Code, edit scripts here)
- **Run on VM** (Ubuntu, execute collectors against binaries)
- **Results on VM** → copy JSONs to Windows → run compare.py → HTML report

## Mentor Alignment
- Ground truth: Ghidra via pyghidra
- Sample diversity: C/C++/Go/Rust ELF + Windows PE malware
- Metrics: functions, entry points, imports, strings, call edges, artifacts
- Output: JSON per backend + HTML comparison report
- Next: debug mode in xrefer CLI (--debug flag → metrics JSON dump)
