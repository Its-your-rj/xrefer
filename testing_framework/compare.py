"""
Comparison Engine
Loads JSON results from all backends, computes % vs Ghidra ground truth,
and generates an HTML report.
Usage: python compare.py
"""
import sys
import os
import json
import glob

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(BASE_DIR, "results")
SAMPLES_JSONL = os.path.abspath(os.path.join(BASE_DIR, "../tests/e2e/xrefer-test/samples.jsonl"))
REPORT_PATH = os.path.join(BASE_DIR, "report", "comparison_report.html")

METRICS = [
    ("functions_count",   "Functions"),
    ("entry_points_count","Entry Points"),
    ("imports_count",     "Imports"),
    ("strings_count",     "Strings"),
    ("call_edges_count",  "Call Edges"),
    ("artifacts_count",   "Total Artifacts"),
    ("analysis_time_seconds", "Analysis Time (s)"),
]


def load_samples():
    samples = {}
    with open(SAMPLES_JSONL, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                s = json.loads(line)
                samples[s["id"]] = s
    return samples


def load_results():
    data = {}
    for backend in ["ghidra", "smda", "vivisect"]:
        pattern = os.path.join(RESULTS_DIR, backend, "*.json")
        for path in glob.glob(pattern):
            sha = os.path.basename(path).replace(".json", "")
            if sha not in data:
                data[sha] = {}
            with open(path, encoding="utf-8") as f:
                data[sha][backend] = json.load(f)
    return data


def pct(val, ref):
    if ref is None or ref == 0:
        return "N/A"
    if val is None:
        return "N/A"
    return f"{round(100 * val / ref, 1)}%"


def score_color(p):
    if p == "N/A":
        return "#888"
    v = float(p.replace("%", ""))
    if v >= 95:
        return "#2d8a4e"
    if v >= 80:
        return "#e6a817"
    return "#c0392b"


def generate_html(samples_meta, results):
    rows_html = ""
    summary_rows = []

    for sha, backends in sorted(results.items()):
        meta = samples_meta.get(sha, {})
        desc = meta.get("description", sha[:20])
        tags = meta.get("tags", [])
        lang = next((t for t in tags if t.startswith("lang:")), "unknown").replace("lang:", "").upper()
        fmt = "PE" if "format:exe" in tags else "ELF"
        size_kb = round(meta.get("size", 0) / 1024, 1)

        ghidra = backends.get("ghidra", {}).get("metrics", {})
        smda = backends.get("smda", {}).get("metrics", {})
        vivi = backends.get("vivisect", {}).get("metrics", {})

        has_error_smda = "error" in backends.get("smda", {})
        has_error_vivi = "error" in backends.get("vivisect", {})
        has_error_ghidra = "error" in backends.get("ghidra", {})

        smda_scores = []
        vivi_scores = []

        metric_rows = ""
        for key, label in METRICS:
            g_val = ghidra.get(key)
            s_val = smda.get(key)
            v_val = vivi.get(key)

            s_pct = pct(s_val, g_val)
            v_pct = pct(v_val, g_val)

            if key != "analysis_time_seconds":
                if s_pct != "N/A":
                    smda_scores.append(float(s_pct.replace("%", "")))
                if v_pct != "N/A":
                    vivi_scores.append(float(v_pct.replace("%", "")))

            s_color = score_color(s_pct) if key != "analysis_time_seconds" else "#333"
            v_color = score_color(v_pct) if key != "analysis_time_seconds" else "#333"

            metric_rows += f"""
            <tr>
              <td>{label}</td>
              <td class="num">{g_val if g_val is not None else "—"}</td>
              <td class="num" style="color:{s_color}">{s_val if s_val is not None else "—"}</td>
              <td class="num" style="color:{s_color}">{s_pct}</td>
              <td class="num" style="color:{v_color}">{v_val if v_val is not None else "—"}</td>
              <td class="num" style="color:{v_color}">{v_pct}</td>
            </tr>"""

        smda_avg = round(sum(smda_scores) / len(smda_scores), 1) if smda_scores else 0
        vivi_avg = round(sum(vivi_scores) / len(vivi_scores), 1) if vivi_scores else 0
        summary_rows.append((desc, lang, fmt, size_kb, smda_avg, vivi_avg))

        error_note = ""
        if has_error_ghidra:
            error_note += "<p class='error'>Ghidra ERROR — no ground truth available</p>"
        if has_error_smda:
            error_note += f"<p class='error'>SMDA ERROR: {backends['smda'].get('error','')[:100]}</p>"
        if has_error_vivi:
            error_note += f"<p class='error'>Vivisect ERROR: {backends['vivisect'].get('error','')[:100]}</p>"

        rows_html += f"""
        <div class="sample">
          <div class="sample-header">
            <span class="tag lang">{lang}</span>
            <span class="tag fmt">{fmt}</span>
            <span class="sample-title">{desc}</span>
            <span class="sample-size">{size_kb} KB</span>
            <span class="score smda-score" style="color:{score_color(str(smda_avg)+'%')}">SMDA {smda_avg}%</span>
            <span class="score vivi-score" style="color:{score_color(str(vivi_avg)+'%')}">Vivisect {vivi_avg}%</span>
          </div>
          <div class="sha">{sha}</div>
          {error_note}
          <table class="metrics">
            <tr>
              <th>Metric</th>
              <th>Ghidra (Truth)</th>
              <th>SMDA</th>
              <th>SMDA %</th>
              <th>Vivisect</th>
              <th>Vivisect %</th>
            </tr>
            {metric_rows}
          </table>
        </div>"""

    # summary table
    summary_html = ""
    for desc, lang, fmt, size_kb, smda_avg, vivi_avg in sorted(summary_rows, key=lambda x: x[0]):
        winner = "Vivisect" if vivi_avg >= smda_avg else "SMDA"
        w_color = "#2d8a4e"
        summary_html += f"""
        <tr>
          <td>{desc}</td>
          <td><span class="tag lang">{lang}</span></td>
          <td><span class="tag fmt">{fmt}</span></td>
          <td>{size_kb} KB</td>
          <td style="color:{score_color(str(smda_avg)+'%')}">{smda_avg}%</td>
          <td style="color:{score_color(str(vivi_avg)+'%')}">{vivi_avg}%</td>
          <td style="color:{w_color}"><b>{winner}</b></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>xrefer Backend Comparison — SMDA vs Vivisect vs Ghidra</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #222; margin: 0; padding: 20px; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: #16213e; margin-top: 40px; }}
  .summary-table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 40px; }}
  .summary-table th {{ background: #1a1a2e; color: white; padding: 10px 14px; text-align: left; }}
  .summary-table td {{ padding: 8px 14px; border-bottom: 1px solid #eee; }}
  .summary-table tr:hover {{ background: #f9f9f9; }}
  .sample {{ background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }}
  .sample-header {{ background: #1a1a2e; color: white; padding: 12px 16px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .sample-title {{ font-weight: bold; flex: 1; }}
  .sample-size {{ color: #aaa; font-size: 0.85em; }}
  .sha {{ font-family: monospace; font-size: 0.75em; color: #888; padding: 4px 16px; background: #f8f8f8; border-bottom: 1px solid #eee; }}
  .tag {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .lang {{ background: #4a90d9; color: white; }}
  .fmt {{ background: #e94560; color: white; }}
  .score {{ font-weight: bold; font-size: 0.9em; }}
  .metrics {{ width: 100%; border-collapse: collapse; }}
  .metrics th {{ background: #f0f0f0; padding: 8px 12px; text-align: left; font-size: 0.85em; color: #555; }}
  .metrics td {{ padding: 7px 12px; border-bottom: 1px solid #f0f0f0; font-size: 0.9em; }}
  .metrics tr:last-child td {{ border-bottom: none; }}
  .num {{ text-align: right; font-family: monospace; }}
  .error {{ color: #c0392b; padding: 8px 16px; background: #fdf0f0; margin: 0; font-size: 0.85em; }}
  .legend {{ display: flex; gap: 20px; margin-bottom: 16px; font-size: 0.85em; }}
  .legend span {{ display: flex; align-items: center; gap: 6px; }}
  .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
</style>
</head>
<body>
<h1>xrefer Backend Comparison Report</h1>
<p>Evaluating <b>SMDA</b> and <b>Vivisect</b> against <b>Ghidra</b> ground truth across {len(results)} binaries.</p>
<p>GSoC 2026 — Mandiant FLARE | Branch: gsoc_2026_next</p>

<div class="legend">
  <span><span class="dot" style="background:#2d8a4e"></span>≥95% — Excellent</span>
  <span><span class="dot" style="background:#e6a817"></span>80–94% — Acceptable</span>
  <span><span class="dot" style="background:#c0392b"></span>&lt;80% — Gap needs fixing</span>
</div>

<h2>Summary</h2>
<table class="summary-table">
  <tr>
    <th>Binary</th><th>Lang</th><th>Format</th><th>Size</th>
    <th>SMDA Score</th><th>Vivisect Score</th><th>Winner</th>
  </tr>
  {summary_html}
</table>

<h2>Detailed Results</h2>
{rows_html}
</body>
</html>"""
    return html


def main():
    samples_meta = load_samples()
    results = load_results()

    if not results:
        print("No results found. Run run_all.py first.")
        sys.exit(1)

    os.makedirs(os.path.join(BASE_DIR, "report"), exist_ok=True)
    html = generate_html(samples_meta, results)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report generated: {REPORT_PATH}")
    print(f"Samples covered: {len(results)}")


if __name__ == "__main__":
    main()
