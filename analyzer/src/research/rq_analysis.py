"""
RQ Analysis — LLM Security Auditing Study
==========================================
RQ A: Trustworthiness Score — which metric combination best captures trustworthiness?
RQ B: Model Benchmarking — how do 6 open-weight models compare?
RQ C: Failure Taxonomy — where do models fail, and why?

Run from analyzer/ root:
    python src/research/rq_analysis.py
"""

import json
import glob
import os
import re
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import pingouin as pg

warnings.filterwarnings("ignore")

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
VALIDATED_DIR = ROOT / "validated"
RESEARCH_DIR = ROOT / "src" / "research"
PLOTS_DIR = RESEARCH_DIR / "plots"
OUT_DIR = VALIDATED_DIR / "rq_outputs"

CALLSITE_FILES = {
    "bina": RESEARCH_DIR / "callsite_results_bina_filtered_filled_researcher.json",
    "yusuf": RESEARCH_DIR / "callsite_results_yusuf_filtered_filled.json",
    "denisa": RESEARCH_DIR / "callsite_results_denisa_filtered_filled.json",
    "lily": RESEARCH_DIR / "evaluations_lily" / "evaluations_lily.merged.json",
}
RESEARCHER_LABELS = {"bina": "R1", "yusuf": "R2", "lily": "R3", "denisa": "R4"}

METRICS = ["hallucinationFrequency", "technicalAccuracy", "effectChainAwareness", "attackSurfaceCoverage"]
SHORT_LABELS = ["HF", "TA", "ECA", "ASC"]
MODEL_SHORT = {
    "ollama/qwen2.5-coder:7b": "qwen2.5",
    "ollama/deepseek-r1:8b": "deepseek-r1",
    "ollama/starcoder2:7b": "starcoder2",
    "ollama/phi4:14b": "phi4",
    "ollama/llama3.2:3b": "llama3.2",
    "ollama/gemma3:12b": "gemma3",
}


# ─── Data Loaders ─────────────────────────────────────────────────────────────

def load_conclusions() -> pd.DataFrame:
    """Aggregate per-app per-model researcherConclusion across all callsite files.

    For each (app, model), average each metric across every permutation/callsite/researcher
    that supplied a researcherConclusion entry for that model.
    """
    bucket: dict[tuple[str, str], list[dict]] = {}
    for path in CALLSITE_FILES.values():
        with open(path) as f:
            data = json.load(f)
        for entry in data:
            m = re.search(r"APP:\s*([^\n]+)", entry.get("context", ""))
            if not m:
                continue
            app = m.group(1).strip()
            for perm in entry.get("permutations", []):
                rc = perm.get("researcherConclusion", {})
                if not isinstance(rc, dict):
                    continue
                for model, metrics in rc.items():
                    if not isinstance(metrics, dict):
                        continue
                    bucket.setdefault((app, model), []).append(metrics)
    rows = []
    for (app, model), items in bucket.items():
        row = {"app": app, "model": model}
        for k in METRICS:
            vals = [
                float(it[k]) for it in items
                if isinstance(it.get(k), (int, float)) and not isinstance(it.get(k), bool)
            ]
            row[k] = float(np.mean(vals)) if vals else np.nan
        rows.append(row)
    df = pd.DataFrame(rows)
    df["model_short"] = df["model"].map(MODEL_SHORT)
    return df


def load_callsite_results() -> pd.DataFrame:
    """Load all three callsite result JSONs → flat DataFrame of per-audit rows."""
    rows = []
    for researcher_name, path in CALLSITE_FILES.items():
        with open(path) as f:
            data = json.load(f)
        for entry in data:
            cid = entry["identifiedCallsiteID"]
            ctx_len = len(entry.get("context", ""))
            # Cross-language indicator: Java class + JS function patterns
            ctx = entry.get("context", "")
            # Bridge complexity: number of exposed methods (proxy for Java-JS surface area)
            n_methods = len(re.findall(r'\[METHOD \d+\]', ctx))

            for perm in entry.get("permutations", []):
                audits = perm.get("audits", {})
                for auditor, inspector_scores in audits.items():
                    for inspector, metrics in inspector_scores.items():
                        if not isinstance(metrics, dict):
                            continue
                        row = {
                            "researcher": researcher_name,
                            "callsite_id": cid,
                            "context_length": ctx_len,
                            "n_methods": n_methods,
                            "auditor": auditor,
                            "inspector": inspector,
                        }
                        for k in METRICS:
                            v = metrics.get(k)
                            row[k] = float(v) if isinstance(v, (int, float)) else np.nan
                        rows.append(row)
    df = pd.DataFrame(rows)
    df["inspector_short"] = df["inspector"].map(MODEL_SHORT)
    df["auditor_short"] = df["auditor"].map(MODEL_SHORT)
    df["researcher"] = df["researcher"].map(RESEARCHER_LABELS).fillna(df["researcher"])
    return df


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Add normalized columns (all → [0,1], HF inverted)."""
    df = df.copy()
    df["inv_hf"] = 1 - df["hallucinationFrequency"]
    df["ta_norm"] = df["technicalAccuracy"] / 10
    df["eca_norm"] = df["effectChainAwareness"] / 10
    df["asc_norm"] = df["attackSurfaceCoverage"]
    return df


# ─── RQ A: Trustworthiness Score ──────────────────────────────────────────────

def rq_a(df_conclusions: pd.DataFrame, df_callsite: pd.DataFrame) -> dict:
    print("\n" + "=" * 60)
    print("RQ A — Trustworthiness Score")
    print("=" * 60)

    df = normalize(df_conclusions)
    norm_cols = ["inv_hf", "ta_norm", "eca_norm", "asc_norm"]
    norm_labels = ["1-HF", "TA/10", "ECA/10", "ASC"]

    # ── Correlation matrix ──────────────────────────────────────────────────
    pearson = df[norm_cols].corr(method="pearson")
    spearman = df[norm_cols].corr(method="spearman")
    pearson.columns = spearman.columns = norm_labels
    pearson.index = spearman.index = norm_labels
    print("\nPearson correlation (normalized metrics):")
    print(pearson.round(3).to_string())

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    sns.heatmap(pearson, annot=True, fmt=".2f", cmap="coolwarm", vmin=-1, vmax=1,
                ax=axes[0], square=True)
    axes[0].set_title("Pearson Correlation")
    sns.heatmap(spearman, annot=True, fmt=".2f", cmap="coolwarm", vmin=-1, vmax=1,
                ax=axes[1], square=True)
    axes[1].set_title("Spearman Correlation")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqa_correlation.png", dpi=150)
    plt.close()

    pearson.to_csv(OUT_DIR / "correlation_matrix_pearson.csv")
    spearman.to_csv(OUT_DIR / "correlation_matrix_spearman.csv")

    # ── PCA ─────────────────────────────────────────────────────────────────
    X = df[norm_cols].dropna().values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    pca = PCA(n_components=4)
    pca.fit(X_scaled)

    loadings = pd.DataFrame(
        pca.components_.T,
        index=norm_labels,
        columns=[f"PC{i+1}" for i in range(4)]
    )
    explained = pd.Series(pca.explained_variance_ratio_, index=[f"PC{i+1}" for i in range(4)])
    print(f"\nPCA explained variance: {explained.round(3).to_dict()}")
    print("\nPCA loadings:")
    print(loadings.round(3).to_string())

    # PCA-derived weights from PC1 (largest variance component)
    pc1_abs = np.abs(pca.components_[0])
    pca_weights = pc1_abs / pc1_abs.sum()
    pca_weight_dict = dict(zip(norm_labels, pca_weights))
    print(f"\nPCA-derived weights (PC1): {dict(zip(norm_labels, pca_weights.round(3)))}")

    loadings.to_csv(OUT_DIR / "pca_loadings.csv")
    pd.DataFrame({"explained_variance_ratio": explained}).to_csv(OUT_DIR / "pca_variance.csv")

    # PCA scree plot
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    axes[0].bar([f"PC{i+1}" for i in range(4)], explained * 100)
    axes[0].set_ylabel("Explained Variance (%)")
    axes[0].set_title("PCA Scree Plot")

    x = np.arange(len(norm_labels))
    w = 0.2
    for i, col in enumerate(loadings.columns):
        axes[1].bar(x + i * w, loadings[col], w, label=col)
    axes[1].set_xticks(x + w * 1.5)
    axes[1].set_xticklabels(norm_labels)
    axes[1].set_title("PCA Loadings")
    axes[1].legend()
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqa_pca.png", dpi=150)
    plt.close()

    # ── Composite Trustworthiness Score ─────────────────────────────────────
    df["TS_equal"] = df[norm_cols].mean(axis=1)
    df["TS_pca"] = sum(df[c] * w for c, w in zip(norm_cols, pca_weights))

    print(f"\nTS_equal (equal weights): mean={df['TS_equal'].mean():.3f} ± {df['TS_equal'].std():.3f}")
    print(f"TS_pca   (PC1 weights):   mean={df['TS_pca'].mean():.3f} ± {df['TS_pca'].std():.3f}")
    corr_ts = df[["TS_equal", "TS_pca"]].corr().iloc[0, 1]
    print(f"Correlation TS_equal vs TS_pca: {corr_ts:.3f}")

    # ── Inter-auditor reliability (ICC) ─────────────────────────────────────
    # For each inspector × callsite, compute ICC across 6 auditors
    icc_results = {}
    for metric in METRICS:
        try:
            # Wide format: rows = inspector×callsite, cols = auditors
            pivot = df_callsite.pivot_table(
                index=["researcher", "callsite_id", "inspector"],
                columns="auditor",
                values=metric
            ).dropna()
            if pivot.empty or pivot.shape[1] < 2:
                continue
            # Melt for pingouin ICC
            long = pivot.reset_index().melt(
                id_vars=["researcher", "callsite_id", "inspector"],
                var_name="auditor", value_name="score"
            )
            long["subject"] = long["researcher"] + "_" + long["callsite_id"] + "_" + long["inspector"]
            icc = pg.intraclass_corr(data=long, targets="subject", raters="auditor",
                                     ratings="score", nan_policy="omit")
            # ICC(A,1) = two-way mixed, absolute agreement, single measures
            row_icc = icc[icc["Type"] == "ICC(A,1)"].iloc[0]
            ci = row_icc["CI95"]
            icc_results[metric] = {
                "ICC_A1": round(float(row_icc["ICC"]), 3),
                "CI95_low": round(float(ci[0]), 3),
                "CI95_high": round(float(ci[1]), 3),
                "p-value": float(row_icc["pval"]),
            }
        except Exception as e:
            icc_results[metric] = {"error": str(e)}

    icc_df = pd.DataFrame(icc_results).T
    print("\nInter-auditor ICC (ICC2):")
    print(icc_df.to_string())
    icc_df.to_csv(OUT_DIR / "icc_inter_auditor.csv")

    # ── Write formula summary ────────────────────────────────────────────────
    formula_lines = [
        "# Trustworthiness Score Formula\n",
        "## Normalized inputs",
        "  inv_hf  = 1 - hallucinationFrequency           # range [0,1]",
        "  ta_norm = technicalAccuracy / 10               # range [0,1]",
        "  eca_norm= effectChainAwareness / 10            # range [0,1]",
        "  asc_norm= attackSurfaceCoverage                # range [0,1]",
        "",
        "## Baseline (equal weights)",
        "  TS_equal = 0.25 * (inv_hf + ta_norm + eca_norm + asc_norm)",
        "",
        "## PCA-derived weights (from PC1 on validated/conclusions.json)",
    ]
    for label, w in zip(norm_labels, pca_weights):
        formula_lines.append(f"  w_{label.replace('/', '_')} = {w:.4f}")
    formula_lines.append("")
    ts_formula = " + ".join(f"{w:.4f}*{c}" for c, w in zip(norm_labels, pca_weights))
    formula_lines.append(f"  TS_pca = {ts_formula}")
    formula_lines.append("")
    formula_lines.append(f"## Correlation between TS_equal and TS_pca: r = {corr_ts:.3f}")

    with open(OUT_DIR / "trustworthiness_formula.md", "w") as f:
        f.write("\n".join(formula_lines))

    return {"df_norm": df, "pca_weights": pca_weights, "norm_labels": norm_labels}


# ─── RQ B: Model Benchmarking ─────────────────────────────────────────────────

def rq_b(df_conclusions: pd.DataFrame, rqa_out: dict) -> None:
    print("\n" + "=" * 60)
    print("RQ B — Model Benchmarking")
    print("=" * 60)

    df = rqa_out["df_norm"]
    pca_weights = rqa_out["pca_weights"]
    norm_cols = ["inv_hf", "ta_norm", "eca_norm", "asc_norm"]
    norm_labels = rqa_out["norm_labels"]

    # ── Summary table ────────────────────────────────────────────────────────
    agg = df.groupby("model_short")[["TS_equal", "TS_pca"] + norm_cols + METRICS].agg(["mean", "std"])
    agg.columns = ["_".join(c) for c in agg.columns]
    agg = agg.sort_values("TS_equal_mean", ascending=False)
    print("\nModel Summary (sorted by TS_equal):")
    print(agg[["TS_equal_mean", "TS_equal_std", "TS_pca_mean"]].round(3).to_string())
    agg.to_csv(OUT_DIR / "model_summary_table.csv")

    # ── Kruskal-Wallis + pairwise Mann-Whitney ────────────────────────────────
    sig_rows = []
    for metric in ["TS_equal", "TS_pca"] + METRICS:
        groups = [g[metric].dropna().values for _, g in df.groupby("model_short")]
        h, p_kw = stats.kruskal(*groups)
        sig_rows.append({"metric": metric, "H_stat": round(h, 3), "p_kruskal": round(p_kw, 4)})

    sig_df = pd.DataFrame(sig_rows)
    print("\nKruskal-Wallis tests:")
    print(sig_df.to_string(index=False))
    sig_df.to_csv(OUT_DIR / "kruskal_wallis.csv", index=False)

    # Pairwise Mann-Whitney for TS_equal
    models = sorted(df["model_short"].unique())
    pw_matrix = pd.DataFrame(index=models, columns=models, dtype=float)
    for i, m1 in enumerate(models):
        for j, m2 in enumerate(models):
            if i == j:
                pw_matrix.loc[m1, m2] = 1.0
            else:
                a = df[df["model_short"] == m1]["TS_equal"].dropna().values
                b = df[df["model_short"] == m2]["TS_equal"].dropna().values
                _, p = stats.mannwhitneyu(a, b, alternative="two-sided")
                # Bonferroni: n_comparisons = n*(n-1)/2
                n_comp = len(models) * (len(models) - 1) / 2
                pw_matrix.loc[m1, m2] = min(p * n_comp, 1.0)  # Bonferroni-corrected

    print("\nPairwise Mann-Whitney (Bonferroni-corrected p-values) for TS_equal:")
    print(pw_matrix.round(4).to_string())
    pw_matrix.to_csv(OUT_DIR / "significance_matrix.csv")

    # ── Visualizations ───────────────────────────────────────────────────────

    # 1. Box plots: TS_equal distribution per model
    fig, ax = plt.subplots(figsize=(10, 5))
    order = agg.index.tolist()
    df_plot = df[df["model_short"].notna()]
    sns.boxplot(data=df_plot, x="model_short", y="TS_equal", order=order, ax=ax, palette="Set2")
    sns.stripplot(data=df_plot, x="model_short", y="TS_equal", order=order, ax=ax,
                  color="black", size=3, alpha=0.5)
    ax.set_title("Trustworthiness Score (equal weights) — per model across 24 apps")
    ax.set_xlabel("Model")
    ax.set_ylabel("TS_equal [0,1]")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqb_boxplots.png", dpi=150)
    plt.close()

    # 2. Heatmap: models × 4 raw metrics (mean, z-scored)
    heat_data = df.groupby("model_short")[METRICS].mean()
    heat_data.columns = SHORT_LABELS
    heat_z = (heat_data - heat_data.mean()) / heat_data.std()
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.heatmap(heat_z, annot=heat_data.round(2), fmt="g", cmap="RdYlGn", ax=ax,
                linewidths=0.5, cbar_kws={"label": "z-score"})
    ax.set_title("Model Performance Heatmap (z-scored, annotated with raw means)")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqb_heatmap.png", dpi=150)
    plt.close()

    # 3. Radar / spider chart
    norm_means = df.groupby("model_short")[norm_cols].mean()
    norm_means.columns = norm_labels
    model_list = norm_means.index.tolist()
    N = len(norm_labels)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw={"polar": True})
    colors = plt.cm.tab10(np.linspace(0, 1, len(model_list)))
    for model, color in zip(model_list, colors):
        vals = norm_means.loc[model].tolist() + norm_means.loc[model].tolist()[:1]
        ax.plot(angles, vals, "o-", linewidth=1.5, label=model, color=color)
        ax.fill(angles, vals, alpha=0.1, color=color)
    ax.set_thetagrids(np.degrees(angles[:-1]), norm_labels)
    ax.set_ylim(0, 1)
    ax.set_title("Model Performance Radar (normalized metrics)", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1), fontsize=8)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqb_radar.png", dpi=150)
    plt.close()

    # 4. Cross-researcher consistency
    cs_df = load_callsite_results()
    cs_df = normalize_callsite(cs_df)
    cs_agg = cs_df.groupby(["researcher", "inspector_short"])["TS_equal"].mean().reset_index()
    fig, ax = plt.subplots(figsize=(10, 5))
    researchers = cs_agg["researcher"].unique()
    x = np.arange(len(models))
    w = 0.2
    palette = {"R1": "#4C72B0", "R2": "#DD8452", "R3": "#55A868", "R4": "#C44E52"}
    for i, res in enumerate(sorted(researchers)):
        sub = cs_agg[cs_agg["researcher"] == res].set_index("inspector_short")
        vals = [sub.loc[m, "TS_equal"] if m in sub.index else np.nan for m in models]
        ax.bar(x + i * w, vals, w, label=res, color=palette.get(res, f"C{i}"))
    ax.set_xticks(x + w * 1.5)
    ax.set_xticklabels(models, rotation=30, ha="right")
    ax.set_ylabel("Mean TS_equal")
    ax.set_title("Cross-researcher Consistency — TS_equal per model")
    ax.legend()
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqb_cross_researcher.png", dpi=150)
    plt.close()

    print("\nPlots saved: rqb_boxplots.png, rqb_heatmap.png, rqb_radar.png, rqb_cross_researcher.png")


def normalize_callsite(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["inv_hf"] = 1 - df["hallucinationFrequency"]
    df["ta_norm"] = df["technicalAccuracy"] / 10
    df["eca_norm"] = df["effectChainAwareness"] / 10
    df["asc_norm"] = df["attackSurfaceCoverage"]
    norm_cols = ["inv_hf", "ta_norm", "eca_norm", "asc_norm"]
    df["TS_equal"] = df[norm_cols].mean(axis=1)
    return df


# ─── RQ C: Failure Taxonomy ───────────────────────────────────────────────────

def rq_c(df_callsite: pd.DataFrame) -> None:
    print("\n" + "=" * 60)
    print("RQ C — Failure Taxonomy")
    print("=" * 60)

    df = normalize_callsite(df_callsite)

    # ── Zero-score detection ─────────────────────────────────────────────────
    zero_mask = (df["technicalAccuracy"] == 0) & (df["attackSurfaceCoverage"] == 0)
    zero_df = df[zero_mask]
    zero_by_model = zero_df.groupby("inspector_short").size().sort_values(ascending=False)
    total_by_model = df.groupby("inspector_short").size()
    zero_pct = (zero_by_model / total_by_model * 100).round(1)
    print("\nZero-score rate per model (TA=0 AND ASC=0):")
    print(zero_pct.to_frame("zero_pct_%").to_string())

    # ── Context length vs performance ────────────────────────────────────────
    print("\nContext length vs metric correlations (Pearson r, all models pooled):")
    corr_rows = []
    for metric in METRICS + ["TS_equal"]:
        sub = df[["context_length", metric]].dropna()
        r, p = stats.pearsonr(sub["context_length"], sub[metric])
        corr_rows.append({"metric": metric, "r": round(r, 3), "p": round(p, 4)})
    corr_ctx = pd.DataFrame(corr_rows)
    print(corr_ctx.to_string(index=False))

    # Per-model context length correlations
    per_model_ctx = []
    for model, g in df.groupby("inspector_short"):
        for metric in ["TS_equal", "attackSurfaceCoverage", "hallucinationFrequency"]:
            sub = g[["context_length", metric]].dropna()
            if len(sub) < 5:
                continue
            r, p = stats.pearsonr(sub["context_length"], sub[metric])
            per_model_ctx.append({"model": model, "metric": metric, "r": round(r, 3), "p": round(p, 4)})
    per_model_ctx_df = pd.DataFrame(per_model_ctx)
    print("\nPer-model context length correlations:")
    print(per_model_ctx_df.to_string(index=False))

    # Context length scatter plot (pooled)
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    for ax, metric, label in zip(axes.flat, METRICS, SHORT_LABELS):
        for model, g in df.groupby("inspector_short"):
            sub = g[["context_length", metric]].dropna()
            ax.scatter(sub["context_length"], sub[metric], s=10, alpha=0.5, label=model)
        ax.set_xlabel("Context Length (chars)")
        ax.set_ylabel(label)
        ax.set_title(f"Context Length vs {label}")
    handles, labels = axes.flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, fontsize=8,
               bbox_to_anchor=(0.5, -0.02))
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "rqc_context_length.png", dpi=150, bbox_inches="tight")
    plt.close()

    # ── Hallucination spike analysis ─────────────────────────────────────────
    spike_mask = df["hallucinationFrequency"] > 0.5
    spike_df = df[spike_mask]
    spike_by_model = spike_df.groupby("inspector_short").size().sort_values(ascending=False)
    spike_pct = (spike_by_model / total_by_model * 100).round(1)
    print("\nHallucination spike rate (HF > 0.5) per model:")
    print(spike_pct.to_frame("spike_pct_%").to_string())

    ctx_in_spikes = spike_df["context_length"].describe()
    ctx_in_normal = df[~spike_mask]["context_length"].describe()
    print(f"\nContext length in spikes — mean: {spike_df['context_length'].mean():.0f}  "
          f"normal — mean: {df[~spike_mask]['context_length'].mean():.0f}")

    # ── Bridge complexity vs performance ─────────────────────────────────────
    # All callsites are Java-JS bridges; n_methods proxies surface area / cross-language complexity
    print("\nBridge method count vs metric correlations (Pearson r, all models pooled):")
    bridge_rows = []
    for metric in METRICS + ["TS_equal"]:
        sub = df[["n_methods", metric]].dropna()
        r, p = stats.pearsonr(sub["n_methods"], sub[metric])
        bridge_rows.append({"metric": metric, "r": round(r, 3), "p": round(p, 4)})
    bridge_corr = pd.DataFrame(bridge_rows)
    print(bridge_corr.to_string(index=False))
    bridge_corr.to_csv(OUT_DIR / "bridge_complexity_correlations.csv", index=False)

    # Quartile split: low-complexity (≤ median methods) vs high-complexity bridges
    med_methods = df["n_methods"].median()
    high_bridge = df[df["n_methods"] > med_methods]
    low_bridge = df[df["n_methods"] <= med_methods]
    print(f"\nBridge complexity split: median={med_methods:.0f} methods")
    print(f"  high-complexity (>{med_methods:.0f} methods): {high_bridge['callsite_id'].nunique()} callsites")
    print(f"  low-complexity  (≤{med_methods:.0f} methods): {low_bridge['callsite_id'].nunique()} callsites")
    if not high_bridge.empty and not low_bridge.empty:
        print("\nMetric comparison — high vs low bridge complexity:")
        for metric in METRICS + ["TS_equal"]:
            mh = high_bridge[metric].mean()
            ml = low_bridge[metric].mean()
            _, p = stats.mannwhitneyu(high_bridge[metric].dropna(), low_bridge[metric].dropna(),
                                      alternative="two-sided")
            print(f"  {metric:30s}  high={mh:.3f}  low={ml:.3f}  p={p:.4f}")

    # ── Failure taxonomy summary ──────────────────────────────────────────────
    failure_rows = []
    for model, g in df.groupby("inspector_short"):
        row = {
            "model": model,
            "n_audits": len(g),
            "zero_score_pct": round(zero_pct.get(model, 0.0), 1),
            "hallucination_spike_pct": round(spike_pct.get(model, 0.0), 1),
            "mean_TS_equal": round(g["TS_equal"].mean(), 3),
            "mean_HF": round(g["hallucinationFrequency"].mean(), 3),
            "mean_TA": round(g["technicalAccuracy"].mean(), 3),
            "mean_ECA": round(g["effectChainAwareness"].mean(), 3),
            "mean_ASC": round(g["attackSurfaceCoverage"].mean(), 3),
            "ctx_len_r_with_TS": per_model_ctx_df[
                (per_model_ctx_df["model"] == model) &
                (per_model_ctx_df["metric"] == "TS_equal")
            ]["r"].values[0] if len(per_model_ctx_df[
                (per_model_ctx_df["model"] == model) &
                (per_model_ctx_df["metric"] == "TS_equal")
            ]) > 0 else np.nan,
        }
        failure_rows.append(row)

    failure_df = pd.DataFrame(failure_rows).sort_values("mean_TS_equal", ascending=False)
    print("\nFailure Taxonomy Summary:")
    print(failure_df.to_string(index=False))
    failure_df.to_csv(OUT_DIR / "failure_taxonomy.csv", index=False)

    # ── Per-callsite heatmap: inspector × callsite TS_equal ──────────────────
    heat = df.groupby(["inspector_short", "callsite_id"])["TS_equal"].mean().unstack()
    if not heat.empty:
        fig, ax = plt.subplots(figsize=(max(12, heat.shape[1] * 0.4), 5))
        sns.heatmap(heat, cmap="RdYlGn", vmin=0, vmax=1, ax=ax,
                    linewidths=0.2, cbar_kws={"label": "TS_equal"})
        ax.set_title("TS_equal — Inspector × Callsite")
        ax.set_xlabel("Callsite ID")
        ax.set_ylabel("Inspector")
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / "rqc_callsite_heatmap.png", dpi=150)
        plt.close()

    corr_ctx.to_csv(OUT_DIR / "context_length_correlations.csv", index=False)
    per_model_ctx_df.to_csv(OUT_DIR / "context_length_correlations_per_model.csv", index=False)

    print("\nPlots saved: rqc_context_length.png, rqc_callsite_heatmap.png")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    PLOTS_DIR.mkdir(exist_ok=True)
    OUT_DIR.mkdir(exist_ok=True)

    print("Loading data...")
    df_conclusions = load_conclusions()
    df_callsite = load_callsite_results()
    print(f"  conclusions: {len(df_conclusions)} rows ({df_conclusions['app'].nunique()} apps, "
          f"{df_conclusions['model'].nunique()} models)")
    print(f"  callsite audits: {len(df_callsite)} rows "
          f"({df_callsite['callsite_id'].nunique()} callsites, "
          f"{df_callsite['researcher'].nunique()} researchers)")

    rqa_out = rq_a(df_conclusions, df_callsite)
    rq_b(df_conclusions, rqa_out)
    rq_c(df_callsite)

    print("\n" + "=" * 60)
    print("Done. Outputs written to:")
    print(f"  {OUT_DIR}")
    print(f"  {PLOTS_DIR}")


if __name__ == "__main__":
    main()
