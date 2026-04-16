"""
TPCRA Dashboard — Third-Party Cybersecurity Risk Assessment
Reads a completed TPCRA questionnaire (.xlsx) and summarizes gaps & risk.
Usage: streamlit run tpcra_dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Third Party Cyber Risk Assessment Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styles ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e2530;
        border-radius: 12px;
        padding: 20px 24px;
        border-left: 4px solid;
        margin-bottom: 8px;
    }
    .metric-card.critical { border-color: #e74c3c; }
    .metric-card.high     { border-color: #e67e22; }
    .metric-card.medium   { border-color: #f1c40f; }
    .metric-card.low      { border-color: #2ecc71; }
    .metric-card.info     { border-color: #3498db; }
    .metric-label { font-size: 12px; color: #8899aa; text-transform: uppercase; letter-spacing: 1px; }
    .metric-value { font-size: 34px; font-weight: 700; color: #ffffff; line-height: 1.1; }
    .metric-sub   { font-size: 12px; color: #aabbcc; margin-top: 2px; }
    .risk-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    .badge-Critical { background:#fde8e8; color:#c0392b; }
    .badge-High     { background:#fef3e2; color:#d35400; }
    .badge-Medium   { background:#fefde7; color:#b7950b; }
    .badge-Low      { background:#e8f8f0; color:#1e8449; }
    .badge-default  { background:#eaf2fb; color:#2471a3; }
    .gap-row { padding: 8px 0; border-bottom: 1px solid #2a3548; }
    div[data-testid="stMetric"] > div { background: #1e2530; border-radius: 10px; padding: 12px; }
</style>
""", unsafe_allow_html=True)


# ── Constants ─────────────────────────────────────────────────────────────────
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
RISK_COLORS = {"Critical": "#e74c3c", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#2ecc71"}
RISK_BG     = {"Critical": "#fde8e8", "High": "#fef3e2", "Medium": "#fefde7", "Low": "#e8f8f0"}
# Answers that indicate NON-COMPLIANCE / gap
GAP_ANSWERS  = {"no", "partial", "n/a"}
PASS_ANSWERS = {"yes"}


# ── Helpers ───────────────────────────────────────────────────────────────────
def badge(tier: str) -> str:
    icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    icon = icons.get(tier, "⚪")
    return f"{icon} {tier}"


def risk_score(tier: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(tier, 0)


def overall_risk_label(score: float) -> tuple[str, str]:
    if score >= 3.5:   return "Critical", "#e74c3c"
    if score >= 2.5:   return "High",     "#e67e22"
    if score >= 1.5:   return "Medium",   "#f1c40f"
    return "Low", "#2ecc71"


# ── Parsing ───────────────────────────────────────────────────────────────────
def parse_part1(xl) -> dict:
    """Return Part 1 metadata as a dict."""
    df = xl.parse("Part 1", header=None)
    meta = {}
    for _, row in df.iterrows():
        qid  = str(row[0]).strip()
        q    = str(row[1]).strip() if pd.notna(row[1]) else ""
        resp = str(row[2]).strip() if pd.notna(row[2]) else ""
        if qid in ("1.1", "1.2", "1.3", "2.1", "2.8") and resp not in ("", "nan"):
            meta[q] = resp
        elif qid == "1.1":
            meta["Company Name"] = resp
    # Try to get company name directly
    for _, row in df.iterrows():
        q = str(row[1]).strip() if pd.notna(row[1]) else ""
        r = str(row[2]).strip() if pd.notna(row[2]) else ""
        if "Company Name" in q and r not in ("", "nan"):
            meta["Company Name"] = r
            break
    return meta


DOMAIN_MAP = {
    "A": "Organizational Management",
    "B": "Human Resource Management",
    "C": "Infrastructure Security",
    "D": "Data Protection",
    "E": "Access Management",
    "F": "Application Security",
    "G": "System Security",
    "H": "Email Security",
    "I": "Mobile Devices",
    "J": "Incident Response",
    "K": "Cloud Services",
    "L": "Business Continuity",
    "M": "Supply Chain & Physical Security",
    "N": "AI & Emerging Technology Risk",
}

def parse_part2(xl) -> pd.DataFrame:
    """
    Return a DataFrame of all assessable Part 2 items with columns:
    id, section, statement, response, other_info, risk_tier, comment_required
    """
    df = xl.parse("Part 2", header=None)
    rows = []
    current_section = "General"

    for _, row in df.iterrows():
        qid      = str(row[0]).strip() if pd.notna(row[0]) else ""
        stmt     = str(row[1]).strip() if pd.notna(row[1]) else ""
        response = str(row[2]).strip() if pd.notna(row[2]) else ""
        other    = str(row[3]).strip() if pd.notna(row[3]) else ""
        tier     = str(row[4]).strip() if pd.notna(row[4]) else "—"
        comment  = str(row[5]).strip() if pd.notna(row[5]) else "—"

        # Detect section headers (no numeric id, stmt is blank)
        if stmt in ("", "nan") and qid and not qid[0].isdigit() and not qid[0].isupper():
            # Map domain letter to full name if available
            domain_key = qid.split("—")[0].strip() if "—" in qid else qid.strip()
            current_section = DOMAIN_MAP.get(domain_key, qid)
            continue
        if stmt in ("", "nan") and qid and qid not in ("nan", ""):
            domain_key = qid.split("—")[0].strip() if "—" in qid else qid.strip()
            current_section = DOMAIN_MAP.get(domain_key, qid)
            continue
        if qid in ("nan", "", "#") or stmt in ("nan", "", "Statement / Question"):
            if stmt in ("nan", "") and qid not in ("nan", ""):
                domain_key = qid.split("—")[0].strip() if "—" in qid else qid.strip()
                current_section = DOMAIN_MAP.get(domain_key, qid)
            continue

        # Normalise tier
        tier_norm = tier if tier in RISK_ORDER else "—"

        if response in ("nan", ""):
            response = "—"

        rows.append({
            "id":               qid,
            "section":          current_section,
            "statement":        stmt,
            "response":         response,
            "other_info":       other if other != "nan" else "",
            "risk_tier":        tier_norm,
            "comment_required": comment,
        })

    return pd.DataFrame(rows)


def parse_evidence(xl) -> pd.DataFrame:
    df = xl.parse("Evidence", header=None)
    rows = []
    for _, row in df.iterrows():
        eid    = str(row[0]).strip()
        title  = str(row[1]).strip() if pd.notna(row[1]) else ""
        status = str(row[3]).strip() if pd.notna(row[3]) else "—"
        req_for= str(row[5]).strip() if pd.notna(row[5]) else ""
        if eid in ("nan", "#", ""):
            continue
        if title in ("nan", "Evidence Required", ""):
            continue
        if status in ("nan", ""):
            status = "—"
        rows.append({"id": eid, "evidence": title, "status": status, "required_for": req_for})
    return pd.DataFrame(rows)


def compute_gaps(df: pd.DataFrame) -> pd.DataFrame:
    """Add an `is_gap` column: True when response is No/Partial/N-A on a tiered item."""
    df = df.copy()
    df["is_gap"] = (
        df["risk_tier"].isin(RISK_ORDER) &
        df["response"].str.lower().isin(GAP_ANSWERS)
    )
    return df


def section_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Per-section gap counts and compliance rate."""
    tiered = df[df["risk_tier"].isin(RISK_ORDER)].copy()
    grp = tiered.groupby("section").agg(
        total=("id", "count"),
        gaps=("is_gap", "sum"),
        answered=("response", lambda x: (x != "—").sum()),
    ).reset_index()
    grp["compliance_pct"] = ((grp["answered"] - grp["gaps"]) / grp["total"] * 100).round(1)
    grp["unanswered"] = grp["total"] - grp["answered"]
    # Compute risk_score via merge to avoid index misalignment
    score_map = (
        tiered[tiered["is_gap"]]
        .copy()
        .assign(score=lambda d: d["risk_tier"].map(risk_score).fillna(0).astype(float))
        .groupby("section")["score"]
        .sum()
        .reset_index()
        .rename(columns={"score": "risk_score"})
    )
    grp = grp.merge(score_map, on="section", how="left")
    grp["risk_score"] = grp["risk_score"].fillna(0).astype(float)
    return grp.sort_values("risk_score", ascending=False)


# ── Main App ──────────────────────────────────────────────────────────────────
st.title("🛡️ Third Party Cyber Risk Assessment Dashboard")
st.caption("Third-Party Cybersecurity Risk Assessment — Gap & Risk Analyzer")

# ── Sidebar upload ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("📂 Upload Questionnaire")
    uploaded = st.file_uploader(
        "Drop your completed TPCRA .xlsx here",
        type=["xlsx"],
        help="Supports TPCRA Questionnaire v3.0 and above",
    )


# ── Load file ─────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def load_data(file_bytes: bytes):
    xl    = pd.ExcelFile(BytesIO(file_bytes))
    meta  = parse_part1(xl)
    df2   = parse_part2(xl)
    evid  = parse_evidence(xl)
    df2   = compute_gaps(df2)
    return meta, df2, evid


if uploaded is None:
    st.info("👆 Upload a completed TPCRA questionnaire to begin analysis.", icon="📋")
    st.markdown("""
    **What this dashboard shows:**
    - 🎯 Overall risk rating for the third-party provider
    - 📊 Gap summary by security domain
    - 🔍 Detailed list of compliance gaps by risk tier
    - 📁 Evidence checklist status
    - 📈 Visual risk distribution charts
    """)
    st.stop()

with st.spinner("Analysing questionnaire…"):
    meta, df2, evid = load_data(uploaded.read())

# Base dataframes (no filter applied globally)
df_view   = df2.copy()
gaps_df   = df2[df2["is_gap"]]
tiered_df = df2[df2["risk_tier"].isin(RISK_ORDER)]

# Unanswered
unanswered = df2[df2["response"] == "—"].copy()

# ── Header metadata ────────────────────────────────────────────────────────────
company_name = meta.get("Company Name *", meta.get("Company Name", "—"))
st.subheader(f"Provider: **{company_name}**")

# ── KPI Cards ──────────────────────────────────────────────────────────────────
total_items  = len(tiered_df)
total_gaps   = int(gaps_df.shape[0])
answered     = int((tiered_df["response"] != "—").sum())
compliance   = round((answered - total_gaps) / total_items * 100, 1) if total_items else 0
avg_score    = gaps_df["risk_tier"].map(risk_score).mean() if not gaps_df.empty else 0
ov_label, ov_color = overall_risk_label(avg_score) if total_gaps > 0 else ("Low", "#2ecc71")

crit_gaps = int((gaps_df["risk_tier"] == "Critical").sum())
high_gaps  = int((gaps_df["risk_tier"] == "High").sum())
med_gaps   = int((gaps_df["risk_tier"] == "Medium").sum())
unans      = int((tiered_df["response"] == "—").sum())

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""<div class="metric-card {'critical' if ov_label in ('Critical','High') else 'low'}">
    <div class="metric-label">Overall Risk</div>
    <div class="metric-value" style="color:{ov_color}">{ov_label}</div>
    <div class="metric-sub">{total_gaps} gap(s) identified</div></div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="metric-card info">
    <div class="metric-label">Compliance Rate</div>
    <div class="metric-value">{compliance}%</div>
    <div class="metric-sub">{answered}/{total_items} items answered</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class="metric-card critical">
    <div class="metric-label">Critical Gaps</div>
    <div class="metric-value">{crit_gaps}</div>
    <div class="metric-sub">Require immediate action</div></div>""", unsafe_allow_html=True)
with c4:
    st.markdown(f"""<div class="metric-card high">
    <div class="metric-label">High Gaps</div>
    <div class="metric-value">{high_gaps}</div>
    <div class="metric-sub">Require priority action</div></div>""", unsafe_allow_html=True)
with c5:
    st.markdown(f"""<div class="metric-card medium">
    <div class="metric-label">Unanswered Items</div>
    <div class="metric-value">{unans}</div>
    <div class="metric-sub">Of {total_items} tiered questions</div></div>""", unsafe_allow_html=True)

st.divider()

# ── Charts row ─────────────────────────────────────────────────────────────────
col_chart1, col_chart2 = st.columns([1, 1])

with col_chart1:
    st.subheader("📊 Gaps by Risk Tier")
    tier_counts = gaps_df["risk_tier"].value_counts().reset_index()
    tier_counts.columns = ["Tier", "Count"]
    tier_counts["order"] = tier_counts["Tier"].map(RISK_ORDER)
    tier_counts = tier_counts.sort_values("order")
    colors = [RISK_COLORS.get(t, "#95a5a6") for t in tier_counts["Tier"]]
    fig = px.bar(tier_counts, x="Tier", y="Count", color="Tier",
                 color_discrete_map=RISK_COLORS, text="Count",
                 template="plotly_dark")
    fig.update_traces(textposition="outside")
    fig.update_layout(showlegend=False, height=300, margin=dict(t=20, b=20),
                      plot_bgcolor="#0e1117", paper_bgcolor="#0e1117")
    st.plotly_chart(fig, use_container_width=True)

with col_chart2:
    st.subheader("🕸️ Compliance by Domain")
    sec_sum = section_summary(df2)
    # Map section names to short domain labels for display
    inv_domain = {v: k for k, v in DOMAIN_MAP.items()}
    sec_sum["domain_label"] = sec_sum["section"].apply(
        lambda s: f"{inv_domain[s]} — {s}" if s in inv_domain else s
    )
    sec_sum_sorted = sec_sum.sort_values("compliance_pct", ascending=True)
    fig2 = px.bar(sec_sum_sorted, x="compliance_pct", y="domain_label",
                  orientation="h", color="compliance_pct",
                  color_continuous_scale=["#e74c3c", "#f1c40f", "#2ecc71"],
                  range_color=[0, 100], text="compliance_pct",
                  template="plotly_dark")
    fig2.update_traces(texttemplate="%{text}%", textposition="outside")
    fig2.update_layout(coloraxis_showscale=False,
                       height=max(300, len(sec_sum_sorted) * 36),
                       margin=dict(t=20, b=20, l=10),
                       plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
                       yaxis_title=None, xaxis_title="Compliance %")
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["🚨 Gaps & Findings", "📋 Full Response Review",
                                   "📁 Evidence Checklist", "ℹ️ Engagement Info"])

# ── Tab 1: Gaps ───────────────────────────────────────────────────────────────
with tab1:
    st.markdown("### Identified Gaps & Compliance Issues")

    # ── Filters (moved from sidebar) ──
    f1, f2 = st.columns([1, 1])
    with f1:
        min_tier = st.selectbox(
            "Minimum risk tier",
            ["All", "Critical", "High", "Medium", "Low"],
            key="gap_tier_filter"
        )
    with f2:
        show_unanswered = st.checkbox("Include unanswered items as gaps", value=True, key="gap_unans")

    tier_filter_map = {
        "All":      list(RISK_ORDER.keys()),
        "Critical": ["Critical"],
        "High":     ["Critical", "High"],
        "Medium":   ["Critical", "High", "Medium"],
        "Low":      list(RISK_ORDER.keys()),
    }
    visible_tiers = tier_filter_map[min_tier]
    filtered_gaps = df2[
        df2["is_gap"] & df2["risk_tier"].isin(visible_tiers)
    ].copy()
    if show_unanswered:
        unans_rows = df2[
            (df2["response"] == "—") & df2["risk_tier"].isin(visible_tiers)
        ].copy()
        unans_rows["is_gap"] = True
        filtered_gaps = pd.concat([filtered_gaps, unans_rows]).drop_duplicates(subset="id")

    st.divider()

    if filtered_gaps.empty:
        st.success("✅ No gaps identified based on current filter settings.")
    else:
        # Group by domain in A–N order
        ordered_domains = list(DOMAIN_MAP.values())
        gap_sections = filtered_gaps["section"].unique().tolist()
        # Sort sections by domain order, unknown sections appended at end
        sorted_sections = sorted(
            gap_sections,
            key=lambda s: ordered_domains.index(s) if s in ordered_domains else len(ordered_domains)
        )

        for section in sorted_sections:
            section_gaps = filtered_gaps[filtered_gaps["section"] == section]
            tier_label = section_gaps["risk_tier"].map(RISK_ORDER).min()
            worst_tier = {v: k for k, v in RISK_ORDER.items()}.get(tier_label, "Low")
            # Find domain letter for label
            domain_letter = next((k for k, v in DOMAIN_MAP.items() if v == section), "")
            domain_label = f"{domain_letter} — {section}" if domain_letter else section

            with st.expander(
                f"{domain_label} ({len(section_gaps)} gap(s))",
                expanded=(worst_tier in ("Critical", "High")),
            ):
                for _, row in section_gaps.sort_values(
                    "risk_tier", key=lambda s: s.map(RISK_ORDER)
                ).iterrows():
                    cols = st.columns([1, 0.7, 4, 1.5])
                    cols[0].markdown(badge(row["risk_tier"]))
                    cols[1].markdown(f"`{row['id']}`")
                    cols[2].markdown(row["statement"])
                    resp_color = {"No": "🔴", "Partial": "🟡", "N/A": "⚪", "—": "⬜"}.get(
                        row["response"], "🔵"
                    )
                    cols[3].markdown(f"{resp_color} **{row['response']}**")

# ── Tab 2: Full responses ──────────────────────────────────────────────────────
with tab2:
    st.markdown("### Full Questionnaire Response Review")

    # Filters
    col_f1, col_f2 = st.columns([2, 1])
    with col_f1:
        search = st.text_input("🔍 Search statements", placeholder="e.g. encryption, MFA, patch…")
    with col_f2:
        resp_filter = st.multiselect("Response", ["Yes", "No", "Partial", "N/A", "—"],
                                      default=["Yes", "No", "Partial", "N/A", "—"])

    display_df = df_view.copy()

    # Add domain label column (e.g. "A — Organizational Management")
    inv_domain = {v: k for k, v in DOMAIN_MAP.items()}
    display_df = display_df.copy()
    display_df["domain"] = display_df["section"].apply(
        lambda s: f"{inv_domain[s]} — {s}" if s in inv_domain else s
    )

    if search:
        display_df = display_df[display_df["statement"].str.contains(search, case=False, na=False)]
    if resp_filter:
        display_df = display_df[display_df["response"].isin(resp_filter)]

    # Colour-coded table — apply(axis=0) works on all pandas versions
    RESP_COLORS = {"Yes": "#e8f8f0", "No": "#fde8e8", "Partial": "#fefde7", "N/A": "#f0f0f0"}

    def style_response_col(col):
        return [f"background-color: {RESP_COLORS.get(v, 'transparent')}" for v in col]

    def style_tier_col(col):
        return [f"background-color: {RISK_BG.get(v, 'transparent')}" for v in col]

    table_df = (
        display_df[["id", "domain", "statement", "response", "risk_tier", "other_info"]]
        .rename(columns={"id": "ID", "domain": "Domain", "statement": "Statement",
                         "response": "Response", "risk_tier": "Tier", "other_info": "Remarks"})
    )
    styled = (
        table_df.style
        .apply(style_response_col, subset=["Response"], axis=0)
        .apply(style_tier_col, subset=["Tier"], axis=0)
    )
    st.dataframe(styled, use_container_width=True, height=500,
                 column_config={"Statement": st.column_config.TextColumn(width="large"),
                                "Domain": st.column_config.TextColumn(width="medium")})

# ── Tab 3: Evidence ────────────────────────────────────────────────────────────
with tab3:
    st.markdown("### Evidence Checklist")
    if evid.empty:
        st.info("No evidence checklist found in the uploaded file.")
    else:
        status_map = {"Submitted": "✅", "Pending": "⏳", "N/A": "⬜", "—": "❓"}
        for _, row in evid.iterrows():
            ico = status_map.get(row["status"], "❓")
            col_a, col_b, col_c = st.columns([3, 1, 2])
            col_a.markdown(f"**{row['id']}.** {row['evidence']}")
            col_b.markdown(f"{ico} `{row['status']}`")
            col_c.caption(row["required_for"])
            st.divider()

# ── Tab 4: Engagement info ─────────────────────────────────────────────────────
with tab4:
    st.markdown("### Engagement Information")
    xl_obj = pd.ExcelFile(BytesIO(uploaded.getvalue()))
    p1 = xl_obj.parse("Part 1", header=None)

    EXCLUDED_IDS = {"1.1", "1.2", "1.3", "1.4"}
    SECTION_ICONS = {
        "SECTION 2": "📋", "SECTION 3": "🏢",
        "SECTION 4": "💻", "SECTION 5": "🖧", "SECTION 6": "☁️",
        "SECTION 7": "🔒", "SECTION 8": "🔄",
    }
    SHOW_SECTIONS = set(SECTION_ICONS.keys())

    current_section_key = None
    current_section_label = None
    items_in_section = []
    sections_data = []

    for _, row in p1.iterrows():
        qid  = str(row[0]).strip() if pd.notna(row[0]) else ""
        q    = str(row[1]).strip() if pd.notna(row[1]) else ""
        resp = str(row[2]).strip() if pd.notna(row[2]) else ""

        # Skip header/title rows
        if qid in ("", "nan", "#") or qid.startswith("TPCRA"):
            continue

        # Detect section header rows (q is blank, qid contains "SECTION")
        if "SECTION" in qid and q in ("", "nan"):
            # Save previous section if it's one we want to show
            if current_section_key in SHOW_SECTIONS and items_in_section:
                sections_data.append((current_section_label, items_in_section))
            current_section_key = " ".join(qid.split()[:2])  # e.g. "SECTION 2"
            current_section_label = qid
            items_in_section = []
            continue

        # Skip column header row
        if q in ("", "nan", "Question"):
            continue

        # Skip excluded question IDs
        if qid in EXCLUDED_IDS:
            continue

        # Only collect items for sections we want to display
        if current_section_key not in SHOW_SECTIONS:
            continue

        items_in_section.append({
            "#": qid,
            "Question": q,
            "Response": resp if resp not in ("", "nan") else "—",
        })

    # Flush last section
    if current_section_key in SHOW_SECTIONS and items_in_section:
        sections_data.append((current_section_label, items_in_section))

    if not sections_data:
        st.info("No engagement information found in the uploaded file.")
    else:
        for section_label, items in sections_data:
            section_key = " ".join(section_label.split()[:2])
            icon = SECTION_ICONS.get(section_key, "📌")
            with st.expander(f"{icon} **{section_label}**", expanded=True):
                for item in items:
                    col_q, col_r = st.columns([2, 2])
                    with col_q:
                        st.markdown(
                            f"<span style='color:#8899aa; font-size:11px'>{item['#']}</span><br>"
                            f"<span style='font-size:14px'>{item['Question']}</span>",
                            unsafe_allow_html=True
                        )
                    with col_r:
                        resp_val = item["Response"]
                        if resp_val == "—":
                            st.markdown(
                                "<span style='color:#8899aa; font-style:italic'>Not provided</span>",
                                unsafe_allow_html=True
                            )
                        else:
                            st.markdown(
                                f"<span style='font-size:14px'>{resp_val}</span>",
                                unsafe_allow_html=True
                            )
                    st.divider()

# ── Sidebar summary ────────────────────────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("### 📈 Risk Summary")
    st.markdown(f"""
| Tier     | Gaps |
|----------|------|
| 🔴 Critical | {crit_gaps} |
| 🟠 High     | {high_gaps} |
| 🟡 Medium   | {med_gaps} |
| 🟢 Low      | {int((gaps_df['risk_tier'] == 'Low').sum())} |
| ⬜ Unanswered | {unans} |
""")
    st.divider()
    st.markdown("### 🏢 Provider")
    st.info(company_name)
    if meta:
        for k, v in list(meta.items())[:4]:
            if v not in ("", "—", "nan"):
                st.caption(f"**{k[:30]}**: {v[:50]}")
