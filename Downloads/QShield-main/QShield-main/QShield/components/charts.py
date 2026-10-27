"""Chart generation components using Plotly for QShield visualizations."""

import pandas as pd
import plotly.graph_objects as go
from typing import Dict, Any


def create_risk_distribution_chart(risk_counts: Dict[str, int]) -> go.Figure:
    """Create a bar chart showing the distribution of assets across risk levels.

    Args:
        risk_counts: Dictionary mapping risk level to asset count.

    Returns:
        Plotly Figure.
    """
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    counts = [risk_counts.get(lvl, 0) for lvl in levels]
    colors = {
        "CRITICAL": "#DC2626",  # Red
        "HIGH": "#EA580C",      # Orange
        "MEDIUM": "#D97706",    # Amber
        "LOW": "#16A34A",       # Green
        "UNKNOWN": "#64748B",   # Slate Gray (Insufficient Information)
    }
    bar_colors = [colors[lvl] for lvl in levels]

    fig = go.Figure(
        data=[
            go.Bar(
                x=levels,
                y=counts,
                marker_color=bar_colors,
                text=counts,
                textposition="auto",
            )
        ]
    )

    fig.update_layout(
        title="Asset Distribution by Quantum Risk Level",
        xaxis_title="Risk Level",
        yaxis_title="Number of Assets",
        template="plotly_white",
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )

    return fig


def create_scenario_exposure_chart(exposed_count: int, safe_count: int) -> go.Figure:
    """Create a pie chart comparing exposed vs safe assets under a threat scenario.

    Args:
        exposed_count: Count of assets exposed under scenario conditions (negative margin).
        safe_count: Count of assets with zero or positive planning buffer or PQC resilience.

    Returns:
        Plotly Figure.
    """
    labels = ["Exposed (Negative Planning Margin)", "Buffer Maintained / Quantum-Safe"]
    values = [exposed_count, safe_count]
    colors = ["#DC2626", "#2563EB"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.45,
                marker=dict(colors=colors),
            )
        ]
    )

    fig.update_layout(
        title="Scenario Exposure Breakdown (Mosca Heuristic)",
        template="plotly_white",
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )

    return fig


def create_planning_margin_distribution_chart(margin_counts: Dict[str, int]) -> go.Figure:
    """Create a bar chart showing the distribution of assets across planning margin categories.

    Args:
        margin_counts: Dict with keys 'NEGATIVE_MARGIN', 'ZERO_BUFFER', 'POSITIVE_MARGIN'.

    Returns:
        Plotly Figure.
    """
    categories = ["Negative Margin (< 0)", "Zero Buffer (== 0)", "Positive Margin (> 0)"]
    counts = [
        margin_counts.get("NEGATIVE_MARGIN", 0),
        margin_counts.get("ZERO_BUFFER", 0),
        margin_counts.get("POSITIVE_MARGIN", 0),
    ]
    colors = ["#DC2626", "#D97706", "#16A34A"]

    fig = go.Figure(
        data=[
            go.Bar(
                x=categories,
                y=counts,
                marker_color=colors,
                text=counts,
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        title="Distribution of Planning Margins: Z - (X + Y)",
        xaxis_title="Planning Margin Status",
        yaxis_title="Number of Assets",
        template="plotly_white",
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )
    return fig


def create_asset_margins_comparison_chart(evaluated_assets: list) -> go.Figure:
    """Create a horizontal bar chart comparing individual asset planning margins.

    Args:
        evaluated_assets: List of evaluated asset summaries with planning_margin, name, crypto_algorithm.

    Returns:
        Plotly Figure.
    """
    if not evaluated_assets:
        fig = go.Figure()
        fig.update_layout(
            title="Asset-Level Planning Margins (No Assets Evaluated)",
            template="plotly_white",
            height=320,
        )
        return fig

    # Sort assets by planning margin (lowest/most urgent first)
    sorted_assets = sorted(evaluated_assets, key=lambda a: a.get("planning_margin", 0))

    labels = [
        f"{a.get('name', 'Asset')} ({a.get('crypto_algorithm', 'N/A')})"
        for a in sorted_assets
    ]
    margins = [a.get("planning_margin", 0) for a in sorted_assets]
    colors = [
        "#DC2626" if m < 0 else ("#D97706" if m == 0 else "#16A34A")
        for m in margins
    ]
    hover_texts = [
        f"<b>{a.get('name')}</b><br>"
        f"Algorithm: {a.get('crypto_algorithm')}<br>"
        f"Role: {a.get('crypto_role')}<br>"
        f"Confidentiality Shelf-Life (X): {a.get('confidentiality_duration_X')} yrs<br>"
        f"Migration Duration (Y): {a.get('migration_duration_Y')} yrs<br>"
        f"Threat Horizon (Z): {a.get('threat_horizon_Z')} yrs<br>"
        f"<b>Planning Margin: {m} yrs</b><br>"
        f"Status: {a.get('exposure_status', 'N/A')}"
        for a, m in zip(sorted_assets, margins)
    ]

    fig = go.Figure(
        data=[
            go.Bar(
                x=margins,
                y=labels,
                orientation="h",
                marker_color=colors,
                text=[f"{m:+d} yrs" if m != 0 else "0 yrs" for m in margins],
                textposition="auto",
                hoverinfo="text",
                hovertext=hover_texts,
            )
        ]
    )

    # Reference line at x=0
    fig.add_vline(
        x=0,
        line_width=1.5,
        line_dash="dash",
        line_color="#475569",
        annotation_text="Zero Buffer (Z = X+Y)",
        annotation_position="top right",
    )

    chart_height = max(340, len(sorted_assets) * 28 + 100)
    fig.update_layout(
        title="Asset-Level Planning Margin Comparison: Z - (X + Y)",
        xaxis_title="Planning Margin (Years Buffer)",
        yaxis_title="Cryptographic Asset",
        template="plotly_white",
        margin=dict(l=20, r=20, t=40, b=20),
        height=chart_height,
    )
    return fig


def create_scenario_comparison_chart(scenario_results: list) -> go.Figure:
    """Create a grouped bar chart comparing exposure and buffer metrics across multiple scenarios.

    Args:
        scenario_results: List of scenario simulation results from compare_scenarios.

    Returns:
        Plotly Figure.
    """
    if not scenario_results:
        fig = go.Figure()
        fig.update_layout(
            title="Scenario Timeline Comparison (No Scenarios Available)",
            template="plotly_white",
            height=320,
        )
        return fig

    scenario_labels = [
        f"{s['scenario_target_year']} (Z={s['threat_horizon_years_Z']}y)"
        for s in scenario_results
    ]
    confirmed_exposed = [
        s.get("confirmed_exposed_assets_count", s.get("exposed_assets_count", 0))
        for s in scenario_results
    ]
    requires_assessment = [s.get("requires_assessment_count", 0) for s in scenario_results]
    buffer_maintained = [
        s.get(
            "resilient_or_buffered_count",
            max(
                0,
                s.get("total_assets_evaluated", 0)
                - s.get("confirmed_exposed_assets_count", s.get("exposed_assets_count", 0))
                - s.get("requires_assessment_count", 0),
            ),
        )
        for s in scenario_results
    ]

    fig = go.Figure(
        data=[
            go.Bar(
                name="Confirmed Exposed (Negative Margin)",
                x=scenario_labels,
                y=confirmed_exposed,
                marker_color="#DC2626",
                text=confirmed_exposed,
                textposition="auto",
            ),
            go.Bar(
                name="Requires Assessment (Unclassified)",
                x=scenario_labels,
                y=requires_assessment,
                marker_color="#64748B",
                text=requires_assessment,
                textposition="auto",
            ),
            go.Bar(
                name="Resilient / Buffer Maintained",
                x=scenario_labels,
                y=buffer_maintained,
                marker_color="#2563EB",
                text=buffer_maintained,
                textposition="auto",
            ),
        ]
    )

    fig.update_layout(
        title="Multi-Scenario Threat Horizon Comparison",
        xaxis_title="Hypothetical Threat Horizon Year",
        yaxis_title="Number of Assets",
        barmode="group",
        template="plotly_white",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=20, r=20, t=60, b=20),
        height=360,
    )
    return fig


def create_scenario_exposure_breakdown_chart(
    confirmed_exposed: int,
    requires_assessment: int,
    buffer_maintained: int,
) -> go.Figure:
    """Create a donut chart distinguishing confirmed exposure from unknown mechanisms and safe assets."""
    if confirmed_exposed + requires_assessment + buffer_maintained == 0:
        fig = go.Figure()
        fig.update_layout(
            title="Scenario Exposure Categorization (No Assets)",
            template="plotly_white",
            margin=dict(l=20, r=20, t=40, b=20),
            height=320,
            annotations=[dict(text="No Assets in Scope", x=0.5, y=0.5, font_size=14, showarrow=False)],
        )
        return fig

    labels = [
        "Confirmed Exposure (Vuln & Neg Margin)",
        "Requires Assessment (Unclassified / Incompatible)",
        "Resilient / Buffer Maintained",
    ]
    values = [confirmed_exposed, requires_assessment, buffer_maintained]
    colors = ["#DC2626", "#64748B", "#16A34A"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.45,
                marker=dict(colors=colors),
            )
        ]
    )

    fig.update_layout(
        title="Scenario Exposure Categorization",
        template="plotly_white",
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )
    return fig
