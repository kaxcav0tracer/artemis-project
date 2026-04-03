"""Artemis SOAR Dashboard - Real-time threat intelligence and operations view"""

import asyncio
import os
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Import models
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from src.models import ThreatCache

# Configure Streamlit page
st.set_page_config(
    page_title="Artemis SOAR Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:artemis@artemis-db:5432/artemis")


async def load_all_data() -> dict:
    """Load all dashboard data in a single async context

    This function creates the engine and session INSIDE the async context
    to avoid asyncio loop conflicts when Streamlit re-runs.
    """
    # Create engine and session INSIDE the async context (not cached)
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    try:
        async with async_session_maker() as session:
            # === Fetch Statistics ===
            total_ips = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).select_from(ThreatCache)
            )
            blocked_ips = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).where(
                    ThreatCache.action_taken == "BLOCK"
                )
            )
            avg_reputation = await session.scalar(
                select(func.avg(ThreatCache.reputation_score)).select_from(ThreatCache)
            )
            fortigate_synced = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).where(
                    ThreatCache.fortigate_synced == True  # type: ignore
                )
            )

            # === Fetch Action Distribution ===
            action_stmt = select(
                ThreatCache.action_taken,
                func.count(ThreatCache.ioc_value).label("count"),
            ).group_by(ThreatCache.action_taken)
            action_result = await session.execute(action_stmt)
            action_data = action_result.all()
            action_df = pd.DataFrame(action_data, columns=["Action", "Count"])

            # === Fetch Threat Level Distribution ===
            total_high = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).where(
                    ThreatCache.reputation_score >= 10
                )
            )
            total_medium = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).where(
                    (ThreatCache.reputation_score >= 3)
                    & (ThreatCache.reputation_score < 10)
                )
            )
            total_low = await session.scalar(
                select(func.count(ThreatCache.ioc_value)).where(
                    ThreatCache.reputation_score < 3
                )
            )
            threat_df = pd.DataFrame(
                {
                    "Threat Level": ["High Risk", "Medium Risk", "Low Risk"],
                    "Count": [total_high or 0, total_medium or 0, total_low or 0],
                }
            )

            # === Fetch Recent Alerts ===
            alerts_stmt = (
                select(ThreatCache)
                .order_by(ThreatCache.updated_at.desc())
                .limit(10)
            )
            alerts_result = await session.execute(alerts_stmt)
            alerts_records = alerts_result.scalars().all()

            alerts_data = []
            for record in alerts_records:
                alerts_data.append(
                    {
                        "IP": record.ioc_value,
                        "Reputation": record.reputation_score,
                        "Action": record.action_taken,
                        "FortiGate": "Synced"
                        if record.fortigate_synced
                        else "Not synced",
                        "Last Seen": record.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                        "Expires": record.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            alerts_df = pd.DataFrame(alerts_data)

        # Return all data aggregated
        return {
            "stats": {
                "total_ips": total_ips or 0,
                "blocked_ips": blocked_ips or 0,
                "avg_reputation": round(avg_reputation or 0, 2),
                "fortigate_synced": fortigate_synced or 0,
            },
            "action_df": action_df,
            "threat_df": threat_df,
            "alerts_df": alerts_df,
        }

    finally:
        # Cleanup: dispose of the engine to close all connections
        await engine.dispose()


def main():
    """Main dashboard application"""
    st.title("Artemis SOAR Dashboard")
    st.markdown(
        "Real-time threat intelligence and security operations center insights"
    )

    try:
        # Load all data in a SINGLE async context (not separate calls)
        dashboard_data = asyncio.run(load_all_data())

        stats = dashboard_data["stats"]
        action_df = dashboard_data["action_df"]
        threat_df = dashboard_data["threat_df"]
        alerts_df = dashboard_data["alerts_df"]

        # === Display Key Metrics ===
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(label="Total IPs Analyzed", value=stats["total_ips"])
        with col2:
            st.metric(
                label="IPs Blocked",
                value=stats["blocked_ips"],
                delta=f"{(stats['blocked_ips'] / max(stats['total_ips'], 1) * 100):.1f}%",
            )
        with col3:
            st.metric(label="Avg Reputation Score", value=stats["avg_reputation"])
        with col4:
            st.metric(label="FortiGate Synced", value=stats["fortigate_synced"])

        st.divider()

        # === Display Charts ===
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Action Distribution")
            if not action_df.empty:
                fig_pie = px.pie(
                    action_df,
                    names="Action",
                    values="Count",
                    hole=0.4,
                    color_discrete_sequence=["#FF4B4B", "#2ECC71", "#FFA500"],
                )
                fig_pie.update_layout(height=300)
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No data available yet")

        with col2:
            st.subheader("Threat Level Distribution")
            if not threat_df.empty:
                fig_bar = px.bar(
                    threat_df,
                    x="Threat Level",
                    y="Count",
                    color="Threat Level",
                    color_discrete_map={
                        "High Risk": "#FF4B4B",
                        "Medium Risk": "#FFA500",
                        "Low Risk": "#2ECC71",
                    },
                )
                fig_bar.update_layout(height=300, showlegend=False)
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No data available yet")

        st.divider()

        # === Display Recent Alerts ===
        st.subheader("Recent Alerts (Last 10)")
        if not alerts_df.empty:
            st.dataframe(alerts_df, use_container_width=True)
            csv = alerts_df.to_csv(index=False)
            st.download_button(
                label="Download as CSV",
                data=csv,
                file_name="artemis_alerts.csv",
                mime="text/csv",
            )
        else:
            st.info("No alerts processed yet")

        st.divider()
        st.markdown(
            f"<small>Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</small>",
            unsafe_allow_html=True,
        )

    except Exception as e:
        st.error(f"Database connection error: {str(e)}")
        st.info("Make sure PostgreSQL is running and DATABASE_URL is configured")


if __name__ == "__main__":
    main()
