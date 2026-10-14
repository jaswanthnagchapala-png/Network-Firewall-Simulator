
import ipaddress
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

from firewall import (
    DEFAULT_RULES,
    evaluate_packet,
    validate_ip_or_network,
)

from database import (
    initialize_database,
    get_rules,
    add_rule,
    delete_rule,
    reorder_rules,
    save_packet_log,
    get_packet_logs,
    clear_packet_logs,
    record_security_alert,
    get_security_alerts,
    update_alert_status,
    clear_security_alerts,
)


# =========================================================
# CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Network Firewall Simulator",
    page_icon="🛡️",
    layout="wide",
)

initialize_database(DEFAULT_RULES)

ALERT_THRESHOLD = 5
ALERT_WINDOW_MINUTES = 5


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Network Firewall Simulator")

st.caption(
    "Simulate network traffic, manage firewall rules, "
    "analyse traffic, and identify suspicious patterns."
)

st.info(
    "Simulation only: this application does not capture "
    "or block real network traffic and does not change "
    "your operating-system firewall."
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def logs_to_dataframe(logs):
    columns = [
        "Time",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Port",
        "Decision",
        "Reason",
    ]

    rows = []

    for item in logs:
        rows.append({
            "Time": item.get("timestamp", ""),
            "Source IP": item.get("source_ip", ""),
            "Destination IP": item.get(
                "destination_ip", ""
            ),
            "Protocol": str(
                item.get("protocol", "UNKNOWN")
            ).upper(),
            "Port": item.get("port", 0),
            "Decision": str(
                item.get("decision", "UNKNOWN")
            ).upper(),
            "Reason": item.get("reason", ""),
        })

    return pd.DataFrame(rows, columns=columns)


def get_rule_port(rule):
    return (
        "ANY"
        if rule.get("port") is None
        else rule.get("port")
    )


def check_suspicious_source(source_ip):
    """Detect repeated blocked packets from one source."""

    logs = get_packet_logs()

    cutoff = (
        datetime.now()
        - timedelta(minutes=ALERT_WINDOW_MINUTES)
    )

    blocked_count = 0

    for log in logs:
        if log.get("source_ip") != source_ip:
            continue

        if str(
            log.get("decision", "")
        ).upper() != "BLOCK":
            continue

        try:
            timestamp = datetime.strptime(
                log.get("timestamp", ""),
                "%Y-%m-%d %H:%M:%S",
            )
        except (ValueError, TypeError):
            continue

        if timestamp >= cutoff:
            blocked_count += 1

    if blocked_count >= ALERT_THRESHOLD:
        severity = (
            "HIGH"
            if blocked_count >= ALERT_THRESHOLD * 2
            else "MEDIUM"
        )

        record_security_alert(
            source_ip=source_ip,
            alert_type="REPEATED_BLOCKED_TRAFFIC",
            severity=severity,
            details=(
                f"{blocked_count} blocked simulated packets "
                f"from {source_ip} within "
                f"{ALERT_WINDOW_MINUTES} minutes."
            ),
            occurrence_count=blocked_count,
        )


# =========================================================
# NAVIGATION
# =========================================================

packet_tab, rules_tab, dashboard_tab, logs_tab, alerts_tab = (
    st.tabs([
        "📦 Packet Simulator",
        "🛡️ Firewall Rules",
        "📊 Analytics Dashboard",
        "📋 Packet Logs",
        "🚨 Security Alerts",
    ])
)


# =========================================================
# PACKET SIMULATOR
# =========================================================

with packet_tab:
    st.subheader("Simulate Network Traffic")

    st.write(
        "Enter packet details to evaluate the simulated "
        "traffic against your firewall rules."
    )

    with st.form("packet_form"):
        col1, col2 = st.columns(2)

        with col1:
            source_input = st.text_input(
                "Source IP Address",
                value="192.168.1.10",
            )

        with col2:
            destination_input = st.text_input(
                "Destination IP Address",
                value="192.168.1.20",
            )

        col3, col4 = st.columns(2)

        with col3:
            protocol = st.selectbox(
                "Protocol",
                ["TCP", "UDP", "ICMP"],
            )

        with col4:
            port = st.number_input(
                "Destination Port",
                min_value=0,
                max_value=65535,
                value=80,
                step=1,
                disabled=(protocol == "ICMP"),
                help=(
                    "ICMP has no TCP/UDP port. "
                    "The simulator stores port 0 for ICMP."
                ),
            )

        submitted = st.form_submit_button(
            "🔍 Simulate Packet",
            use_container_width=True,
        )

    if submitted:
        try:
            source = str(
                ipaddress.ip_address(
                    source_input.strip()
                )
            )

            destination = str(
                ipaddress.ip_address(
                    destination_input.strip()
                )
            )

        except ValueError:
            st.error(
                "Enter valid source and destination "
                "IPv4 or IPv6 addresses."
            )

        else:
            actual_port = (
                0 if protocol == "ICMP" else int(port)
            )

            result = evaluate_packet(
                source,
                destination,
                protocol,
                actual_port,
                get_rules(),
            )

            decision = result["action"]
            reason = result["reason"]

            save_packet_log({
                "source_ip": source,
                "destination_ip": destination,
                "protocol": protocol,
                "port": actual_port,
                "decision": decision,
                "reason": reason,
            })

            check_suspicious_source(source)

            st.divider()
            st.subheader("Firewall Decision")

            if decision == "ALLOW":
                st.success(
                    "🟢 ALLOW — The packet matches an allow rule."
                )
            else:
                st.error(
                    "🔴 BLOCK — The simulator blocked this packet."
                )

            st.write(f"**Reason:** {reason}")

            metric1, metric2, metric3 = st.columns(3)

            metric1.metric("Protocol", protocol)

            metric2.metric(
                "Destination Port",
                "N/A" if protocol == "ICMP" else actual_port,
            )

            metric3.metric("Decision", decision)

            with st.expander(
                "View complete packet details"
            ):
                st.write(f"**Source IP:** {source}")
                st.write(
                    f"**Destination IP:** {destination}"
                )
                st.write(f"**Protocol:** {protocol}")
                st.write(
                    "**Destination Port:** "
                    + (
                        "N/A"
                        if protocol == "ICMP"
                        else str(actual_port)
                    )
                )
                st.write(
                    "**Matched Rule ID:** "
                    + str(result.get("rule_number") or "None")
                )
                st.write(f"**Explanation:** {reason}")

            st.caption(
                "This is a simulated firewall decision, "
                "not a test of actual network connectivity."
            )


# =========================================================
# FIREWALL RULE MANAGEMENT
# =========================================================

with rules_tab:
    st.subheader("Firewall Rules")

    st.caption(
        "Rules are checked from highest to lowest priority. "
        "The first matching rule determines the decision. "
        "Unmatched packets are blocked by default."
    )

    rules = get_rules()

    if rules:
        rule_rows = []

        for priority, rule in enumerate(
            rules,
            start=1
        ):
            rule_rows.append({
                "Priority": priority,
                "Rule ID": rule["id"],
                "Source IP / CIDR": rule["source_ip"],
                "Destination IP / CIDR": (
                    rule["destination_ip"]
                ),
                "Protocol": rule["protocol"],
                "Port": get_rule_port(rule),
                "Action": rule["action"],
            })

        st.dataframe(
            pd.DataFrame(rule_rows),
            hide_index=True,
            use_container_width=True,
        )

    else:
        st.warning(
            "No rules configured. Unmatched traffic "
            "will be blocked by default."
        )

    st.divider()
    st.subheader("Add a Firewall Rule")

    st.caption(
        "IP fields accept an exact IP address, a CIDR "
        "network such as 192.168.1.0/24, or ANY."
    )

    with st.form("add_rule_form"):
        new_source = st.text_input(
            "Source IP, CIDR, or ANY",
            value="ANY",
        )

        new_destination = st.text_input(
            "Destination IP, CIDR, or ANY",
            value="ANY",
        )

        new_protocol = st.selectbox(
            "Protocol",
            ["TCP", "UDP", "ICMP", "ANY"],
        )

        any_port = st.checkbox(
            "Match any port",
            value=False,
        )

        new_port = st.number_input(
            "Destination Port",
            min_value=0,
            max_value=65535,
            value=8080,
            step=1,
            disabled=(
                any_port or new_protocol == "ICMP"
            ),
        )

        new_action = st.selectbox(
            "Action",
            ["ALLOW", "BLOCK"],
        )

        add_submitted = st.form_submit_button(
            "Add Firewall Rule",
            use_container_width=True,
        )

    if add_submitted:
        try:
            source_value = validate_ip_or_network(
                new_source
            )

            destination_value = validate_ip_or_network(
                new_destination
            )

            candidate = {
                "source_ip": source_value,
                "destination_ip": destination_value,
                "protocol": new_protocol,
                "port": (
                    None
                    if any_port or new_protocol == "ICMP"
                    else int(new_port)
                ),
                "action": new_action,
            }

            existing_rules = get_rules()

            duplicate = any(
                all(
                    existing.get(key) == candidate.get(key)
                    for key in candidate
                )
                for existing in existing_rules
            )

            if duplicate:
                st.warning(
                    "An identical rule already exists."
                )

            else:
                add_rule(candidate)

                st.success(
                    "Rule added at the top of the priority list."
                )

                st.rerun()

        except ValueError as exc:
            st.error(f"Invalid rule: {exc}")

    st.divider()
    st.subheader("Change Rule Priority or Delete")

    rules = get_rules()

    if rules:
        labels = []

        for index, rule in enumerate(
            rules,
            start=1
        ):
            labels.append(
                f"Priority {index} | {rule['action']} | "
                f"{rule['protocol']} | "
                f"{rule['source_ip']} → "
                f"{rule['destination_ip']} | "
                f"Port {get_rule_port(rule)} | "
                f"ID {rule['id']}"
            )

        selected_index = st.selectbox(
            "Select rule",
            options=list(range(len(rules))),
            format_func=lambda i: labels[i],
            key="selected_rule_index",
        )

        up_col, down_col, delete_col = st.columns(3)

        with up_col:
            move_up = st.button(
                "⬆️ Move Up",
                disabled=(selected_index == 0),
                use_container_width=True,
            )

        with down_col:
            move_down = st.button(
                "⬇️ Move Down",
                disabled=(
                    selected_index == len(rules) - 1
                ),
                use_container_width=True,
            )

        with delete_col:
            delete_selected = st.button(
                "🗑️ Delete Rule",
                use_container_width=True,
            )

        if move_up or move_down:
            order = [
                rule["id"]
                for rule in rules
            ]

            other_index = (
                selected_index - 1
                if move_up
                else selected_index + 1
            )

            order[selected_index], order[other_index] = (
                order[other_index],
                order[selected_index],
            )

            reorder_rules(order)
            st.rerun()

        if delete_selected:
            delete_rule(
                rules[selected_index]["id"]
            )

            st.success("Rule deleted.")
            st.rerun()

    else:
        st.info(
            "Add a rule to enable priority management."
        )


# =========================================================
# ANALYTICS DASHBOARD
# =========================================================

with dashboard_tab:
    st.subheader("Firewall Analytics")

    logs = get_packet_logs()
    df = logs_to_dataframe(logs)

    if df.empty:
        st.info(
            "No traffic recorded yet. Simulate packets "
            "to populate the analytics dashboard."
        )

    else:
        df["Decision"] = df["Decision"].str.upper()
        df["Protocol"] = df["Protocol"].str.upper()

        total = len(df)

        allowed = int(
            (df["Decision"] == "ALLOW").sum()
        )

        blocked = int(
            (df["Decision"] == "BLOCK").sum()
        )

        allow_rate = (
            allowed / total * 100
            if total else 0
        )

        block_rate = (
            blocked / total * 100
            if total else 0
        )

        metric1, metric2, metric3, metric4 = (
            st.columns(4)
        )

        metric1.metric("Total Packets", total)
        metric2.metric("Allowed", allowed)
        metric3.metric("Blocked", blocked)
        metric4.metric(
            "Block Rate",
            f"{block_rate:.1f}%",
        )

        rate1, rate2 = st.columns(2)

        with rate1:
            st.write("**Allowed traffic**")
            st.progress(int(round(allow_rate)))
            st.caption(
                f"{allow_rate:.1f}% of recorded packets"
            )

        with rate2:
            st.write("**Blocked traffic**")
            st.progress(int(round(block_rate)))
            st.caption(
                f"{block_rate:.1f}% of recorded packets"
            )

        st.divider()
        st.subheader("Allowed vs Blocked Traffic")

        decision_data = pd.DataFrame({
            "Decision": ["ALLOW", "BLOCK"],
            "Packets": [allowed, blocked],
        })

        decision_fig = px.bar(
            decision_data,
            x="Decision",
            y="Packets",
            color="Decision",
            text="Packets",
            color_discrete_map={
                "ALLOW": "#22C55E",
                "BLOCK": "#EF4444",
            },
            title="Firewall Decisions",
        )

        decision_fig.update_layout(
            height=390,
            showlegend=False,
            xaxis_title="Firewall Decision",
            yaxis_title="Number of Packets",
        )

        st.plotly_chart(
            decision_fig,
            use_container_width=True,
        )

        st.divider()
        st.subheader("Protocol-wise Firewall Decisions")

        protocol_decisions = (
            df[
                df["Decision"].isin(
                    ["ALLOW", "BLOCK"]
                )
            ]
            .groupby(["Protocol", "Decision"])
            .size()
            .reset_index(name="Packets")
        )

        if not protocol_decisions.empty:
            protocol_fig = px.bar(
                protocol_decisions,
                x="Protocol",
                y="Packets",
                color="Decision",
                barmode="group",
                text="Packets",
                color_discrete_map={
                    "ALLOW": "#22C55E",
                    "BLOCK": "#EF4444",
                },
                title="Decisions by Protocol",
            )

            protocol_fig.update_layout(
                height=420,
                xaxis_title="Network Protocol",
                yaxis_title="Number of Packets",
            )

            st.plotly_chart(
                protocol_fig,
                use_container_width=True,
            )

        st.divider()
        st.subheader("Protocol Distribution")

        protocol_counts = (
            df["Protocol"]
            .value_counts()
            .rename_axis("Protocol")
            .reset_index(name="Packets")
        )

        protocol_pie = px.pie(
            protocol_counts,
            names="Protocol",
            values="Packets",
            hole=0.45,
            title="Share of Simulated Traffic",
        )

        protocol_pie.update_traces(
            textposition="inside",
            textinfo="label+value+percent",
        )

        st.plotly_chart(
            protocol_pie,
            use_container_width=True,
        )

        st.divider()
        st.subheader("Traffic Decisions Over Time")

        time_df = df.copy()

        time_df["Parsed Time"] = pd.to_datetime(
            time_df["Time"],
            errors="coerce",
        )

        time_df = time_df.dropna(
            subset=["Parsed Time"]
        ).sort_values("Parsed Time")

        if time_df.empty:
            st.info(
                "Timestamps could not be interpreted, "
                "so the time chart is unavailable."
            )

        else:
            time_df["Allowed Count"] = (
                time_df["Decision"] == "ALLOW"
            ).cumsum()

            time_df["Blocked Count"] = (
                time_df["Decision"] == "BLOCK"
            ).cumsum()

            cumulative_df = time_df.melt(
                id_vars=["Parsed Time"],
                value_vars=[
                    "Allowed Count",
                    "Blocked Count",
                ],
                var_name="Metric",
                value_name="Cumulative Packets",
            )

            cumulative_df["Metric"] = (
                cumulative_df["Metric"].map({
                    "Allowed Count": "Allowed",
                    "Blocked Count": "Blocked",
                })
            )

            time_fig = px.line(
                cumulative_df,
                x="Parsed Time",
                y="Cumulative Packets",
                color="Metric",
                markers=True,
                color_discrete_map={
                    "Allowed": "#22C55E",
                    "Blocked": "#EF4444",
                },
                title="Cumulative Allow/Block Decisions",
            )

            time_fig.update_layout(
                height=420,
                xaxis_title="Simulation Time",
                yaxis_title="Cumulative Packets",
            )

            st.plotly_chart(
                time_fig,
                use_container_width=True,
            )

        st.divider()
        st.subheader("Protocol Summary")

        summary_df = (
            df.groupby("Protocol")
            .agg(
                Total_Packets=("Protocol", "size"),
                Allowed=(
                    "Decision",
                    lambda x: (x == "ALLOW").sum()
                ),
                Blocked=(
                    "Decision",
                    lambda x: (x == "BLOCK").sum()
                ),
            )
            .reset_index()
            .rename(columns={
                "Total_Packets": "Total Packets"
            })
        )

        st.dataframe(
            summary_df,
            hide_index=True,
            use_container_width=True,
        )


# =========================================================
# PACKET LOGS
# =========================================================

with logs_tab:
    st.subheader("Packet History")

    logs = get_packet_logs()
    df = logs_to_dataframe(logs)

    if df.empty:
        st.info(
            "No packet logs available. "
            "Simulate a packet first."
        )

    else:
        filter1, filter2, filter3 = st.columns(3)

        with filter1:
            decision_filter = st.selectbox(
                "Decision",
                ["ALL", "ALLOW", "BLOCK"],
            )

        with filter2:
            protocol_filter = st.selectbox(
                "Protocol",
                ["ALL", "TCP", "UDP", "ICMP"],
            )

        with filter3:
            ip_filter = st.text_input(
                "Search source or destination IP",
                value="",
            ).strip()

        filtered = df.copy()

        if decision_filter != "ALL":
            filtered = filtered[
                filtered["Decision"] == decision_filter
            ]

        if protocol_filter != "ALL":
            filtered = filtered[
                filtered["Protocol"] == protocol_filter
            ]

        if ip_filter:
            source_match = (
                filtered["Source IP"]
                .astype(str)
                .str.contains(
                    ip_filter,
                    regex=False,
                    case=False,
                )
            )

            destination_match = (
                filtered["Destination IP"]
                .astype(str)
                .str.contains(
                    ip_filter,
                    regex=False,
                    case=False,
                )
            )

            filtered = filtered[
                source_match | destination_match
            ]

        st.write(
            f"**{len(filtered)} matching records**"
        )

        st.dataframe(
            filtered,
            hide_index=True,
            use_container_width=True,
        )

        csv_data = filtered.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "📥 Download Filtered Logs as CSV",
            data=csv_data,
            file_name="firewall_packet_logs.csv",
            mime="text/csv",
        )

        st.divider()
        st.subheader("Recent Activity")

        recent = filtered.head(5)

        for _, row in recent.iterrows():
            label = (
                f"{row['Protocol']} | "
                f"{row['Source IP']} → "
                f"{row['Destination IP']} | "
                f"Port {row['Port']}"
            )

            message = (
                f"{row['Decision']} — {label}\n\n"
                f"Reason: {row['Reason']}"
            )

            if row["Decision"] == "ALLOW":
                st.success(message)

            elif row["Decision"] == "BLOCK":
                st.error(message)

            else:
                st.warning(message)

        st.divider()

        if st.button("🗑️ Clear All Packet Logs"):
            clear_packet_logs()
            st.success("Packet logs cleared.")
            st.rerun()


# =========================================================
# SECURITY ALERTS
# =========================================================

with alerts_tab:
    st.subheader("🚨 Suspicious Traffic Alerts")

    st.caption(
        f"An alert is raised when one source IP has at least "
        f"{ALERT_THRESHOLD} blocked simulated packets within "
        f"{ALERT_WINDOW_MINUTES} minutes. This is a basic "
        "demonstration detector, not a production IDS."
    )

    alerts = get_security_alerts()

    if not alerts:
        st.info(
            "No alerts recorded. Simulate repeated blocked "
            "packets from the same source IP to test this feature."
        )

    else:
        alert_rows = []

        for alert in alerts:
            alert_rows.append({
                "ID": alert["id"],
                "Time": alert["timestamp"],
                "Source IP": alert["source_ip"],
                "Alert Type": alert["alert_type"],
                "Severity": alert["severity"],
                "Occurrences": alert["occurrence_count"],
                "Status": alert["status"],
                "Details": alert["details"],
            })

        st.dataframe(
            pd.DataFrame(alert_rows),
            hide_index=True,
            use_container_width=True,
        )

        st.divider()
        st.subheader("Manage Alerts")

        selected_alert = st.selectbox(
            "Select alert",
            options=[a["id"] for a in alerts],
            format_func=lambda alert_id: (
                f"Alert #{alert_id} — "
                f"{next(
                    a['source_ip']
                    for a in alerts
                    if a['id'] == alert_id
                )}"
            ),
        )

        new_status = st.selectbox(
            "Alert status",
            ["OPEN", "ACKNOWLEDGED", "RESOLVED"],
        )

        col1, col2 = st.columns(2)

        with col1:
            if st.button(
                "Update Alert Status",
                use_container_width=True,
            ):
                update_alert_status(
                    selected_alert,
                    new_status,
                )

                st.success("Alert status updated.")
                st.rerun()

        with col2:
            if st.button(
                "Clear All Alerts",
                use_container_width=True,
            ):
                clear_security_alerts()
                st.success("Security alerts cleared.")
                st.rerun()
