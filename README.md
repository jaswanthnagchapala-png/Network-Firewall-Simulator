# Network Firewall Simulator

A Python-based web application that simulates firewall rule evaluation and packet filtering through an interactive dashboard. The project demonstrates how network traffic can be evaluated using firewall rules, logged, and analyzed for suspicious activity.

## Overview

The Network Firewall Simulator provides a practical way to understand the basic working principles of a network firewall. Users can simulate packets, configure firewall rules, inspect filtering decisions, view traffic statistics, and monitor security alerts.

**This is an educational simulation. It does not block real network traffic or modify the operating system's firewall.**

## Features

- **Packet Simulation:** Simulate packets using source IP address, destination IP address, protocol, and port.
- **Firewall Rule Management:** Add and manage rules to allow or block traffic.
- **IP and CIDR Matching:** Support IP address and network-range matching.
- **Rule Priority:** Evaluate matching rules according to their configured order.
- **Default Deny:** Block packets when no applicable rule permits the traffic.
- **Analytics Dashboard:** Visualize packet activity and filtering results.
- **Packet Logging:** Record packet evaluation results and review traffic logs.
- **CSV Export:** Export packet logs for further analysis.
- **Security Alerts:** Identify repeated blocked traffic from the same source using the configured alert logic.
- **SQLite Database:** Store firewall rules, packet logs, and security alerts.

## Technologies Used

- Python
- Streamlit
- SQLite
- Pandas
- Plotly

## Project Structure

```text
Network-Firewall-Simulator/
├── app.py
├── firewall.py
├── database.py
├── requirements.txt
├── .gitignore
└── README.md
```

The files shown above represent the core project structure. Your repository may contain additional files.

## Requirements

- Python 3.10 or later
- pip
- A modern web browser

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/jaswanthnagchapala-png/Network-Firewall-Simulator.git
cd Network-Firewall-Simulator
```

### 2. Create a virtual environment (recommended)

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal, usually:

```text
http://localhost:8501
```

## How to Use

1. Open the Packet Simulator.
2. Enter the packet details, including IP addresses, protocol, and port.
3. Submit the packet and inspect the allow or block decision.
4. Add or modify firewall rules to experiment with different filtering policies.
5. Use the Analytics Dashboard to examine packet statistics.
6. Review Packet Logs and export records to CSV.
7. Check Security Alerts for repeated blocked traffic.

## How It Works

1. The user enters packet information through the Streamlit interface.
2. The application passes the packet details to the firewall evaluation logic.
3. The firewall checks the configured rules and their matching conditions.
4. The application determines whether the simulated packet is allowed or blocked.
5. The result is recorded in the SQLite database.
6. The dashboard displays logs, analytics, and relevant security alerts.

## Learning Objectives

- Understand basic network firewall concepts.
- Learn how allow and block rules influence packet filtering.
- Understand rule priority and default-deny behavior.
- Practice IP address and CIDR-based matching.
- Explore packet logging and security alert logic.
- Build an interactive application using Python and Streamlit.
- Store and analyze application data using SQLite and Pandas.

## Limitations

- Packet filtering is simulated; real network packets are not intercepted or blocked.
- Alert generation depends on the application's configured detection conditions.
- Results depend on the packet information and firewall rules supplied by the user.

## Future Enhancements

- Add automated unit tests for firewall rules.
- Improve traffic filtering and log search.
- Add more security alert conditions.
- Support importing and exporting firewall rules.
- Expand analytics and reporting features.

## License

No license has been specified. A license can be added if the project is intended for reuse or distribution.
