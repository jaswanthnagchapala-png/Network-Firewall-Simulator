# Network Firewall Simulator

A Python-based web application that simulates firewall rule evaluation, packet filtering decisions, traffic logging, and security alerts through an interactive dashboard.

## Overview

The Network Firewall Simulator demonstrates how firewall rules can be used to evaluate network packets and decide whether traffic should be allowed or blocked. Users can configure rules, simulate packets, review traffic logs, and monitor suspicious activity.

**Note:** This is an educational software simulation. It does not configure an operating system firewall or block real network traffic.

## Features

- **Packet Simulation:** Test packets using source IP, destination IP, protocol, and port.
- **Firewall Rule Management:** Add and manage rules to allow or block traffic.
- **CIDR Support:** Match IP addresses against network ranges.
- **Rule Priorities:** Evaluate matching rules according to their order and priority.
- **Default Deny:** Block packets when no applicable rule allows them.
- **Analytics Dashboard:** Visualize packet activity and filtering results.
- **Packet Logs:** Review recorded packet decisions and export logs to CSV.
- **Security Alerts:** Detect repeated blocked traffic from the same source and generate alerts.
- **SQLite Database:** Store firewall rules, packet logs, and security alerts.
- **Docker Support:** Run the application in a container.

## Technologies Used

- Python
- Streamlit
- SQLite
- Pandas
- Plotly
- Docker

## Project Structure

```text
Network-Firewall-Simulator/
├── app.py
├── firewall.py
├── database.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── .gitignore
└── README.md
```

Additional files may be present depending on your project setup.

## Requirements

- Python 3.10 or later
- pip
- A web browser

For containerized execution, Docker Desktop or another working Docker installation is required.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/Network-Firewall-Simulator.git
cd Network-Firewall-Simulator
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment (recommended)

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation, you can run the application using the environment's Python executable directly.

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

## Using the Application

1. Open the Packet Simulator and enter the packet details.
2. Submit the packet for evaluation.
3. Review whether the packet is allowed or blocked and inspect the matching rule.
4. Use Firewall Rules to configure filtering behavior.
5. Explore the Analytics Dashboard to review traffic statistics.
6. Open Packet Logs to inspect recorded decisions and export data.
7. Review Security Alerts for repeated blocked traffic.

## Docker

Build the Docker image from the project directory:

```bash
docker build -t network-firewall-simulator .
```

Run the container:

```bash
docker run -d --name firewall-simulator -p 8501:8501 -v firewall_data:/app/data network-firewall-simulator
```

Open `http://localhost:8501` in your browser.

The named Docker volume is intended to preserve application data across container recreation when the application is configured to store its database in `/app/data`.

## Learning Objectives

- Understand the basic purpose of network firewalls.
- Learn how allow and block rules affect packet-filtering decisions.
- Explore IP address and CIDR-based matching.
- Understand rule ordering and default-deny behavior.
- Practice logging, data visualization, and basic security monitoring.
- Gain experience building a Python web application and packaging it with Docker.

## Limitations

- The application simulates packet filtering; it does not inspect or block actual network packets.
- Security alerts are based on the application's configured detection logic.
- Results depend on the configured firewall rules and the packet information supplied by the user.

## Future Improvements

- Add rule import and export.
- Expand alerting and traffic-analysis options.
- Add automated tests for firewall evaluation.
- Improve reporting and filtering in packet logs.

## License

No license has been specified yet. Add a license before permitting others to reuse or distribute this project.
