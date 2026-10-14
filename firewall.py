
import ipaddress

DEFAULT_RULES = [
    {
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 80,
        "action": "ALLOW",
    },
    {
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 443,
        "action": "ALLOW",
    },
    {
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 22,
        "action": "BLOCK",
    },
    {
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 23,
        "action": "BLOCK",
    },
    {
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "UDP",
        "port": 53,
        "action": "ALLOW",
    },
]


def validate_ip_or_network(value, allow_any=True):
    """Validate and normalize an IP address, CIDR network, or ANY."""
    value = str(value).strip()

    if allow_any and value.upper() == "ANY":
        return "ANY"

    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))

        return str(ipaddress.ip_address(value))

    except ValueError as exc:
        raise ValueError(
            f"Invalid IP address or CIDR network: {value}"
        ) from exc


def address_matches(rule_value, packet_ip):
    """Check whether a packet IP matches an exact IP or CIDR rule."""
    rule_value = str(rule_value).strip()

    if rule_value.upper() == "ANY":
        return True

    try:
        packet_address = ipaddress.ip_address(str(packet_ip))

        if "/" in rule_value:
            network = ipaddress.ip_network(
                rule_value,
                strict=False
            )

            return (
                packet_address.version == network.version
                and packet_address in network
            )

        rule_address = ipaddress.ip_address(rule_value)

        return packet_address == rule_address

    except ValueError:
        return False


def evaluate_packet(
    source_ip,
    destination_ip,
    protocol,
    port,
    rules
):
    """Evaluate a simulated packet against ordered firewall rules."""

    protocol = str(protocol).strip().upper()

    try:
        source_ip = str(ipaddress.ip_address(source_ip))
        destination_ip = str(
            ipaddress.ip_address(destination_ip)
        )
    except ValueError:
        return {
            "action": "BLOCK",
            "reason": "Invalid source or destination IP address.",
            "rule_number": None,
        }

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0

    if protocol not in {"TCP", "UDP", "ICMP"}:
        return {
            "action": "BLOCK",
            "reason": "Unsupported network protocol.",
            "rule_number": None,
        }

    for priority, rule in enumerate(rules, start=1):
        source_matches = address_matches(
            rule.get("source_ip", "ANY"),
            source_ip
        )

        destination_matches = address_matches(
            rule.get("destination_ip", "ANY"),
            destination_ip
        )

        rule_protocol = str(
            rule.get("protocol", "ANY")
        ).upper()

        protocol_matches = (
            rule_protocol == "ANY"
            or rule_protocol == protocol
        )

        rule_port = rule.get("port")

        # ICMP has no TCP/UDP port.
        port_matches = (
            protocol == "ICMP"
            or rule_port is None
            or int(rule_port) == port
        )

        if (
            source_matches
            and destination_matches
            and protocol_matches
            and port_matches
        ):
            rule_number = rule.get("id", priority)
            action = str(
                rule.get("action", "BLOCK")
            ).upper()

            return {
                "action": action,
                "reason": (
                    f"Matched rule #{rule_number} "
                    f"(priority {priority})."
                ),
                "rule_number": rule_number,
            }

    return {
        "action": "BLOCK",
        "reason": (
            "No matching rule. "
            "Default-deny policy applied."
        ),
        "rule_number": None,
    }
