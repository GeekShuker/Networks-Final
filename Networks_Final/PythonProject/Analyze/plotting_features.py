"""
plotting_features.py
This module provides functions to create visual comparisons between applications
based on their network traffic features extracted from Wireshark CSVs.

Each function generates a different type of bar chart or histogram,
focusing on a specific network metric.

These plots help visualize behavioral fingerprints across applications
(e.g., Zoom vs Chrome vs Spotify), even when payload is encrypted.

Examples of insights revealed by these charts:
- Flow size/volume reveals bursty vs persistent traffic.
- Unique IPs and flows suggest server/client dynamics.
- TCP flags and retransmissions highlight connection behavior.
- Multicast/Broadcast reveal special protocols (e.g., discovery, conferencing).
- Top ports and protocol mix provide app-layer clues.

These visualizations are useful for both manual analysis and explaining patterns
in automated app classification or anomaly detection.
"""

import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

def plot_flow_size(extended_summary):
    """
    Display a bar chart for the Flow Size (number of packets in the first 10 seconds) for each application.
    """
    # Extract list of application names
    apps = list(extended_summary.keys())
    # Create X axis locations
    x = np.arange(len(apps))
    # Get flow size for each application
    flow_size = [extended_summary[app]['flow_size_10s'] for app in apps]

    # Start new figure for plotting
    plt.figure(figsize=(8, 5))
    # Bar plot: flow size per application
    plt.bar(x, flow_size, color='blue', label='Flow Size (10s)')
    # Set X-ticks to application names
    plt.xticks(x, apps)
    plt.xlabel("Application")
    plt.ylabel("Number of Packets")
    plt.title("Flow Size (10s)")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_flow_volume(extended_summary):
    """
    Display a bar chart for the Flow Volume (total bytes in the first 10 seconds) for each application.
    """
    # Application names
    apps = list(extended_summary.keys())
    # X axis positions
    x = np.arange(len(apps))
    # Get total flow volume (bytes) for each app
    flow_volume = [extended_summary[app]['flow_volume_10s'] for app in apps]

    plt.figure(figsize=(8, 5))
    plt.bar(x, flow_volume, color='orange', label='Flow Volume (10s)')
    plt.xticks(x, apps)
    plt.xlabel("Application")
    plt.ylabel("Total Bytes")
    plt.title("Flow Volume (10s)")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_unique_ips_flows(extended_summary):
    """
    Display a bar chart for unique source IPs, unique destination IPs, and unique flows for each application.
    """
    # Extract application names and axis positions
    apps = list(extended_summary.keys())
    x = np.arange(len(apps))
    # For each app, extract the relevant statistics
    unique_sources = [extended_summary[app]['unique_sources'] for app in apps]
    unique_destinations = [extended_summary[app]['unique_destinations'] for app in apps]
    unique_flows = [extended_summary[app]['unique_flows'] for app in apps]
    width = 0.2  # Width of each bar

    plt.figure(figsize=(6, 5))
    # Three adjacent bars per app: sources, destinations, flows
    plt.bar(x - width, unique_sources, width, label='Unique Sources')
    plt.bar(x, unique_destinations, width, label='Unique Destinations')
    plt.bar(x + width, unique_flows, width, label='Unique Flows')
    plt.xticks(x, apps)
    plt.xlabel("Application")
    plt.title("Unique Sources, Destinations & Flows")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_multicast_packets(extended_summary):
    """
    Display a bar chart for the number of multicast packets for each application.
    """
    apps = list(extended_summary.keys())
    x = np.arange(len(apps))
    multicast_packets = [extended_summary[app]['multicast_packets'] for app in apps]

    plt.figure(figsize=(8, 5))
    # Plot multicast packets per app in green
    plt.bar(x, multicast_packets, color='green', label='Multicast Packets')
    plt.xticks(x, apps)
    plt.xlabel("Application")
    plt.ylabel("Number of Packets")
    plt.title("Multicast Packets")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_broadcast_packets(extended_summary):
    """
    Display a bar chart for the number of broadcast packets for each application.
    """
    apps = list(extended_summary.keys())
    x = np.arange(len(apps))
    broadcast_packets = [extended_summary[app]['broadcast_packets'] for app in apps]

    plt.figure(figsize=(8, 5))
    # Plot broadcast packets per app in purple
    plt.bar(x, broadcast_packets, color='purple', label='Broadcast Packets')
    plt.xticks(x, apps)
    plt.xlabel("Application")
    plt.ylabel("Number of Packets")
    plt.title("Broadcast Packets")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_tcp_flags_distribution(tcp_flags_dict, apps_list):
    """
    Display a bar chart for the TCP flags distribution (SYN, ACK, PSH, RST, FIN, URG) for each application.
    """
    plt.figure(figsize=(10, 5))
    flags_list = ["SYN", "ACK", "PSH", "RST", "FIN", "URG"]
    x = np.arange(len(flags_list))
    # Plot bars for each app, offsetting by small width
    for i, app in enumerate(apps_list):
        # Get count of each flag for this app
        counts = [tcp_flags_dict.get(app, Counter()).get(flag, 0) for flag in flags_list]
        plt.bar(x + i * 0.13, counts, width=0.13, label=app)
    # Set X-ticks to flag names, center between groups
    plt.xticks(x + 0.13 * (len(apps_list) / 2), flags_list)
    plt.xlabel("TCP Flags")
    plt.ylabel("Count")
    plt.title("TCP Flags Distribution")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_feature_bar(summary_dict, metric):
    """
    Display a bar chart for a specific metric (e.g., average packet size) for each application.
    Parameters:
        summary_dict (dict): Dictionary with application as key and stats as value.
        metric (str): Name of the metric (key in summary_dict[app]).
    """
    plt.figure(figsize=(8, 4))
    # List of application names
    apps = list(summary_dict.keys())
    # Get metric value for each app, default to 0 if missing
    values = [summary_dict[app].get(metric, 0) for app in apps]
    plt.bar(apps, values, color='skyblue', edgecolor='black')
    plt.title(f"{metric.replace('_', ' ').title()} by Application")
    plt.xlabel("Application")
    plt.ylabel(metric.replace('_', ' ').title())
    plt.tight_layout()
    plt.show()

def plot_connection_events(events_dict):
    """
    Display a bar chart for connection events (e.g., SYN, FIN, RST) for each application.
    """
    # Get all unique event keys (SYN, FIN, RST, etc.)
    keys = set()
    for app_events in events_dict.values():
        keys.update(app_events.keys())
    keys = sorted(keys)

    plt.figure(figsize=(10, 5))
    x = range(len(events_dict))
    # For each event type, plot a bar for each app
    for i, k in enumerate(keys):
        # Collect the count for each app for this event
        vals = [events_dict[app].get(k, 0) for app in events_dict]
        plt.bar([xi + i * 0.13 for xi in x], vals, width=0.13, label=k)
    plt.xticks([xi + 0.13 * len(keys) / 2 for xi in x], events_dict.keys())
    plt.xlabel("Application")
    plt.ylabel("Count")
    plt.title("Connection Events Distribution")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_combined_top_ports(top_ports_dict):
    """
    Display a bar chart for the most common ports across applications.
    """
    plt.figure(figsize=(12, 6))
    # Gather all unique port numbers from all apps
    all_ports = set()
    for ports in top_ports_dict.values():
        all_ports.update(ports.keys())
    all_ports = sorted(all_ports)
    x = range(len(all_ports))
    width = 0.13
    # For each app, plot a bar for each port
    for i, (app, ports) in enumerate(top_ports_dict.items()):
        counts = [ports.get(p, 0) for p in all_ports]
        plt.bar([xi + i * width for xi in x], counts, width=width, label=app)
    # Set X-ticks to port numbers, centered for group
    plt.xticks([xi + width * len(top_ports_dict) / 2 for xi in x], all_ports, rotation=45)
    plt.xlabel("Port")
    plt.ylabel("Count")
    plt.title("Top Ports Across Applications")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_protocol_distribution(protocols_dict, apps_list):
    """
    Display a bar chart for the protocol distribution for each application.
    """
    plt.figure(figsize=(12, 6))
    # Get list of all unique protocols in all apps
    all_protocols = sorted(set(proto for proto_counts in protocols_dict.values() for proto in proto_counts))
    x = np.arange(len(all_protocols))
    width = 0.13
    # For each app, plot the protocol distribution
    for i, app in enumerate(apps_list):
        counts = [protocols_dict.get(app, {}).get(proto, 0) for proto in all_protocols]
        plt.bar(x + i * width, counts, width=width, label=app)
    plt.xticks(x + width * (len(apps_list) / 2), all_protocols, rotation=90)
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.title("Protocol Distribution Across Applications")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_new_connections_vs_retransmissions(extended_summary):
    """
    Display a bar chart comparing the number of new connections and retransmissions for each application.
    """
    # Get list of apps and their positions on axis
    apps = list(extended_summary.keys())
    x = np.arange(len(apps))
    # For each app, get new connection and retransmission count
    new_conn = [extended_summary[app]['new_connections'] for app in apps]
    retrans = [extended_summary[app]['retransmissions'] for app in apps]
    width = 0.35

    plt.figure(figsize=(8, 5))
    # Plot two bars per app: left = new connections, right = retransmissions
    plt.bar(x - width/2, new_conn, width, label="New Connections", color='lightcoral', edgecolor='black')
    plt.bar(x + width/2, retrans, width, label="Retransmissions", color='gray', edgecolor='black')
    plt.xticks(x, apps, rotation=45)
    plt.xlabel("Application")
    plt.ylabel("Count")
    plt.title("New Connections vs Retransmissions")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_repeated_packets(extended_summary):
    """
    Display a bar chart for the number of repeated packets for each application.
    """
    apps = list(extended_summary.keys())
    # Get count of repeated packets for each app
    repeated = [extended_summary[app]['repeated_packets'] for app in apps]
    plt.figure(figsize=(8, 5))
    # Plot repeated packets per app in gold
    plt.bar(apps, repeated, color='gold', edgecolor='black')
    plt.xlabel("Application")
    plt.ylabel("Repeated Packets Count")
    plt.title("Repeated Packets")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
