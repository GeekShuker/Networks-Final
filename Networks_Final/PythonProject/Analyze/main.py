"""
     This script processes Wireshark-exported CSV files from different applications,
     extracts traffic features, and visualizes them for comparison.

    Key logic sections that could use extra explanation:

     1. Loading and verifying CSVs:
     - Checks whether all required network capture files exist before proceeding.
     - If any are missing, the script exits early.

     2. Processing per-application network data:
     - For each application, the CSV is read into a DataFrame.
     - Various statistical and structural network features are computed, such as:
       a. Packet sizes (mean, std deviation)
       b. Inter-arrival times (mean, std deviation)
       c. Packet counts and volume in the first 10 seconds
       d. IP address and flow diversity
       e. Special packet types (IPv6, broadcast, multicast)
       f. TCP reliability indicators (retransmissions, duplicates)
       g. TCP handshake-related event counts (SYN, FIN, RST)
       h. RTT estimation using SYN-SYN/ACK pairing
       i. Port usage summary
       j. QoS field variety (DSCP field)

     3. Data aggregation:
     - All stats are stored in dictionaries by app name for plotting.

     4. Plotting and visualization:
     - Each feature is visualized using bar charts or histograms.
     - For example: flow size, flow volume, unique IPs, TCP flags, RTT distribution.
     - These plots allow intuitive visual comparison between applications.


    Main script to load CSV files, perform network traffic analysis, and display plots.

"""

import os
from unified_feature_extraction import *
from plotting_features import *

# Set the directory where the CSV files are stored
csv_folder = os.path.join(os.getcwd(), "wireshark_files")

# Map application names to their CSV files
csv_files = {
    "Chrome": os.path.join(csv_folder, "chrome.csv"),
    "Firefox": os.path.join(csv_folder, "firefox.csv"),
    "Spotify": os.path.join(csv_folder, "spotify.csv"),
    "YouTube": os.path.join(csv_folder, "youtube.csv"),
    "Zoom": os.path.join(csv_folder, "zoomrecord.csv")
}

# Check if all files exist; exit if any are missing
missing = [app for app, path in csv_files.items() if not os.path.exists(path)]
if missing:
    print("Missing files:", missing)
    exit()
else:
    print("All CSV files found.")

# Dictionaries for aggregating analysis results per application
protocols_dict = {}            # Protocol distribution per app
flags_dict = {}                # TCP flags distribution per app
extended_summary = {}          # Main feature summary per app
connection_events_summary = {} # SYN/FIN/RST events per app
rtt_data = {}                  # RTT list per app
top_ports_dict = {}            # Top ports per app

# Process each CSV file for each application
for app, path in csv_files.items():
    # Load packet data for this application
    df = read_csv(path)
    if df is None or df.empty:
        continue

    # Basic feature extraction
    # Count protocols and TCP flag distribution for this app
    protocols_dict[app] = count_protocols(df)
    flags_dict[app] = get_tcp_flags_distribution(df)

    # Create a summary dictionary for each application
    summary = {}
    # Compute average packet size
    summary['avg_packet_size'] = calculate_avg_packet_size(df)

    # Compute inter-arrival time stats
    iats = calculate_inter_arrival_times(df)
    summary['mean_iat'] = np.mean(iats) if len(iats) > 0 else 0
    summary['std_iat'] = np.std(iats) if len(iats) > 0 else 0
    summary['std_packet_size'] = df['Length'].std()

    # Flow features: how much data/packets in the first 10 seconds
    summary['flow_size_10s'] = flow_size_in_first_10_seconds(df)
    summary['flow_volume_10s'] = flow_volume_in_first_10_seconds(df)

    # Transmission quality features
    summary['retransmissions'] = count_retransmissions(df)
    summary['new_connections'] = count_new_connections(df)
    summary['repeated_packets'] = count_repeated_packets(df)

    # Unique IPs and flows
    ip_stats = get_unique_ip_stats(df)
    summary.update(ip_stats)

    # Count IPv6, broadcast, and multicast packets
    summary['ipv6_packets'] = count_ipv6_packets(df)
    summary['broadcast_packets'] = count_broadcast_packets(df)
    summary['multicast_packets'] = count_multicast_packets(df)

    # Analyze QoS, events, top ports
    qos_results = analyze_qos_events_ports(df)
    summary['unique_qos_values'] = qos_results.get('unique_qos_values', 0)
    summary['top_ports'] = qos_results.get('top_ports', {})

    extended_summary[app] = summary

    # Count connection events (SYN, FIN, RST, etc.) for this application
    event_counter = Counter()
    for ev in qos_results.get('connection_events', []):
        for k, v in ev.items():
            if v:
                event_counter[k] += 1
    connection_events_summary[app] = dict(event_counter)

    # Compute RTT values for this application
    rtt_data[app] = calculate_rtt(df)
    # Save top ports for port distribution plots
    top_ports_dict[app] = summary['top_ports']

# --- Plotting ---
# Each plot below compares the different applications for one key feature

plot_flow_size(extended_summary)                      # Number of packets per app in first 10 seconds
plot_flow_volume(extended_summary)                    # Number of bytes per app in first 10 seconds
plot_unique_ips_flows(extended_summary)               # Unique sources/destinations/flows per app
plot_broadcast_packets(extended_summary)              # Number of broadcast packets per app
plot_multicast_packets(extended_summary)              # Number of multicast packets per app
plot_new_connections_vs_retransmissions(extended_summary) # Compare new connections vs retransmissions
plot_repeated_packets(extended_summary)               # Number of repeated packets per app
plot_connection_events(connection_events_summary)      # TCP events per app

# Plot RTT distributions for all applications (histograms)
plt.figure(figsize=(10, 5))
for app, rtts in rtt_data.items():
    if rtts:
        plt.hist(rtts, bins=30, alpha=0.5, label=app)
plt.xlabel("RTT")
plt.ylabel("Frequency")
plt.title("RTT Distribution")
plt.legend()
plt.tight_layout()
plt.show()

plot_combined_top_ports(top_ports_dict)               # Top ports used by each app
apps_list = list(csv_files.keys())
plot_protocol_distribution(protocols_dict, apps_list) # Protocols per app
plot_tcp_flags_distribution(flags_dict, apps_list)    # TCP flags per app

print("\nAnalysis Complete!")
