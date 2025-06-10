"""
    Overall Goal:
    This module extracts statistical and behavioral features from Wireshark-exported CSVs.
    It operates entirely on metadata (e.g., headers, timing, packet lengths), not decrypted content.

    === BASIC METRICS ===
    These functions provide general traffic statistics such as protocol counts,
    packet size distributions, and arrival timing — useful for identifying app behavior patterns.

    === TRANSPORT LAYER FEATURES ===
    Functions like `get_tcp_flags_distribution`, `count_retransmissions`, and
    `calculate_rtt` focus on TCP control-level signals. These help:
      - detect handshake patterns
      - estimate latency
      - infer reliability of the connection (e.g., retransmissions)

    === FLOW INITIATION METRICS ===
    `count_new_connections` finds TCP SYN packets not followed by SYN-ACK,
    suggesting new session attempts (important for Zoom/Youtube vs Spotify).

    === TRAFFIC SHAPE & BURSTINESS ===
    Inter-arrival times (`calculate_inter_arrival_times`) and volume in first 10 seconds
    (`flow_size_in_first_10_seconds`, `flow_volume_in_first_10_seconds`) quantify how "bursty" or front-loaded
    traffic is – e.g., Spotify vs Chrome.

    === ADDRESSING & STRUCTURE ===
    `get_unique_ip_stats`, `count_broadcast_packets`, `count_multicast_packets`,
    `count_ipv6_packets` — these give clues about:
      - network role (client/server behavior)
      - use of special address types (e.g., multicast in Zoom/YouTube)

    === ADVANCED FEATURES: QoS + PORTS ===
    - `extract_qos_data`: extracts DSCP field to detect priority handling.
    - `analyze_qos_events_ports`: combines TCP control flags + port frequency + QoS tags
      to give a richer signature of the app’s low-level traits.

    Intended Use:
    All extracted features feed into visualizations or machine learning models
    for fingerprinting, classification, or anomaly detection of encrypted apps.
"""

import pandas as pd
import numpy as np
import re
from collections import Counter, defaultdict

def read_csv(file_path):
    """
    Read a CSV file using pandas with specific encoding.
    Parameters:
        file_path (str): Path to the CSV file.
    Returns:
        pd.DataFrame or None: DataFrame with the packet data, or None on failure.
    """
    try:
        return pd.read_csv(file_path, encoding='ISO-8859-1')
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

# ==================== BASIC FEATURES ====================

def count_protocols(df):
    """
    Count the occurrences of each protocol in the DataFrame.
    Parameters:
        df (pd.DataFrame): Network packet data with 'Protocol' column.
    Returns:
        dict: Protocol name as key, count as value.
    """
    # Fill missing values with 'Unknown' and count each protocol
    return df['Protocol'].fillna('Unknown').value_counts().to_dict()

def get_tcp_flags_distribution(df):
    """
    Count occurrences of TCP flags (SYN, ACK, PSH, RST, FIN, URG) in the 'Info' column.
    Parameters:
        df (pd.DataFrame): Network packet data with 'Info' column.
    Returns:
        Counter: Keys are TCP flag names, values are counts.
    """
    flags_counter = Counter()
    # Iterate over each row's Info field to check for each TCP flag
    for info in df['Info'].fillna(''):
        for flag in ['SYN', 'ACK', 'PSH', 'RST', 'FIN', 'URG']:
            if flag in info:
                flags_counter[flag] += 1
    return flags_counter

def count_retransmissions(df):
    """
    Count the number of retransmissions.
    A retransmission is identified by 'Retransmission' appearing in the 'Info' column.
    Parameters:
        df (pd.DataFrame): Network packet data.
    Returns:
        int: Number of retransmissions.
    """
    # Use pandas string search to find 'Retransmission' rows
    return df['Info'].str.contains('Retransmission', na=False).sum()

def calculate_rtt(df):
    """
    Calculate round-trip time (RTT) by matching SYN packets with corresponding SYN-ACK packets.
    Parameters:
        df (pd.DataFrame): Must have 'Info', 'Source', 'Destination', 'Time'.
    Returns:
        list: RTT values for matched connections.
    """
    # Get all SYN packets (not SYN-ACK) and all SYN-ACK packets
    syn_df = df[df['Info'].str.contains(r'\[SYN\]', na=False)].copy()
    syn_ack_df = df[df['Info'].str.contains(r'\[SYN, ACK\]', na=False)].copy()
    rtts = []
    # For each SYN, find a matching SYN-ACK in the reverse direction that occurs later
    for _, syn_row in syn_df.iterrows():
        match = syn_ack_df[
            (syn_ack_df['Source'] == syn_row['Destination']) &
            (syn_ack_df['Destination'] == syn_row['Source']) &
            (syn_ack_df['Time'] > syn_row['Time'])
        ]
        if not match.empty:
            # Compute RTT as time difference between SYN and first SYN-ACK
            rtts.append(match.iloc[0]['Time'] - syn_row['Time'])
    return rtts

def calculate_avg_packet_size(df):
    """
    Compute the average packet size in the DataFrame.
    Parameters:
        df (pd.DataFrame): Must have 'Length' column.
    Returns:
        float: Average packet size.
    """
    # Drop missing values and compute mean
    sizes = df['Length'].dropna().values
    return np.mean(sizes) if len(sizes) > 0 else 0

def calculate_inter_arrival_times(df):
    """
    Calculate time differences between consecutive packets.
    Parameters:
        df (pd.DataFrame): Must have 'Time' column.
    Returns:
        np.ndarray: Array of inter-arrival times.
    """
    times = df['Time'].dropna().values
    # np.diff computes time between consecutive entries
    return np.diff(times) if len(times) > 1 else []

def flow_size_in_first_10_seconds(df):
    """
    Count number of packets in the first 10 seconds of the capture.
    Parameters:
        df (pd.DataFrame): Must have 'Time' column.
    Returns:
        int: Number of packets in the first 10 seconds.
    """
    # The first packet's timestamp is the reference (start time)
    start = df['Time'].iloc[0]
    # Filter packets in the first 10 seconds
    return df[df['Time'] <= start + 10].shape[0]

def flow_volume_in_first_10_seconds(df):
    """
    Calculate total size (bytes) of packets in the first 10 seconds.
    Parameters:
        df (pd.DataFrame): Must have 'Time' and 'Length' columns.
    Returns:
        int: Total bytes sent in first 10 seconds.
    """
    start = df['Time'].iloc[0]
    # Sum the 'Length' of packets in the first 10 seconds
    return df[df['Time'] <= start + 10]['Length'].sum()

def count_ipv6_packets(df):
    """
    Count packets using IPv6 based on ':' character in the 'Source' address.
    Parameters:
        df (pd.DataFrame): Must have 'Source' column.
    Returns:
        int: Number of IPv6 packets.
    """
    # IPv6 addresses contain ':' (colon)
    return df['Source'].astype(str).str.contains(':').sum()

def count_broadcast_packets(df):
    """
    Count broadcast packets by checking for 'ff:ff:ff' or 'Broadcast' in 'Destination'.
    Parameters:
        df (pd.DataFrame): Must have 'Destination' column.
    Returns:
        int: Number of broadcast packets.
    """
    return df['Destination'].astype(str).str.contains('ff:ff:ff|Broadcast', case=False).sum()

def count_multicast_packets(df):
    """
    Count multicast packets based on multicast address patterns in 'Destination'.
    Parameters:
        df (pd.DataFrame): Must have 'Destination' column.
    Returns:
        int: Number of multicast packets.
    """
    # Match typical IPv6 multicast or the word "multicast"
    return df['Destination'].astype(str).str.contains('ff0|ff02|multicast', case=False).sum()

def get_unique_ip_stats(df):
    """
    Calculate statistics on unique IP addresses and flows.
    Parameters:
        df (pd.DataFrame): Must have 'Source' and 'Destination' columns.
    Returns:
        dict: Counts for unique_sources, unique_destinations, unique_flows (source-destination pairs).
    """
    return {
        'unique_sources': df['Source'].nunique(),
        'unique_destinations': df['Destination'].nunique(),
        'unique_flows': df.groupby(['Source', 'Destination']).ngroups
    }

# ==================== ADVANCED FEATURES ====================

def extract_tcp_window_size(row):
    """
    Extract TCP window size value from a packet row (if available).
    Parameters:
        row (pd.Series): Row from DataFrame.
    Returns:
        int or None: Window size or None if not present/cannot convert.
    """
    try:
        return int(row.get('tcp.window_size', None))
    except (TypeError, ValueError):
        # Return None if not available or invalid
        return None

def extract_qos_data(row):
    """
    Extract QoS (DSField) value from a row, convert from hex to integer.
    Parameters:
        row (pd.Series): Row from DataFrame.
    Returns:
        int or None: Integer value of QoS or None.
    """
    try:
        return int(row.get('ip.dsfield', None), 16)
    except (TypeError, ValueError):
        return None

def identify_connection_events(info_str):
    """
    Identify connection-related events (SYN, FIN, RST, Duplicate ACK) in a packet's Info field.
    Parameters:
        info_str (str): Packet's Info string.
    Returns:
        defaultdict(bool): Events detected (key=True if event is present).
    """
    events = defaultdict(bool)
    # SYN without ACK means connection initiation
    if 'SYN' in info_str and 'ACK' not in info_str:
        events['SYN'] = True
    # FIN indicates connection teardown
    if 'FIN' in info_str:
        events['FIN'] = True
    # RST indicates connection reset
    if 'RST' in info_str:
        events['RST'] = True
    # Dup Ack or Duplicate ACK indicate duplicate acknowledgment
    if 'Dup Ack' in info_str or 'Duplicate ACK' in info_str:
        events['Dup_ACK'] = True
    return events

def analyze_qos_events_ports(df):
    """
    Analyze advanced features: extract QoS values, identify connection events, and count common ports.
    Parameters:
        df (pd.DataFrame): DataFrame containing packet capture data.
    Returns:
        dict: Summary of tcp window sizes, unique QoS values, connection events, and top 5 ports.
    """
    results = {
        'tcp_window_sizes': [],
        'qos_values': [],
        'connection_events': [],
        'top_ports': {}
    }

    qos_decimal = []
    port_guesses = []

    # Iterate over each row (packet) in the DataFrame
    for _, row in df.iterrows():
        # Try to extract TCP window size (if present)
        tws = extract_tcp_window_size(row)
        if tws is not None:
            results['tcp_window_sizes'].append(tws)

        # Try to extract QoS field (if present)
        qos = extract_qos_data(row)
        if qos is not None:
            qos_decimal.append(qos)

        # Analyze connection events (SYN, FIN, RST, Dup ACK) from the 'Info' field
        info_str = str(row.get('Info', ''))
        results['connection_events'].append(identify_connection_events(info_str))

        # Try to guess port numbers that appear in the Info string (regex for 2-5 digit numbers)
        ports = re.findall(r'\b\d{2,5}\b', info_str)
        port_guesses.extend(ports)

    # Calculate number of unique QoS values found
    results['unique_qos_values'] = len(set(qos_decimal)) if qos_decimal else 0
    # Count most common ports (top 5)
    port_counts = Counter(port_guesses)
    results['top_ports'] = dict(port_counts.most_common(5))

    return results

# Additional utility functions for feature extraction

def count_new_connections(df):
    """
    Count packets that contain [SYN] but not [SYN, ACK], indicating a new connection attempt.
    Parameters:
        df (pd.DataFrame): DataFrame with an 'Info' column.
    Returns:
        int: Number of new connection attempts.
    """
    if 'Info' not in df.columns:
        return 0

    # Create boolean masks for [SYN] and [SYN, ACK] packets
    syn_mask = df['Info'].str.contains(r'\[SYN\]', na=False)
    syn_ack_mask = df['Info'].str.contains(r'\[SYN, ACK\]', na=False)

    # Count SYN packets that are not also SYN-ACK (initial connection attempts)
    return (syn_mask & ~syn_ack_mask).sum()

def count_repeated_packets(df):
    """
    Count packets that indicate retransmissions or duplicate acknowledgments.
    Parameters:
        df (pd.DataFrame): DataFrame with an 'Info' column.
    Returns:
        int: Number of repeated (retransmission/dup ack) packets.
    """
    if 'Info' not in df.columns:
        return 0
    # Search for 'Retransmission', 'Dup Ack', or 'Duplicate ACK' in Info
    return df['Info'].str.contains('Retransmission|Dup Ack|Duplicate ACK', case=False, na=False).sum()
