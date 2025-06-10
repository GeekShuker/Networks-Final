import os
import pandas as pd
import hashlib
from collections import Counter
from scapy.all import rdpcap
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
import joblib

def flow_hash(pkt):
    """
    Calculate a unique flow hash for a packet using the 4-tuple:
    (source IP, dest IP, source port, dest port).
    
    How it works:
    1. Checks if the packet contains IP layer and either TCP or UDP
    2. Constructs a flow identifier string combining the 4-tuple
    3. Uses SHA-256 hashing to create a unique, irreversible identifier
    4. Returns the hash as a hexadecimal string
    
    This is used to identify flows without exposing actual IP/port values.
    It simulates what an attacker could know about flow identifiers while
    maintaining privacy of the actual network endpoints.
    
    Parameters:
        pkt (scapy.Packet): A network packet from scapy
        
    Returns:
        str or None: SHA-256 hash of the flow 4-tuple, or None if not applicable
    """
    if 'IP' in pkt and ('TCP' in pkt or 'UDP' in pkt):
        # Create flow identifier from 4-tuple (src_ip-dst_ip-src_port-dst_port)
        flow_tuple = f"{pkt['IP'].src}-{pkt['IP'].dst}-{pkt.sport}-{pkt.dport}"
        # Use SHA-256 for hashing the flow tuple to anonymize actual IPs/ports
        return hashlib.sha256(flow_tuple.encode()).hexdigest()
    return None

def extract_pcap_features(pcap_path, use_flow=True):
    """
    Extract features from a PCAP file for classification.
    
    How it works:
    1. Loads all packets from the PCAP file using scapy
    2. Extracts packet sizes and timestamps for all packets
    3. If use_flow=True, calculates flow hashes for flow-aware analysis
    4. Computes statistical features:
       - Mean packet size (average bytes per packet)
       - Mean interarrival time (average time between consecutive packets)
       - Most common flow hash (converted to integer for ML model)
    
    This simulates two attack scenarios:
    - Flow-aware attacker: knows packet metadata + flow identifiers
    - Flow-unaware attacker: knows only packet metadata (size, timing)
    
    Parameters:
        pcap_path (str): Path to the PCAP file to analyze
        use_flow (bool): Whether to include flow hash features
        
    Returns:
        list: Feature vector [mean_size, mean_time_diff, flow_hash] or [mean_size, mean_time_diff]
    """
    # Load all packets from the PCAP file
    packets = rdpcap(pcap_path)
    # Extract packet sizes (in bytes)
    sizes = [len(pkt) for pkt in packets]
    # Extract packet timestamps
    times = [pkt.time for pkt in packets]

    # Calculate flow hashes if requested (for flow-aware attacker)
    flow_hashes = [flow_hash(pkt) for pkt in packets if flow_hash(pkt)] if use_flow else []

    # Calculate feature: average packet size
    mean_size = sum(sizes) / len(sizes) if sizes else 0
    # Calculate feature: average interarrival time between consecutive packets
    mean_time_diff = sum([t - s for s, t in zip(times[:-1], times[1:])]) / len(times[:-1]) if len(times) > 1 else 0
    # Use the most common flow hash (as integer) if present
    common_flow_hash = int(Counter(flow_hashes).most_common(1)[0][0][:8], 16) if flow_hashes else 0

    # Return features with or without flow hash depending on attacker type
    return [mean_size, mean_time_diff, common_flow_hash] if use_flow else [mean_size, mean_time_diff]

def define_label(filename):
    """
    Map file name prefixes to application labels.
    
    How it works:
    1. Converts filename to lowercase for consistent matching
    2. Checks filename prefixes to determine the application
    3. Returns standardized application name
    
    This lets the script auto-label files for supervised learning based on
    a naming convention where each file starts with app identifier.
    
    Supported applications:
    - 'ch*' → Chrome
    - 'ed*' → Edge  
    - 'yo*' → YouTube
    - 'zo*' → Zoom
    - 's*' → Spotify
    
    Parameters:
        filename (str): Name of the PCAP file
        
    Returns:
        str: Application label or 'Unknown' if no match
    """
    # Convert to lowercase for case-insensitive matching
    name = filename.lower()
    # Map filename prefixes to application labels
    if name.startswith('ch'):
        return 'Chrome'
    elif name.startswith('ed'):
        return 'Edge'
    elif name.startswith('yo'):
        return 'YouTube'
    elif name.startswith('zo'):
        return 'Zoom'
    elif name.startswith('s'):
        return 'Spotify'
    else:
        return 'Unknown'

def generate_csv_and_train(training_dir):
    """
    Extract features from all PCAP files in the training directory,
    write two CSV files (with and without flow hash),
    and train two RandomForest models.
    
    How it works:
    1. Iterates through all PCAP files in the training directory
    2. Extracts features for both attack scenarios (flow-aware and flow-unaware)
    3. Auto-labels files based on filename prefixes
    4. Creates two datasets and saves them as CSV files
    5. Trains two separate Random Forest classifiers:
       - Full model: uses packet metadata + flow hashes (flow-aware attacker)
       - Partial model: uses only packet metadata (flow-unaware attacker)
    6. Applies feature scaling using MinMaxScaler for better ML performance
    7. Saves trained models and scalers for later prediction
    
    This simulates the two attack scenarios mentioned in the assignment:
    - Attacker with flow ID knowledge
    - Attacker with only packet size and timing knowledge
    
    Parameters:
        training_dir (str): Directory containing training PCAP files
    """
    data_full, data_partial = [], []

    # Iterate over each PCAP in the directory
    for file in os.listdir(training_dir):
        if file.endswith(".pcapng"):
            # Extract features with and without flow info for comparison
            full_features = extract_pcap_features(os.path.join(training_dir, file), use_flow=True)
            partial_features = extract_pcap_features(os.path.join(training_dir, file), use_flow=False)
            # Auto-label based on filename
            label = define_label(file)

            # Store feature vectors with labels
            data_full.append(full_features + [label])
            data_partial.append(partial_features + [label])

    # Create pandas DataFrames for both attack models
    df_full = pd.DataFrame(data_full, columns=['MeanPacketSize', 'MeanInterarrivalTime', 'FlowHash', 'Label'])
    df_partial = pd.DataFrame(data_partial, columns=['MeanPacketSize', 'MeanInterarrivalTime', 'Label'])

    # Save to CSV for later analysis or visualization
    df_full.to_csv('train_flowid.csv', index=False)
    df_partial.to_csv('train2_table.csv', index=False)

    # Remove samples without a recognized label (Unknown) to ensure clean training
    df_full = df_full[df_full['Label'] != 'Unknown']
    df_partial = df_partial[df_partial['Label'] != 'Unknown']

    # Split features/labels for training
    X_full, y_full = df_full[['MeanPacketSize', 'MeanInterarrivalTime', 'FlowHash']], df_full['Label']
    X_partial, y_partial = df_partial[['MeanPacketSize', 'MeanInterarrivalTime']], df_partial['Label']

    # Normalize features using MinMaxScaler to ensure all features are on similar scales
    scaler_full = MinMaxScaler()
    scaler_partial = MinMaxScaler()
    X_full_scaled = scaler_full.fit_transform(X_full)
    X_partial_scaled = scaler_partial.fit_transform(X_partial)

    # Train Random Forest classifiers for both models
    model_full = RandomForestClassifier(n_estimators=100, random_state=42)
    model_partial = RandomForestClassifier(n_estimators=100, random_state=42)

    # Fit models on scaled training data
    model_full.fit(X_full_scaled, y_full)
    model_partial.fit(X_partial_scaled, y_partial)

    # Save trained models and scalers for prediction
    joblib.dump(model_full, 'network_classifier_full.pkl')
    joblib.dump(scaler_full, 'scaler_full.pkl')
    joblib.dump(model_partial, 'network_classifier_partial.pkl')
    joblib.dump(scaler_partial, 'scaler_partial.pkl')

    print("✔️ CSVs created and RandomForest models trained.")

# Example usage:
generate_csv_and_train('training_pcaps')
