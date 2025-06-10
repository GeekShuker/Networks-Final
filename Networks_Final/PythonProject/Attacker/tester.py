import joblib
import pandas as pd
import os
from scapy.all import rdpcap
import hashlib
from collections import Counter

def flow_hash(pkt):
    """
    Compute a unique hash for the flow a packet belongs to,
    based on (source IP, destination IP, source port, destination port).
    
    How it works:
    1. Extracts the IP layer and transport layer (TCP/UDP) from packet
    2. Creates a flow identifier string from the 4-tuple
    3. Uses SHA-256 to generate a consistent, anonymized flow identifier
    4. Returns the hexadecimal hash string
    
    This helps group packets into flows without exposing real IP addresses.
    It simulates what an attacker could derive from network metadata while
    preserving privacy of actual endpoints.
    
    Parameters:
        pkt (scapy.Packet): Network packet from scapy
        
    Returns:
        str or None: SHA-256 hash of flow 4-tuple, or None if packet lacks required layers
    """
    if 'IP' in pkt and ('TCP' in pkt or 'UDP' in pkt):
        # Construct flow identifier from 4-tuple
        flow_tuple = f"{pkt['IP'].src}-{pkt['IP'].dst}-{pkt.sport}-{pkt.dport}"
        # Generate consistent hash for this flow
        return hashlib.sha256(flow_tuple.encode()).hexdigest()
    return None

def extract_pcap_features(pcap_path, use_flow=True):
    """
    Extract statistical features from a PCAP file for application classification.
    
    How it works:
    1. Loads the entire PCAP file using scapy's rdpcap function
    2. Iterates through all packets to extract sizes and timestamps
    3. If use_flow=True, computes flow hashes for each packet
    4. Calculates key statistical features:
       - Mean packet size: average bytes per packet
       - Mean interarrival time: average time gap between consecutive packets
       - Most common flow hash: dominant flow converted to integer
    5. Returns feature vector for machine learning model
    
    This enables comparison between flow-aware and flow-unaware attackers:
    - Flow-aware: has access to flow identifiers + packet metadata
    - Flow-unaware: has access only to packet sizes and timing
    
    Parameters:
        pcap_path (str): Path to PCAP file to analyze
        use_flow (bool): Whether to include flow hash in feature extraction
        
    Returns:
        list: Feature vector for ML prediction [mean_size, mean_time_diff, flow_hash?]
    """
    # Load all packets from the PCAP file
    packets = rdpcap(pcap_path)
    # Extract packet sizes in bytes
    sizes = [len(pkt) for pkt in packets]
    # Extract packet timestamps
    times = [pkt.time for pkt in packets]

    # For flow-aware mode, get the hash for each packet's flow
    flow_hashes = [flow_hash(pkt) for pkt in packets if flow_hash(pkt)] if use_flow else []

    # Calculate mean packet size
    mean_size = sum(sizes) / len(sizes) if sizes else 0
    # Calculate mean interarrival time between consecutive packets
    mean_time_diff = sum([t - s for s, t in zip(times[:-1], times[1:])]) / len(times[:-1]) if len(times) > 1 else 0
    # Use the most common flow hash (as integer) if present, else zero
    common_flow_hash = int(Counter(flow_hashes).most_common(1)[0][0][:8], 16) if flow_hashes else 0

    # Return the selected features based on attacker capability
    return [mean_size, mean_time_diff, common_flow_hash] if use_flow else [mean_size, mean_time_diff]

def define_label(filename):
    """
    Assign a label (app name) based on file name prefix.
    
    How it works:
    1. Converts filename to lowercase for consistent pattern matching
    2. Checks predefined prefixes to identify the application
    3. Returns the corresponding application name
    
    This is used to determine the ground truth for evaluation by assuming
    a consistent naming convention for test files.
    
    Supported applications and their prefixes:
    - 'ch*' → Chrome browser
    - 'ed*' → Microsoft Edge
    - 'yo*' → YouTube
    - 'zo*' → Zoom
    - 's*' → Spotify
    
    Parameters:
        filename (str): Name of the PCAP file
        
    Returns:
        str: Application name or 'Unknown' if no prefix matches
    """
    # Convert to lowercase for case-insensitive matching
    name = filename.lower()
    # Match filename prefixes to application labels
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

def predict_and_log(pcap_path, log_path='prediction_log.csv'):
    """
    Predict the application for a PCAP using two models and log results.
    
    How it works:
    1. Loads both pre-trained models and their corresponding scalers
    2. Extracts features for both attack scenarios from the test PCAP
    3. Applies the same feature scaling used during training
    4. Makes predictions using both models:
       - Full model: simulates flow-aware attacker
       - Partial model: simulates flow-unaware attacker
    5. Determines ground truth from filename
    6. Logs all results to CSV for analysis
    7. Prints predictions for immediate feedback
    
    This enables direct comparison of attack effectiveness between:
    - Attacker with flow information access
    - Attacker with only timing and size information
    
    Parameters:
        pcap_path (str): Path to the PCAP file to classify
        log_path (str): Path to CSV log file for results
    """
    # Load trained models and scalers from disk
    model_full = joblib.load('network_classifier_full.pkl')
    scaler_full = joblib.load('scaler_full.pkl')
    model_partial = joblib.load('network_classifier_partial.pkl')
    scaler_partial = joblib.load('scaler_partial.pkl')

    # Extract features for both attacker types
    features_full = extract_pcap_features(pcap_path, use_flow=True)
    features_partial = extract_pcap_features(pcap_path, use_flow=False)

    # Scale features to match model training (critical for ML performance)
    scaled_full = scaler_full.transform(
        pd.DataFrame([features_full], columns=['MeanPacketSize', 'MeanInterarrivalTime', 'FlowHash']))
    scaled_partial = scaler_partial.transform(
        pd.DataFrame([features_partial], columns=['MeanPacketSize', 'MeanInterarrivalTime']))

    # Predict app label using both models
    prediction_full = model_full.predict(scaled_full)[0]
    prediction_partial = model_partial.predict(scaled_partial)[0]
    # Determine ground truth from filename
    true_label = define_label(os.path.basename(pcap_path))

    # Log results to a CSV file (append if exists, else write header)
    log_exists = os.path.exists(log_path)
    with open(log_path, 'a') as f:
        if not log_exists:
            # Write CSV header on first run
            f.write('filename,true_label,full_prediction,partial_prediction\n')
        # Append prediction results
        f.write(f"{os.path.basename(pcap_path)},{true_label},{prediction_full},{prediction_partial}\n")

    # Print results for immediate feedback
    print(f"Full Prediction: {prediction_full}")
    print(f"Partial Prediction: {prediction_partial}")

# Example usage: loop over PCAP files in folder and log predictions for each
folder = 'prediction_files'
for file in os.listdir(folder):
    if file.endswith('.pcapng'):
        predict_and_log(os.path.join(folder, file))
