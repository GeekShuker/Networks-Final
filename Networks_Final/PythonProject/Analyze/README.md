# 🌐 Network Traffic Analysis Tool

<div align="center">

*Analyze encrypted network traffic patterns using Wireshark data*

</div>

---

## 📋 Overview

This sophisticated tool analyzes network traffic captured from **Wireshark** to identify patterns and characteristics of different applications, even when the traffic is **encrypted**. It provides both statistical analysis and beautiful visualizations to help understand application behavior.

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Traffic Analysis** | Extracts statistical features from Wireshark CSV exports |
| 🔐 **Behavioral Fingerprinting** | Identifies unique patterns in encrypted application traffic |
| 📊 **Rich Visualizations** | Creates comparative charts for different network metrics |
| 🌐 **Protocol Analysis** | Examines TCP flags, connection patterns, and protocol usage |
| ⚡ **Flow Analysis** | Studies traffic patterns in the first 10 seconds of connections |

## 🛠️ Requirements

### 🐍 Python Environment
```
Python 3.8+
├── pandas     (Data manipulation)
├── numpy      (Numerical computations)
├── matplotlib (Data visualization)
└── collections (Built-in)
```

### 💻 System Requirements
- **Wireshark** installed for packet capture
- **Disk Space**: Sufficient for packet captures
- **Memory**: Minimum 4GB RAM recommended
- **OS**: Windows, Linux, or macOS

## 📦 Installation

### Step 1: Python Setup
```bash
# Check Python version
python --version

# Install required packages
pip install pandas numpy matplotlib
```

### Step 2: Wireshark Setup
Download and install from [🦈 wireshark.org](https://www.wireshark.org/)

---

## 📁 Project Structure

```
📂 Analyze/
├── 🐍 main.py                         # Main analysis script
├── 🔧 unified_feature_extraction.py   # Feature extraction functions
├── 📊 plotting_features.py            # Visualization functions
├── 📄 README.md                       # Hebrew documentation
├── 📄 README_EN.md                    # English documentation
└── 📂 wireshark_files/               # CSV exports directory
```

## 🚀 Usage Guide

### 📝 Step 1: Data Preparation
1. **🎯 Capture Traffic** using Wireshark
2. **💾 Export as CSV**: `File → Export Packet Dissections → As CSV`
3. **📁 Place File** in the `wireshark_files` directory

#### 📋 Required CSV Columns
The exported CSV file must contain the following columns for proper analysis:

| Column Name | Description | Example Values |
|-------------|-------------|----------------|
| `Time` | Packet timestamp | 0.000000, 0.001234, ... |
| `Source` | Source IP address | 192.168.1.100, 10.0.0.1 |
| `Destination` | Destination IP address | 172.217.164.142, 10.0.0.1 |
| `Protocol` | Network protocol | TCP, UDP, HTTP, TLS |
| `Length` | Packet size in bytes | 54, 1514, 74 |
| `Info` | Packet information | [SYN] Seq=0, [ACK] Seq=1 |
| `Destination Port` | Target port number | 80, 443, 8080 |

> **⚠️ Important**: Make sure to select all necessary fields when exporting from Wireshark to CSV format.

### 🔬 Step 2: Analysis Types

<table>
<tr>
<td width="50%">

#### 📈 Basic Traffic Statistics
- 📦 Packet counts
- 🌊 Flow sizes  
- 🔗 Protocol distribution

#### 🔄 Connection Analysis
- 🏳️ TCP flag patterns
- 📡 Connection events
- 🔄 Retransmission rates

</td>
<td width="50%">

#### 🗺️ Network Topology
- 🌐 Unique IP addresses
- 🔀 Flow patterns
- 📡 Broadcast/multicast usage

#### 📱 Application Behavior
- 🚀 Initial connection patterns
- 💥 Traffic burstiness
- 🎯 Protocol preferences

</td>
</tr>
</table>

## 📊 Output & Visualizations

The tool generates comprehensive visualizations comparing different applications:

### 🎯 Available Plots

| Plot Type | Description | What It Shows |
|-----------|-------------|---------------|
| 📊 **Flow Size (10s)** | Number of packets in first 10 seconds | Initial connection behavior |
| 📈 **Flow Volume (10s)** | Total bytes in first 10 seconds | Bandwidth requirements |
| 🌐 **Unique IPs & Flows** | Source/destination IP statistics | Network topology patterns |
| 📡 **Multicast Packets** | Multicast traffic analysis | Special protocol usage |
| 📢 **Broadcast Packets** | Broadcast traffic analysis | Network discovery patterns |
| 🏳️ **TCP Flags Distribution** | SYN, ACK, PSH, RST, FIN, URG counts | Connection state analysis |
| 🔄 **Connection Events** | Connection lifecycle events | Protocol behavior patterns |
| 🌍 **Protocol Distribution** | Network protocol usage | Application layer analysis |
| 🔗 **New Connections vs Retransmissions** | Connection reliability metrics | Network quality assessment |
| 🔄 **Repeated Packets** | Duplicate packet analysis | Network efficiency metrics |

### 📊 Visualization Examples

Each plot provides comparative analysis across multiple applications:

```
Example Output:
┌─────────────────────────────────────┐
│  Flow Size Comparison (10s)        │
├─────────────────────────────────────┤
│  ████████ Zoom      (120 packets)  │
│  ██████   Chrome    (85 packets)   │
│  ████     Spotify   (60 packets)   │
└─────────────────────────────────────┘
```

> **💡 Insight**: Different applications show distinct traffic patterns that can be used for identification and analysis.

## 💡 Tips & Best Practices

> **🎯 Pro Tips:**
> - Use clean, focused captures of single applications
> - Longer captures provide more reliable patterns
> - Some features may require specific Wireshark export settings

## ⚠️ Important Notes

| ⚠️ **Limitations** | 📌 **Details** |
|-------------------|----------------|
| Metadata Only | Analysis based on headers only (no payload inspection) |
| Network Dependency | Results may vary based on network conditions |
| Pattern Similarity | Some applications may use similar traffic patterns |

## 🤝 Contributing

We welcome contributions! Feel free to:
- 🐛 Submit bug reports
- 💡 Suggest new features
- 🔧 Submit pull requests
- 📖 Improve documentation

---

Made with ❤️ for network analysis

</div> 
