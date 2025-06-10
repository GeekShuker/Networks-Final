# Networks Final Project

A comprehensive network traffic analysis and classification system built for academic research and network security applications.
## REMARK:
## Due to a heavy amount of pcap files, we couldn't upload them directly to the repository, so we uploaded them into the following drive:
(https://drive.google.com/drive/folders/1sD26taJF0SN7WwlfZHkfTmrZnU0gUuhX?usp=sharing)
## Please make sure to bind the file into the following directory:

## Project Overview

This project consists of two main components that work together to analyze and classify network traffic patterns:

1. **Network Traffic Analysis** (`Analyze/`) - Analyzes and visualizes traffic characteristics from different applications
2. **Traffic Classification & Attack Detection** (`Attacker/`) - Machine learning-based classification and prediction system

## Project Structure

```
Networks_Final-main/
├── PythonProject/
│   ├── Analyze/           # Traffic analysis and visualization
│   │   ├── main.py
│   │   ├── unified_feature_extraction.py
│   │   ├── plotting_features.py
│   │   ├── wireshark_files/
│   │   └── README.md
│   └── Attacker/          # ML-based traffic classification
│       ├── trainer.py
│       ├── tester.py
│       ├── training_pcaps/
│       ├── prediction_files/
│       └── README_EN.md

```

## Components

### 🔍 Traffic Analysis (`Analyze/`)
- Processes Wireshark CSV exports from different applications
- Extracts statistical and behavioral network features
- Generates comparative visualizations between applications
- Supports analysis of web browsers, streaming services, and video conferencing

### 🤖 Traffic Classification (`Attacker/`)
- Machine learning pipeline for network traffic classification
- Trains models on PCAP files with feature extraction
- Provides prediction capabilities for new traffic samples
- Includes both flow-based and packet-based analysis methods

## Key Features

- **Multi-Application Analysis**: Compare traffic patterns across Chrome, Firefox, Spotify, YouTube, Zoom
- **Feature Extraction**: Advanced metrics including RTT, TCP flags, protocol distribution, QoS analysis
- **Visualization**: Comprehensive plotting suite for traffic characteristic comparison
- **Machine Learning**: Automated classification with trained models and scalers
- **Privacy-Preserving**: Analysis based on metadata only, no content inspection

## Requirements

- Python 3.x
- pandas, numpy, matplotlib
- scikit-learn (for classification component)
- Wireshark (for traffic capture)

## Use Cases

- Network behavior analysis and fingerprinting
- Application traffic pattern research
- Network security and anomaly detection
- Educational purposes for understanding network protocols
- Performance analysis of different applications



*This project was developed as part of a Networks course final assignment, focusing on practical network analysis and machine learning applications in cybersecurity.* 
