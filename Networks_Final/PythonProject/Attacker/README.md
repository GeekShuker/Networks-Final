# 🔍 Network Traffic Attack Simulation Tool

<div align="center">


*Simulating attackers attempting to identify applications from encrypted network traffic*

</div>

---

## 📋 Overview

This tool simulates an **attacker** trying to identify which applications a user accessed, even when the traffic is **fully encrypted**. It addresses **Part 4** of the assignment and examines two different attacker types with varying levels of information access.

## 🎯 Attack Scenarios

The tool examines **two distinct attack scenarios**:

| 🔐 **Flow-Aware Attacker** | 🕵️ **Flow-Unaware Attacker** |
|---------------------------|------------------------------|
| **Knows:** Packet size, timestamp, hash of 4-tuple flow ID | **Knows:** Only packet size and timestamp |
| **Access:** Flow identifiers available | **Access:** No flow identifier information |
| **Accuracy:** Generally higher | **Accuracy:** Generally lower |
| **Real-world:** ISP or network administrator | **Real-world:** Passive network observer |

## 🛠️ Project Structure

```
📂 Attacker/
├── 🎓 trainer.py                          # ML model training script
├── 🔬 tester.py                           # Prediction testing script
├── 📊 train_flowid.csv                    # Training data (with flow IDs)
├── 📊 train2_table.csv                    # Training data (without flow IDs)
├── 🤖 network_classifier_full.pkl         # Full model (with flow info)
├── 🤖 network_classifier_partial.pkl      # Partial model (without flow info)
├── ⚖️ scaler_full.pkl                     # Feature scaler for full model
├── ⚖️ scaler_partial.pkl                  # Feature scaler for partial model
├── 📝 prediction_log.csv                  # Prediction results log
├── 📂 training_pcaps/                     # PCAP files for training
└── 📂 prediction_files/                   # PCAP files for testing
```

## 🚀 How It Works

### 📝 Step 1: Feature Extraction
The tool extracts statistical features from PCAP files:

| 📊 **Feature** | 📋 **Description** | 🎯 **Purpose** |
|---------------|-------------------|----------------|
| **Mean Packet Size** | Average bytes per packet | Identify traffic patterns |
| **Mean Interarrival Time** | Average time between consecutive packets | Identify transmission frequency |
| **Common Flow Hash** | Most frequent flow identifier | Distinguish between connections |

### 🎓 Step 2: Model Training
1. **Data Loading**: Read PCAP files from training directory
2. **Auto-labeling**: Identify applications from filename prefixes
3. **Feature Extraction**: Create feature vectors for each file
4. **Model Training**: Train two Random Forest classifiers
5. **Model Saving**: Save models and scalers for future use

### 🔬 Step 3: Testing & Prediction
1. **Model Loading**: Load pre-trained models
2. **Feature Extraction**: From test PCAP files
3. **Prediction**: Using both models
4. **Logging**: Save results to CSV for analysis

## 🎯 Supported Applications

The tool identifies the following applications based on filename prefixes:

| 🏷️ **File Prefix** | 📱 **Application** | 📋 **Example** |
|-------------------|-------------------|---------------|
| `ch*` | Chrome | `chrome_session1.pcapng` |
| `ed*` | Edge | `edge_browsing.pcapng` |
| `yo*` | YouTube | `youtube_video.pcapng` |
| `zo*` | Zoom | `zoom_meeting.pcapng` |
| `s*` | Spotify | `spotify_music.pcapng` |

## 📊 Results & Metrics

### 📈 Prediction Log Format
The `prediction_log.csv` contains:

```csv
filename,true_label,full_prediction,partial_prediction
chrome_test.pcapng,Chrome,Chrome,Chrome
zoom_test.pcapng,Zoom,Zoom,Unknown
spotify_test.pcapng,Spotify,Spotify,Chrome
```

### 🔍 Analysis Results
- **Flow-Aware Attacker**: Generally higher accuracy (with flow information)
- **Flow-Unaware Attacker**: Lower accuracy (timing + size only)
- **Difficult Applications**: Those with similar traffic patterns



## 🎯 Results

| Model Type            | Accuracy |
| --------------------- | -------- |
| Flow-aware Attacker   | \~92%    |
| Flow-unaware Attacker | \~80%    |

* The biggest gaps were seen with apps like **Chrome** and **Spotify** due to variability.
* Apps like **Zoom** and **YouTube** were highly identifiable even without flow context.


## 💡 Research Insights

### ✅ Why Attackers Can Identify Applications

1. **Unique Traffic Patterns**: Each application has distinct characteristics
2. **Packet Size Distributions**: Different apps send packets of varying sizes
3. **Timing Patterns**: Transmission frequency varies between applications
4. **Flow Information**: Connection identifiers provide additional context

### ⚠️ Attack Limitations

1. **Network Noise**: Can affect prediction accuracy
2. **Similar Applications**: Difficult to distinguish between similar apps
3. **Network Conditions**: Latency can alter patterns
4. **Data Requirements**: Sufficient data needed for accurate prediction

## 🛡️ Possible Defenses

### 🔒 Mitigation Strategies Against This Attack:

| 🛡️ **Defense Method** | 📋 **Description** | ⚖️ **Trade-offs** |
|----------------------|-------------------|-------------------|
| **Traffic Padding** | Add dummy packets to obscure patterns | Increased bandwidth usage |
| **Traffic Shaping** | Normalize traffic patterns across apps | Potential performance impact |
| **Advanced VPN** | Hide metadata and timing information | Cost and complexity |
| **Tor/Onion Routing** | Mask source and destination | Significant latency increase |
| **Random Timing** | Randomize packet transmission patterns | May affect application performance |

## 🚀 Usage

### 📋 Requirements
```bash
pip install scapy scikit-learn pandas joblib numpy
```

### 🎓 Training Models
make sure that there are pcaps in training_pcap file and their names according to  the prefixes that explained (ch,ed...)
```python
# Run training
python trainer.py
```

### 🔬 Testing Predictions
make sure that there are pcaps in prediction_pcap file and their names according to  the prefixes that explained (ch,ed...)
```python
# Run predictions
python tester.py
```

## 📊 Example Output

```
🔍 Analyzing: test_chrome.pcapng
Full Prediction: Chrome
Partial Prediction: Chrome

🔍 Analyzing: test_zoom.pcapng  
Full Prediction: Zoom
Partial Prediction: Unknown

🔍 Analyzing: test_spotify.pcapng
Full Prediction: Spotify
Partial Prediction: Chrome
```

## 🎯 Key Findings

### 📈 Attack Effectiveness
1. **Flow-aware attackers** can identify applications with high accuracy
2. **Flow-unaware attackers** are less accurate but still pose a threat
3. **Encrypted traffic** doesn't prevent traffic analysis attacks
4. **Metadata patterns** reveal significant information about applications

### 🔬 Research Implications
- **Privacy concerns**: Even encrypted traffic can leak application usage
- **Defense necessity**: Proactive measures needed to prevent identification
- **Further research**: Required for developing effective countermeasures
- **Real-world relevance**: Applicable to actual network monitoring scenarios

## ⚙️ Technical Details

### 🧠 Machine Learning Approach
- **Algorithm**: Random Forest Classifier
- **Features**: Statistical packet metadata
- **Scaling**: MinMax normalization
- **Validation**: Filename-based ground truth

### 📊 Feature Engineering
- **Temporal features**: Inter-arrival time statistics
- **Size features**: Packet length distributions  
- **Flow features**: Connection-level identifiers
- **Anonymization**: SHA-256 hashing for privacy

## 📚 Academic Context

This tool demonstrates concepts from:
- **Network Security**: Traffic analysis attacks
- **Privacy Engineering**: Metadata leakage
- **Machine Learning**: Classification on network data
- **Cryptography**: Limitations of encryption

---

<div align="center">

**⚠️ This tool is intended for research and educational purposes only**

Created as part of an academic assignment on network security

**🔒 Use responsibly and ethically**

</div> 