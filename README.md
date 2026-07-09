# 🛡️ AI-Based Intrusion Detection & Prevention System (AI-IDPS)

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)
![Flask](https://img.shields.io/badge/Flask-Backend-black.svg)
![React](https://img.shields.io/badge/React-Frontend-61DAFB.svg)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-green.svg)
![License](https://img.shields.io/badge/License-MIT-success.svg)

An **AI-powered Intrusion Detection and Prevention System (AI-IDPS)** that captures live network traffic, extracts flow-based network features, detects malicious activity using a Deep Learning model, and automatically blocks attackers through the Windows Firewall.

The system provides **real-time network monitoring**, **AI-based threat detection**, **automatic prevention**, and a **web dashboard** for monitoring alerts, system performance, and prevention actions.

---

# 🚀 Features

- 🔍 Real-time network packet capture
- 📂 Offline PCAP analysis
- 🧠 Deep Learning-based attack detection
- 📊 Flow-based feature extraction
- ⚡ Batch inference for high-speed traffic
- 🧵 Multi-threaded architecture
- 🛡 Automatic IP blocking
- 🔥 Windows Firewall integration
- 📈 Live monitoring dashboard
- 📋 Attack logging
- 📁 Prevention logging
- ⚙ Configurable prevention settings
- 📡 REST API using Flask
- 💻 React + Vite frontend
- 📊 System resource monitoring
- 📈 Network bandwidth monitoring
- ⏱ Automatic unblock after configurable duration

---

# 🏗 System Architecture

```
                Network Traffic
                       │
                       ▼
            Packet Capture (Scapy)
                       │
                       ▼
               Packet Queue
                       │
                       ▼
          Flow Aggregation Engine
                       │
                       ▼
        Statistical Feature Extraction
                       │
                       ▼
             StandardScaler
                       │
                       ▼
        TensorFlow Deep Learning Model
                       │
          ┌────────────┴─────────────┐
          ▼                          ▼
      BENIGN                     ATTACK
                                     │
                                     ▼
                    Confidence > Threshold?
                                     │
                          Yes ─────────►
                                     │
                                     ▼
                      Windows Firewall Block
                                     │
                                     ▼
                   Log + Dashboard Notification
```

---

# 💡 Project Overview

Traditional intrusion detection systems rely on predefined signatures and rules, making them less effective against evolving cyber threats.

This project uses **Artificial Intelligence** to identify malicious traffic patterns by analyzing network flows in real time.

Instead of examining every packet individually, packets are aggregated into network flows, statistical features are extracted, and a trained Deep Learning model classifies each flow as either:

- BENIGN
- ATTACK

If the prediction confidence exceeds the configured threshold, the attacker IP is automatically blocked using the Windows Firewall.

---

# 🛠 Tech Stack

## Backend

- Python
- Flask
- Flask-CORS
- TensorFlow / Keras
- Scikit-learn
- Scapy
- NumPy
- Pandas
- Joblib
- psutil
- threading

## Frontend

- React
- Vite
- JavaScript
- HTML
- CSS

## Security

- Windows Firewall
- Network Traffic Analysis
- Flow-based Intrusion Detection

---

# 📂 Project Structure

```
AI-IDPS/
│
├── backend/
│   ├── capture_heavy.py
│   ├── server.py
│   ├── prevention_settings.json
│   ├── predictions_log.csv
│   ├── prevention_actions.csv
│   ├── prevention_log.csv
│   └── models/
│       ├── dl_model4.keras
│       └── dl_scaler4.joblib
│       └── tensorflow_model.ipynb
|
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│   
│
├── README.md
└── requirements.txt
```

---

# 🧠 Deep Learning Model

The intrusion detection model is implemented using **TensorFlow/Keras**.

## Architecture

```
Input Layer
      │
      ▼
Dense (128, ReLU)
      │
Dropout (0.3)
      │
Dense (64, ReLU)
      │
Dropout (0.3)
      │
Dense (1, Sigmoid)
      │
Prediction
```

## Model Features

- Binary Classification
- Adam Optimizer
- Binary Crossentropy Loss
- StandardScaler preprocessing
- Early Stopping
- Dropout Regularization
- Sigmoid Output Layer

---

# 📊 Dataset

The model is trained using the **CICIDS2017** dataset.

Attack categories include:

- DDoS
- DoS
- Port Scan
- Botnet
- Brute Force
- Web Attacks
- Heartbleed
- Infiltration

All attack classes are merged into a single **ATTACK** class for binary classification.

---

# 📈 Feature Engineering

The system extracts more than **80 network flow features**, including:

- Source Port
- Destination Port
- Protocol
- Flow Duration
- Total Forward Packets
- Total Backward Packets
- Packet Length Statistics
- Flow Bytes/s
- Flow Packets/s
- Flow IAT Statistics
- Forward IAT
- Backward IAT
- TCP Flags
- Header Length
- Average Packet Size
- Bulk Statistics
- Initial Window Size
- Active Time
- Idle Time
- Down/Up Ratio

---

# ⚡ Detection Pipeline

```
Packet Capture
      │
      ▼
Packet Normalization
      │
      ▼
Flow Aggregation
      │
      ▼
Feature Extraction
      │
      ▼
StandardScaler
      │
      ▼
TensorFlow Model
      │
      ▼
Prediction
      │
      ▼
Auto Prevention
```

---

# 🛡 Intrusion Prevention

When an attack is detected:

1. AI predicts ATTACK
2. Confidence is compared against the configured threshold
3. Source IP is blocked using Windows Firewall
4. Prevention action is logged
5. Dashboard is updated
6. Firewall rule is automatically removed after the configured duration

---

# 🌐 Backend API

## Monitoring

| Method | Endpoint | Description |
|---------|----------|-------------|
| GET | /api/status | System statistics |
| GET | /api/alerts | Security alerts |
| POST | /api/start | Start monitoring |
| POST | /api/stop | Stop monitoring |

## Prevention

| Method | Endpoint |
|---------|----------|
| GET | /api/prevention/actions |
| POST | /api/prevention/block |
| POST | /api/prevention/unblock |
| GET | /api/prevention/settings |
| POST | /api/prevention/settings |

---

# 📊 Dashboard

The web dashboard provides:

- Live threat monitoring
- Detection history
- CPU usage
- Memory usage
- Temperature
- Network bandwidth
- Active connections
- Prevention actions
- Blocked IP management
- Prevention settings

---

# 🧵 Custom Data Structures

To improve performance under heavy traffic, custom data structures are implemented.

### Doubly Linked List

Maintains active network flows and efficiently removes expired flows.

### Hash Map

Provides O(1) flow lookup.

### Queue

Buffers captured packets before processing.

### Stack

Stores recent alerts.

---

# ⚙ Performance Optimizations

- Multi-threading
- Batch inference
- Flow timeout handling
- Bounded packet queue
- Drop-oldest strategy during bursts
- Efficient memory usage
- Feature alignment with trained scaler
- Asynchronous packet processing

---

# 📋 Logging

The system automatically maintains:

### predictions_log.csv

Contains:

- Timestamp
- Source IP
- Destination IP
- Ports
- Prediction
- Confidence
- Block Status

### prevention_actions.csv

Contains:

- Blocked IP
- Action
- Timestamp
- Duration
- Status
- Expiration Time

### prevention_log.csv

Stores firewall prevention history.

---

# ▶ Running the Project

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Start Backend

```bash
python server.py
```

## Start Live Monitoring

```bash
python capture_heavy.py \
--iface "YOUR_NETWORK_INTERFACE" \
--scaler models/dl_scaler4.joblib \
--model models/dl_model4.keras
```

## Analyze PCAP

```bash
python capture_heavy.py \
--pcap sample.pcap \
--scaler models/dl_scaler4.joblib \
--model models/dl_model4.keras
```

---

# 📌 Future Improvements

- Multi-class attack classification
- Explainable AI (XAI)
- Linux firewall support
- macOS firewall integration
- Docker deployment
- Kubernetes deployment
- Cloud-based monitoring
- SIEM integration
- Email & SMS alerts
- Threat intelligence feeds
- Database integration
- User authentication
- Role-based access control
- Real-time visualization
- Interactive attack graphs

---

# 🎯 Learning Outcomes

This project demonstrates practical knowledge of:

- Artificial Intelligence
- Deep Learning
- Machine Learning
- Cybersecurity
- Intrusion Detection Systems
- Intrusion Prevention Systems
- Network Security
- Packet Analysis
- Feature Engineering
- Multi-threading
- REST APIs
- Backend Development
- Firewall Automation
- Real-Time Data Processing
- Data Structures
- Software Engineering

---

# 📄 License

This project is developed for educational and research purposes. Feel free to use, modify, and extend it with proper attribution.

---

# 👩‍💻 Author

**Muqadas Ilyas**

Software Engineering Student | AI & Full-Stack Developer

**Interests**

- Artificial Intelligence
- Cybersecurity
- Machine Learning
- Full-Stack Development
- Network Security
- Deep Learning

⭐ If you found this project helpful, consider giving it a **star** on GitHub!
