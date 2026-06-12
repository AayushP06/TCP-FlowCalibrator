# TCPTracker 🛡️
**Real-Time High-Precision Network Intrusion Detection System (NIDS)**

TCPTracker is a lightweight, full-stack cybersecurity monitoring tool designed to detect network anomalies, specifically TCP SYN floods and DoS attacks, in real time. It utilizes a highly tuned XGBoost machine learning model coupled with a real-time Scapy packet sniffer, feeding into a clean, modern React dashboard via WebSockets.

---

## 🏗️ Architecture

The system follows a strict, decoupled SaaS-ready architecture designed for low latency and high precision:

### 1. The Inference Engine (Backend)
* **Packet Sniffing:** Uses `scapy` to continuously monitor network interfaces and extract real-time TCP flow metrics without heavy memory overhead.
* **Machine Learning:** Powered by an **XGBoost Classifier** trained on the CIC-IDS2017 enterprise benchmark dataset. The model operates on a strict 95% confidence threshold (0.95) to maximize precision and eliminate False Positives (alert fatigue).
* **Feature Extraction:** Extracts 7 specific velocity and protocol features on the fly (ignoring payload size to prevent shortcut learning):
    * `Destination Port`
    * `Flow Duration`
    * `ACK / PSH Flag Counts`
    * `Fwd / Bwd / Total Packets per Second`
* **Live Broadcast:** A **FastAPI** asynchronous server pushes verified threat signatures through a native WebSocket pipeline.

### 2. The Telemetry Dashboard (Frontend)
* **Tech Stack:** React.js, Vite, and Tailwind CSS.
* **Design Philosophy:** A high-density, minimal dark-theme interface built for Security Operations Centers (SOC). No clutter, just raw operational data.
* **Live State:** Instantly reflects incoming WebSocket payloads, updating attack logs, packet velocity, and mitigated threat counts natively in the browser.

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.9+
* Node.js (for the frontend)
* Wireshark / npcap (for Windows network adapter hooking)

### Backend Initialization (Requires Administrator / Root)
1. Clone the repository and navigate to the root folder.
2. Activate your virtual environment and install dependencies:
   ```bash
   pip install pandas xgboost scapy fastapi uvicorn


📂 Repository Structure

TCPTracker/
├── app.py                            # FastAPI & Scapy live-sniffer backend
├── tcp_tracker_high_precision.json   # Trained XGBoost NIDS weights
├── train_model.py                    # ML Pipeline for retraining
├── evaluate_model.py                 # Cross-validation & auditing scripts
├── tcptracker-ui/                    # React frontend application
│   ├── src/App.jsx                   # Main WebSocket Dashboard logic
│   ├── src/index.css                 # Tailwind directives
│   └── package.json                  
└── README.md
