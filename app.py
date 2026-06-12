import asyncio
import threading
import time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import xgboost as xgb
from scapy.all import sniff, IP, TCP

app = FastAPI(title="TCPTracker Real-Time NIDS API")

# Enable CORS so your React frontend (running on Vercel or localhost) can securely connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global tracking elements
STRICT_THRESHOLD = 0.95
active_flows = {}
connected_clients = set()

# Thread-safe event loop and queue to pass alerts from the Scapy thread to the FastAPI async loop
async_loop = None
alert_queue = None

print("🧠 Loading High-Precision XGBoost Classifier...")
model = xgb.XGBClassifier()
model.load_model('tcp_tracker_high_precision.json')


def packet_sniffer_loop(loop):
    """Runs in a dedicated background thread to sniff traffic continuously."""
    def process_packet(packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            connection_id = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))
            current_time = time.time()
            
            if connection_id not in active_flows:
                active_flows[connection_id] = {
                    'start_time': current_time,
                    'fwd_packets': 0,
                    'bwd_packets': 0,
                    'ack_count': 0,
                    'psh_count': 0,
                    'initiator': src_ip
                }
            
            flow = active_flows[connection_id]
            
            if src_ip == flow['initiator']:
                flow['fwd_packets'] += 1
            else:
                flow['bwd_packets'] += 1
                
            if 'A' in flags: flow['ack_count'] += 1
            if 'P' in flags: flow['psh_count'] += 1
            
            duration = max(current_time - flow['start_time'], 0.0001) 
            total_packets = flow['fwd_packets'] + flow['bwd_packets']
            
            # Map features for the ML model
            live_features = pd.DataFrame([{
                'Destination Port': dst_port,
                'Flow Duration': duration,
                'ACK Flag Count': flow['ack_count'],
                'PSH Flag Count': flow['psh_count'],
                'Fwd Packets/s': flow['fwd_packets'] / duration,
                'Bwd Packets/s': flow['bwd_packets'] / duration,
                'Flow Packets/s': total_packets / duration
            }])
            
            risk_score = float(model.predict_proba(live_features)[0][1])
            
            # If an anomaly is hit, build payload and queue it for websocket delivery
            if risk_score >= STRICT_THRESHOLD:
                alert_payload = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "attacker_ip": src_ip,
                    "target_port": dst_port,
                    "confidence": round(risk_score * 100, 2),
                    "packets_per_sec": round(total_packets / duration, 2),
                    "status": "BLOCKED"
                }
                # Safely pass data from synchronous background thread into async event loop
                loop.call_soon_threadsafe(alert_queue.put_nowait, alert_payload)

    # Scapy Sniffer initialization (store=0 ensures memory doesn't leak over days of tracking)
    sniff(prn=process_packet, store=False)


@app.on_event("startup")
async def startup_event():
    """Initializes the background thread pool when the FastAPI server boots up."""
    global async_loop, alert_queue
    async_loop = asyncio.get_event_loop()
    alert_queue = asyncio.Queue()
    
    # Spin up the background sniffer engine
    sniffer_thread = threading.Thread(target=packet_sniffer_loop, args=(async_loop,), daemon=True)
    sniffer_thread.start()
    
    # Run the broadcast manager as a background task within FastAPI
    asyncio.create_task(broadcast_alert_manager())
    print("🛡️ Live Sniffer Core successfully detached to background thread.")


async def broadcast_alert_manager():
    """Monitors the internal queue and pushes live alerts to all connected UI clients."""
    while True:
        alert = await alert_queue.get()
        if connected_clients:
            # Broadcast to every open dashboard interface
            disconnected = set()
            for websocket in connected_clients:
                try:
                    await websocket.send_json(alert)
                except Exception:
                    disconnected.add(websocket)
            
            connected_clients.difference_update(disconnected)
        alert_queue.task_done()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Manages continuous active stateful pipelines to client UI dashboards."""
    await websocket.accept()
    connected_clients.add(websocket)
    print(f"🔌 UI Client Connected. Active Monitors: {len(connected_clients)}")
    try:
        while True:
            # Keep the socket open and listen for ping/pong signals
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        print(f"❌ UI Client Disconnected. Active Monitors: {len(connected_clients)}")