import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 1. Load Data and Prepare the Dataset
print("Loading attack data...")
attack_df = pd.read_csv("network_features.csv")
# Take a sample so it doesn't consume all your RAM
attack_df = attack_df.sample(n=100000, random_state=42) 
attack_df['Label'] = 1 # 1 = Malicious

print("Generating synthetic benign data for baseline...")
# Simulating normal HTTP traffic (Payloads vary, SYN/ACK are standard)
benign_df = pd.DataFrame({
    'Src_IP': '192.168.1.100', 'Dst_IP': '192.168.1.1',
    'Src_Port': np.random.randint(1024, 65535, 100000),
    'Dst_Port': 80,
    'Payload_Size': np.random.randint(100, 1500, 100000),
    'SYN_Flag': np.random.choice([0, 1], 100000, p=[0.9, 0.1]),
    'ACK_Flag': 1 # Normal traffic usually has ACK set
})
benign_df['Label'] = 0 # 0 = Benign

# Combine and shuffle
df = pd.concat([attack_df, benign_df]).sample(frac=1, random_state=42).reset_index(drop=True)

# Features to train on (Ignoring IPs for this basic model)
features = ['Src_Port', 'Dst_Port', 'Payload_Size', 'SYN_Flag', 'ACK_Flag']
X = df[features]
y = df['Label']

# 2. Split into Train (60%), Calibration (20%), and Test (20%)
X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train, X_calib, y_train, y_calib = train_test_split(X_temp, y_temp, test_size=0.25, random_state=42)

# 3. Train the XGBoost Classifier
print("Training XGBoost Classifier...")
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X_train, y_train)

# 4. CONFORMAL PREDICTION (The Magic)
print("Calibrating the Conformal Wrapper...")
# Get probabilities for the calibration set
calib_probs = model.predict_proba(X_calib)

# Calculate non-conformity scores (1 - probability of the TRUE class)
n_calib = len(y_calib)
true_class_probs = calib_probs[np.arange(n_calib), y_calib.values]
non_conformity_scores = 1 - true_class_probs

# Set confidence level (alpha). alpha=0.05 means 95% confidence.
alpha = 0.05
q_level = np.ceil((n_calib + 1) * (1 - alpha)) / n_calib
q_hat = np.quantile(non_conformity_scores, q_level)

# 5. Test the Model and Generate Sets
print("\n--- Conformal Prediction Results on Test Set ---")
test_probs = model.predict_proba(X_test)

# A prediction is included in the set if (1 - prob) <= q_hat
prediction_sets = (1 - test_probs) <= q_hat

classes = np.array(['Benign', 'Malicious'])
uncertain_count = 0

for i in range(10): # Let's look at the first 10 packets
    # Extract the labels where the boolean matrix is True
    pred_set = classes[prediction_sets[i]]
    actual_label = classes[y_test.values[i]]
    
    print(f"Packet {i+1} -> Actual: {actual_label} | Prediction Set: {list(pred_set)}")
    if len(pred_set) > 1:
        uncertain_count += 1

print(f"\nTotal packets flagged for Human Review (Set size > 1) in first 10: {uncertain_count}")
