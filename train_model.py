import pandas as pd
from sklearn.model_selection import train_test_split
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Loading the CIC-IDS2017 benchmark dataset...")
df = pd.read_csv('cicids2017_cleaned.csv')


df.columns = df.columns.str.strip()

ideal_features = [
    'Destination Port', 
    'Flow Duration', 
    'Fwd PSH Flags', 
    'Bwd PSH Flags',
    'SYN Flag Count',
    'ACK Flag Count',
    'PSH Flag Count',
    'Fwd Packets/s', 
    'Bwd Packets/s',
    'Flow Packets/s'
]


selected_features = [col for col in ideal_features if col in df.columns]

print(f"\nSuccessfully mapped {len(selected_features)} features:")
for f in selected_features:
    print(f" -> {f}")

X = df[selected_features]
y = (df['Attack Type'] != 'Normal Traffic').astype(int)

print("\nSplitting data into training (80%) and testing (20%) sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Initializing and training the robust XGBoost model...")
model = xgb.XGBClassifier(eval_metric='logloss', random_state=42) 
model.fit(X_train, y_train)

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_score, recall_score

print("Model trained! Running probability predictions...")

y_proba = model.predict_proba(X_test)[:, 1]


strict_threshold = 0.95 
y_pred_strict = (y_proba >= strict_threshold).astype(int)

# --- EVALUATION ---
print(f"\n=== HIGH-PRECISION RESULTS (Threshold: {strict_threshold}) ===")

# Calculate the specific metrics
precision = precision_score(y_test, y_pred_strict)
recall = recall_score(y_test, y_pred_strict)

print(f"Precision (Trustworthiness): {precision * 100:.2f}%")
print(f"Recall (Catch Rate):         {recall * 100:.2f}%\n")

print("Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred_strict)
print(cm)

print(f"\nFalse Positives (Innocent users blocked): {cm[0][1]}")
print(f"False Negatives (Attacks missed):         {cm[1][0]}")

model.save_model('tcp_tracker_high_precision.json')
print("\nModel saved successfully as 'tcp_tracker_high_precision.json'")