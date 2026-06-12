import pandas as pd
import xgboost as xgb
from sklearn.model_selection import cross_val_score

print("Loading dataset...")
df = pd.read_csv('final_ml_dataset.csv')
X = df.drop(columns=['Src_IP', 'Dst_IP', 'Label'], errors='ignore')
y = df['Label']

print("\n--- 1. FEATURE IMPORTANCE AUDIT ---")
# Load the model you just trained
model = xgb.XGBClassifier()
model.load_model('tcp_tracker_xgboost.json')

# Get feature importance scores
importance = model.feature_importances_
feature_names = X.columns

# Display the scores
print("How much the model relied on each feature:")
for name, score in zip(feature_names, importance):
    print(f"> {name}: {score * 100:.2f}%")

print("\n--- 2. K-FOLD CROSS VALIDATION ---")
print("Testing the model across 5 different data splits...")
# This splits the data 5 times, trains 5 models, and tests on 5 different holdout sets
cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')

print(f"Accuracy across the 5 tests: {[f'{score * 100:.2f}%' for score in cv_scores]}")
print(f"Average Robust Accuracy: {cv_scores.mean() * 100:.2f}%\n")