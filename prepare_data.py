import pandas as pd
from sklearn.utils import shuffle

print("Loading benign traffic...")
benign_df = pd.read_csv('benign_features.csv')
benign_count = len(benign_df)
print(f"Benign packets loaded: {benign_count}")

print("Loading attack traffic (this might take a minute due to the 1.2GB size)...")
attack_df = pd.read_csv('attack_features.csv')

print("Downsampling attack traffic...")
attack_df_sampled = attack_df.sample(n=(benign_count * 2), random_state=42)

print("Merging and shuffling datasets...")
final_df = pd.concat([benign_df, attack_df_sampled])
final_df = shuffle(final_df, random_state=42).reset_index(drop=True)
final_df.to_csv('final_ml_dataset.csv', index=False)
print(f"Success! Final balanced dataset saved. Total rows: {len(final_df)}")