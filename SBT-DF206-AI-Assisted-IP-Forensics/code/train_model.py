import pandas as pd
import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, classification_report

def load_jsonl(path):
    data = []
    with open(path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return pd.DataFrame(data)

print("Loading JSONL files...")
train_df = load_jsonl('originals/dataset_train.jsonl')
test_df = load_jsonl('originals/dataset_test.jsonl')

y_train = (train_df['completion'].str.strip() == 'positive').astype(int)
y_test = (test_df['completion'].str.strip() == 'positive').astype(int)

# --- Baseline Model (Regex Only) ---
def baseline_predict(text):
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        return 1
    return 0

baseline_preds = test_df['prompt'].apply(baseline_predict)
print("\n--- Baseline Model (Regex Only) ---")
print(classification_report(y_test, baseline_preds, target_names=['Negative', 'Positive'], zero_division=0))

# --- Machine Learning Model (TF-IDF + Logistic Regression) ---
print("\n--- Training ML Model (TF-IDF + LR) ---")
vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))
X_train = vectorizer.fit_transform(train_df['prompt'])
X_test = vectorizer.transform(test_df['prompt'])

clf = LogisticRegression(random_state=42)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

print("\n--- ML Model (TF-IDF + LR) ---")
print(classification_report(y_test, y_pred, target_names=['Negative', 'Positive'], zero_division=0))

# Save predictions for Phase E
pred_df = test_df.copy()
pred_df['actual'] = y_test
pred_df['predicted'] = y_pred
pred_df['baseline_pred'] = baseline_preds
pred_df[['prompt', 'actual', 'predicted', 'baseline_pred']].to_csv('predictions.csv', index=False)
print("\nSaved test predictions to predictions.csv")
