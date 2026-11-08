import pandas as pd
import matplotlib.pyplot as plt

print("Loading historical artifacts...")
steps_df = pd.read_csv('originals/fine_tuning_steps.txt')
result_df = pd.read_csv('originals/result.csv')

plt.figure(figsize=(10, 5))
plt.plot(steps_df['step'], steps_df['training_loss'], label='Training Loss', color='red')
plt.title('Historical Fine-Tuning Training Loss')
plt.xlabel('Step')
plt.ylabel('Loss')
plt.legend()
plt.grid(True)
plt.savefig('screenshots/figure_07_historical_loss.png')
print("Saved loss plot to screenshots/figure_07_historical_loss.png")

print("\n--- Final Non-Null Metrics from result.csv ---")
final_metrics = result_df.dropna(subset=['classification/accuracy']).iloc[-1]
print(f"Step: {final_metrics['step']}")
print(f"Accuracy: {final_metrics['classification/accuracy']}")
print(f"Precision: {final_metrics['classification/precision']}")
print(f"Recall: {final_metrics['classification/recall']}")
print(f"F1: {final_metrics['classification/f1']}")
print("\nNote: These are historical artifacts, NOT student-run model outputs.")
