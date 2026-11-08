import pandas as pd
import re
import ipaddress

# Load dataset
df = pd.read_csv('originals/dataset_small.csv')
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
candidates = []

for index, row in df.iterrows():
    text = str(row.get('text', ''))
    source_label = row.get('class', 'Unknown')
    matches = ip_pattern.findall(text)
    
    for match in matches:
        regex_match = True
        ipv4_valid = False
        note = ""
        
        try:
            ipaddress.IPv4Address(match)
            ipv4_valid = True
        except ValueError:
            ipv4_valid = False
            
        if source_label != 'N' and ipv4_valid:
            note = "True Positive: Source Positive & Valid IP"
        elif source_label != 'N' and not ipv4_valid:
            note = "MISMATCH: Source Positive but INVALID IPv4"
        elif source_label == 'N' and not ipv4_valid:
            note = "True Negative: Source Negative & Invalid IP"
        elif source_label == 'N' and ipv4_valid:
            note = "MISMATCH: Source Negative but VALID IPv4"

        candidates.append({
            'source_row': index,
            'context': text[:40] + "...",
            'candidate': match,
            'regex_match': regex_match,
            'ipv4_valid': ipv4_valid,
            'source_label': source_label,
            'analyst_note': note
        })

output_df = pd.DataFrame(candidates)
output_df.to_csv('candidate_review.csv', index=False)

print("--- 10 Demonstration Samples for Report ---")
# Prioritize showing mismatches in the first 10 rows
samples = pd.concat([
    output_df[output_df['analyst_note'].str.contains('MISMATCH')].head(5),
    output_df[output_df['analyst_note'].str.contains('True')].head(5)
])
print(samples.to_string(index=False))
print("\nFull review saved to candidate_review.csv")
