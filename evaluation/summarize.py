import pandas as pd
from pathlib import Path

def summarize():
    csv_path = Path(__file__).parent / "triage_results.csv"
    df = pd.read_csv(csv_path)
    
    out_md = Path(__file__).parent / "triage_summary.md"
    
    # Calculate medians
    medians = df.groupby(["scenario", "condition"])["seconds"].median().reset_index()
    accuracy = df.groupby(["scenario", "condition"])["correct"].mean().reset_index()
    accuracy["correct"] = accuracy["correct"] * 100
    
    with open(out_md, "w") as f:
        f.write("# Triage Evaluation Summary\n\n")
        f.write("## Median Time (Seconds)\n")
        f.write(medians.to_markdown(index=False) + "\n\n")
        f.write("## Accuracy (%)\n")
        f.write(accuracy.to_markdown(index=False) + "\n\n")
        f.write("## Limitations\n")
        f.write("Note: n is small, and testers already know the tool and scenarios well. This evaluation is anecdotal rather than statistically significant.\n")
        
if __name__ == "__main__":
    summarize()
