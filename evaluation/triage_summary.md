# Triage Evaluation Summary

## Results by Scenario

| Scenario | Condition | Median (s) | Total (s) | Accuracy |
|---|---|---|---|---|
| s1_ssh_bruteforce | manual | 34.8 | 100.5 | 100.0% |
| s1_ssh_bruteforce | tool | 9.5 | 28.7 | 100.0% |
| s3_clock_skew | manual | 78.2 | 186.6 | 66.7% |
| s3_clock_skew | tool | 11.2 | 33.0 | 100.0% |

*Note: No triage data yet for: s2_web_attack*

## Overall Performance

- **Manual overall median:** 40.6 s
- **Tool overall median:** 10.3 s
- **Speed-up:** 3.9x

## Limitations
- Sample size (n) is very small.
- Testers are the authors and know the tool well.
- Scenario authors had prior knowledge of the events.
- Synthetic data might not perfectly replicate real-world complexity.
