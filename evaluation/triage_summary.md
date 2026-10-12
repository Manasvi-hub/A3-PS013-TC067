# Triage Evaluation Summary

## Results by Scenario

| Scenario | Condition | Median (s) | Total (s) | Accuracy |
|---|---|---|---|---|
| s1_ssh_bruteforce | manual | 34.8 | 100.5 | 100.0% |
| s1_ssh_bruteforce | tool | 9.5 | 28.7 | 100.0% |
| s2_web_attack | manual | 32.5 | 95.1 | 66.7% |
| s2_web_attack | tool | 13.4 | 45.1 | 100.0% |
| s3_clock_skew | manual | 78.2 | 186.6 | 66.7% |
| s3_clock_skew | tool | 11.2 | 33.0 | 100.0% |

## Overall Performance

- **Manual overall median:** 34.8 s
- **Tool overall median:** 11.2 s
- **Speed-up:** 3.1x

## Limitations
- Sample size (n) is very small.
- Testers are the authors and know the tool well.
- S2 manual and tool sessions were run by the same tester, so the tool session may benefit from familiarity with the logs.
- Scenario authors had prior knowledge of the events.
- Synthetic data might not perfectly replicate real-world complexity.
