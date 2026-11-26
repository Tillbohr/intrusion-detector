# Team Cache — How we collaborate

Work on the public GitHub repository: https://github.com/Tillbohr/intrusion-detector

1. Pull the latest main: `git checkout main` then `git pull origin main`.
2. Create your own feature branch: `git checkout -b feature/kaleb-rules` (replace name/task).
3. Edit only the files for your component when possible; coordinate changes to shared models.
4. Run `python -m unittest discover -s tests -v` before committing.
5. Commit: `git add .` then `git commit -m "Describe what changed"`.
6. Push: `git push -u origin feature/kaleb-rules`.
7. Open a pull request on GitHub so another teammate can review before merging into main.

Avoid committing `.venv/`, large derived output files, personal paths or credentials. The original project PCAPNG captures are already tracked in the repository. Do not duplicate them in each branch or add other large datasets without agreement.

## Who is doing what

| Person | Files | Work |
|---|---|---|
| Melvin | `cache_ids/packets.py`, `cache_ids/runner.py`, `cache_ids/__main__.py` | Packet parser, integration, command line, system design write-up |
| Kaleb | `cache_ids/rules.py`, `tests/test_rules.py` | Detection rules, alert generation, code testing |
| Tyler | `evaluate.py`, `docs/TESTING_CHECKLIST.md` | Run the real captures, record results, technical demo |
| Michael | `docs/` | Diagrams, related research, references, final paper and ethics document; helps with code as needed |

`cache_ids/models.py` is shared by everyone, so agree as a team before changing it.

### Notes for Kaleb

- With `--baseline network-traffic-1.pcapng`, `high_connection_rate` fires on the normal capture itself (one IPv6 host made 30 initiating SYNs within 10 s). The baseline formula gives ceil(0.728 × 10 × 3) = 22, which is below `min_high_rate_count` (30), so the threshold actually applied is the fixed 30, not "3× baseline".
- `traffic-repeated-connection.pcapng` produces two `repeated_syn` alerts for the same activity; the second comes after the 60 s cooldown. Decide whether that is wanted.

### Notes for Tyler

- Wireshark (TShark 4.6.10) counts to check the program's output against:

  | Capture | IP packets | IPv4 | IPv6 | TCP | UDP | Initiating SYNs |
  |---|---|---|---|---|---|---|
  | `network-traffic-1.pcapng` | 51,661 | 2,105 | 49,556 | 10,157 | 41,492 | 93 |
  | `traffic-many-ports.pcapng` | 2,001 | 2,000 | 1 | 2,000 | 0 | 1,000 |
  | `traffic-repeated-connection.pcapng` | 210 | 210 | 0 | 202 | 8 | 101 |

- `evaluate.py` defaults to `--results results.json`, but the program writes `outputs/results.json`. Its error message also mentions `detector.py`, which does not exist.
- Each alert has a readable `time` (local time, the same as Wireshark's View → Time Display Format → Date and Time of Day). Captures that could not be read are listed under `errors` in `results.json`, not under `results`.

Each teammate should record the code version and parameters used for any reported result. Do not claim a test was successful until someone actually ran it against the real capture.
