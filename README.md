# Team Cache — Lightweight Network Intrusion Detection

CPT S 427 · Milestone 3 · Offline PCAP/PCAPNG analysis prototype

**Status:** A code foundation. Unit tests can be run immediately; end-to-end validation with our three saved PCAPNG captures remains outstanding. No measured accuracy or real-PCAP detection results are claimed yet.

## Ownership and code layout

| Component | Owner | Purpose |
|---|---|---|
| `cache_ids/packets.py` | Melvin | Read PCAP/PCAPNG with Scapy, extract packet fields |
| `cache_ids/runner.py`, `cache_ids/__main__.py` | Melvin | Integrate components, command line, JSON and CSV output |
| `cache_ids/rules.py` | Kaleb | Add/tune detection rules and alert behavior |
| `evaluate.py`, `outputs/` | Tyler | Run captures, evaluate results, record demonstration |
| `docs/`, final paper | Michael | Figure, supporting documentation, references, ethics |
| `cache_ids/models.py` | Shared contract | Discuss field changes before editing, as they affect everyone |

**No active probing or live network sniffing** is performed by this program. It only reads saved captures.

## Step 1: Clone the repository (Windows PowerShell)

```powershell
git clone https://github.com/Tillbohr/intrusion-detector.git
cd intrusion-detector
```

Place the project code in this repository root (same level as the three PCAPNG files), then:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If `py` is unavailable, substitute `python`. Python 3.10 or newer is recommended.

## Step 2: Check the code foundation

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

These are synthetic-event and mocked-layer tests, not a replacement for real capture validation. Parser tests that simulate Scapy verify conversion logic; they do not prove compatibility with the saved PCAPNG files.

## Step 3: Run all three saved captures

```powershell
.\.venv\Scripts\python.exe -m cache_ids --pcap network-traffic-1.pcapng traffic-many-ports.pcapng traffic-repeated-connection.pcapng
```

`outputs/results.json` contains counts, alerts and timing per capture; `outputs/alerts.csv` contains alerts suitable for a table or report. Generated outputs are ignored by Git by default: Tyler can copy cleaned measurements into `docs/` and attach screenshots/logs for the paper.

To also test the **experimental** baseline-dependent rate rule:

```powershell
.\.venv\Scripts\python.exe -m cache_ids --pcap network-traffic-1.pcapng traffic-many-ports.pcapng traffic-repeated-connection.pcapng --baseline network-traffic-1.pcapng
```

Then run the small-sample scenario evaluation:

```powershell
.\.venv\Scripts\python.exe evaluate.py --results outputs/results.json
```

## Detection rules in the starter

- Port scan: 20 different TCP destination ports from one source to one destination within 10 seconds.
- Repeated attempts: 30 initiating TCP SYN packets targeting the same destination IP/port within 60 seconds.
- High connection rate: optional baseline-relative rate rule when `--baseline` is provided.

These are **unvalidated starting thresholds** from the Milestone 2 plan. If repeated attempts in a capture don't reach 30 SYNs, the rule will not fire; do not change thresholds solely to make a demo look successful. Record chosen thresholds and justify them using observed packet counts and limitations. A rule alert means a pattern was flagged, not that an attack was proven.

To test a candidate threshold for repeated SYNs (with clear documentation):

```powershell
.\.venv\Scripts\python.exe -m cache_ids --pcap traffic-repeated-connection.pcapng --repeated-syns 10
```

## Collaborating without overwriting each other

Create a **separate Git branch** per task and submit a pull request. Avoid simultaneously editing `cache_ids/models.py`. Run the unit tests before submitting changes. Check `CONTRIBUTING.md` for example commands.

## Known limitations and research notes

- Traffic captures have not yet been analyzed with this version of the parser.
- The normal capture is from a home Wi-Fi network; suspicious traffic is from an isolated VM network. Differences in environments can confound baseline comparisons.
- The repeated-connections capture reportedly used Nmap TCP connect scans. The exact number of SYN attempts must be verified before determining whether 30/60 seconds is appropriate.
- Three labeled captures are insufficient for robust production intrusion detection accuracy claims.
- The optional baseline is a global initiating-SYN rate and does not represent a per-device behavioral model.
- Readable demonstrations should zoom in on representative packet fields and alert lines.
