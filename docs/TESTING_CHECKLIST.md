# Real-capture testing checklist

For each capture, record the actual run date, code commit hash, capture filename, byte size, thresholds, IP packet count, initiating SYN count, alerts by rule, processing time, and whether observed alerts match the controlled scenario.

| Capture | Scenario | Expected observation | Verified result |
|---|---|---|---|
| `network-traffic-1.pcapng` | Ordinary browsing | Mostly typical traffic; evaluate false alerts | NOT YET TESTED |
| `traffic-many-ports.pcapng` | Controlled SYN scan | TCP SYNs to many different ports | NOT YET TESTED |
| `traffic-repeated-connection.pcapng` | Repeated connections | Inspect repeated attempts to port 445 | NOT YET TESTED |

Review every false positive and missed scenario. Include packet screenshots with visible port, flag, source/destination, and timestamp. Avoid treating three capture-level outcomes as a statistically meaningful accuracy score. Produce a readable demo at presentation size.
