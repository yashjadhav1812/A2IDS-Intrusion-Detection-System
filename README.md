# Network Intrusion Datasets Provenance & Feature Schema

## 1. Overview and Standards

This directory documents the research dataset foundations and training benchmarks for the AI-NIDS/IPS machine learning pipeline.

The feature extraction engine (`flow_engine.py`) and ML model (`model.py`) adhere to standard flow feature definitions established by modern intrusion detection benchmarks:
- **CICIDS2017** (Canadian Institute for Cybersecurity)
- **UNSW-NB15** (Cyber Range Lab of the Australian Centre for Cyber Security)

## 2. Documented Feature Schema (17 Core Features)

| Feature Name | Type | Description | Source Benchmark |
| :--- | :--- | :--- | :--- |
| `flow_duration` | Float | Total elapsed time of the bidirectional conversation in seconds | CICIDS2017 `Flow Duration` |
| `total_fwd_pkts` | Float | Number of packets from initiator to responder | CICIDS2017 `Total Fwd Packets` |
| `total_bwd_pkts` | Float | Number of packets from responder to initiator | CICIDS2017 `Total Backward Packets` |
| `total_fwd_bytes` | Float | Total payload/header bytes sent forward | CICIDS2017 `Total Length of Fwd Packets` |
| `total_bwd_bytes` | Float | Total payload/header bytes sent backward | CICIDS2017 `Total Length of Bwd Packets` |
| `pkt_len_mean` | Float | Mean packet size across the flow | CICIDS2017 `Packet Length Mean` |
| `pkt_len_std` | Float | Standard deviation of packet sizes | CICIDS2017 `Packet Length Std` |
| `pkt_len_max` | Float | Maximum packet length observed | CICIDS2017 `Packet Length Max` |
| `pkt_len_min` | Float | Minimum packet length observed | CICIDS2017 `Packet Length Min` |
| `flow_pkts_per_sec` | Float | Packets transmitted per second | CICIDS2017 `Flow Packets/s` |
| `flow_bytes_per_sec` | Float | Bytes transmitted per second | CICIDS2017 `Flow Bytes/s` |
| `syn_flag_count` | Float | Number of packets with TCP SYN flag set | CICIDS2017 `SYN Flag Count` |
| `ack_flag_count` | Float | Number of packets with TCP ACK flag set | CICIDS2017 `ACK Flag Count` |
| `fin_flag_count` | Float | Number of packets with TCP FIN flag set | CICIDS2017 `FIN Flag Count` |
| `rst_flag_count` | Float | Number of packets with TCP RST flag set | CICIDS2017 `RST Flag Count` |
| `psh_flag_count` | Float | Number of packets with TCP PSH flag set | CICIDS2017 `PSH Flag Count` |
| `flow_iat_mean` | Float | Mean inter-arrival time between packets | CICIDS2017 `Flow IAT Mean` |

## 3. Class Definitions

1. `BENIGN`: Normal interactive network traffic (web browsing, DNS lookups, API queries, streaming). Characterized by balanced forward/backward packets, standard TCP handshakes (SYN -> SYN/ACK -> ACK -> FIN), and non-zero payload distributions.
2. `SYN_FLOOD`: Denial-of-Service attack pattern. Characterized by rapid forward SYN packets, 0 or near-0 backward packets, extremely high packet rates, and minimal or no ACK/FIN flags.
3. `PORT_SCAN`: Reconnaissance activity. Characterized by short flow durations, single-packet probes with 0 or 1 response, low bytes, and rapid consecutive connection attempts across destination ports.
4. `GENERIC_MALICIOUS`: Outlier flows exhibiting anomalous packet size distributions, abnormal burstiness, or asymmetric payload ratios consistent with malware C2 beaconing or exfiltration attempts.

## 4. Known Collection Limitations

- Offline benchmark models are trained in controlled testbed environments. Real production traffic exhibits varying background noise, asymmetric routing (missing reverse packets due to NAT or multi-path routing), and bursty user behaviors.
- Machine learning probabilities reflect statistical proximity to training patterns, not absolute mathematical certainty of an attack.
- The IDS combines this ML classifier with deterministic rule validation (`detector.py`) to prevent false-positive automated blocks.
