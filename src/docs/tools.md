# Wi-Fi & Network PCAP Analyzer — MCP Server

A **Model Context Protocol (MCP)** server for deep, evidence-backed analysis of Wi-Fi (802.11), IP, TCP, UDP, DNS, DHCP, ARP, and application-layer traffic captured in PCAP/PCAPNG files.

Built on **PyShark/TShark** as the packet-dissection engine, the server exposes structured analysis capabilities to AI coding agents (GitHub Copilot, Cursor, Claude, etc.) and human engineers alike.

**Audience:** Wi-Fi engineers · Network engineers/admins · Security engineers · NOC/SOC teams · AI troubleshooting agents

---

## Table of Contents

1. [Architecture](#architecture)
2. [Design Principle](#design-principle)
3. [Tool Catalog](#tool-catalog)
   - [A. Capture Lifecycle](#a-capture-lifecycle)
   - [B. Capture Intelligence](#b-capture-intelligence)
   - [C. Packet Intelligence](#c-packet-intelligence)
   - [D. Protocol Intelligence](#d-protocol-intelligence)
   - [E. Wi-Fi Network Discovery](#e-wi-fi-network-discovery)
   - [F. Wi-Fi Channel Analysis](#f-wi-fi-channel-analysis)
   - [G. Wi-Fi PHY / RF Analysis](#g-wi-fi-phy--rf-analysis)
   - [H. Wi-Fi Management Frames](#h-wi-fi-management-frames)
   - [I. Wi-Fi Frame Exchange & MAC-Layer Efficiency](#i-wi-fi-frame-exchange--mac-layer-efficiency)
   - [J. Wi-Fi Power Save & QoS](#j-wi-fi-power-save--qos)
   - [K. Wi-Fi Security](#k-wi-fi-security)
   - [L. Wi-Fi Roaming & 802.11k/v/r](#l-wi-fi-roaming--80211kvr)
   - [M. Wi-Fi Connectivity](#m-wi-fi-connectivity)
   - [N. DHCP Analysis](#n-dhcp-analysis)
   - [O. ARP Analysis](#o-arp-analysis)
   - [P. IP Analysis](#p-ip-analysis)
   - [Q. TCP Analysis](#q-tcp-analysis)
   - [R. UDP Analysis](#r-udp-analysis)
   - [S. DNS Analysis](#s-dns-analysis)
   - [T. Application Protocol Analysis](#t-application-protocol-analysis)
   - [U. Conversation Analysis](#u-conversation-analysis)
   - [V. Traffic Analysis](#v-traffic-analysis)
   - [W. Performance Analysis](#w-performance-analysis)
   - [X. VoIP / Real-Time Analysis](#x-voip--real-time-analysis)
   - [Y. Security & Anomaly Detection](#y-security--anomaly-detection)
   - [Z. Expert Diagnosis](#z-expert-diagnosis)
   - [AA. Network Health & Scoring](#aa-network-health--scoring)
   - [AB. Correlation Engine](#ab-correlation-engine)
   - [AC. Evidence Engine & Comparison](#ac-evidence-engine--comparison)
   - [AD. Root Cause Analysis & Reporting](#ad-root-cause-analysis--reporting)
4. [Recommended Agent-Facing Tool Surface](#recommended-agent-facing-tool-surface)
5. [Suggested Development Phases](#suggested-development-phases)
6. [Target End-to-End Experience](#target-end-to-end-experience)

---

## Architecture

```
                 MCP TOOLS
                     │
                     ▼
             ANALYSIS SERVICES
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    Wi-Fi Engine  Network Engine  Security Engine
        │            │            │
        └────────────┼────────────┘
                     ▼
              CORRELATION ENGINE
                     │
                     ▼
               EVIDENCE ENGINE
                     │
                     ▼
              PyShark / TShark
                     │
                     ▼
                PCAP / PCAPNG
```

## Design Principle

> **TShark/PyShark performs packet decoding. The analysis layer performs engineering interpretation and correlation. The MCP layer exposes those capabilities to AI agents.**

Keeping this separation makes it tractable to grow from a handful of tools to hundreds of analysis capabilities without the codebase collapsing into an unmaintainable pile of ad-hoc filters.

---

## Tool Catalog

### A. Capture Lifecycle

Session/state management for loaded captures. *(Added — the original spec had `load_capture` but no lifecycle counterparts, which any multi-capture server needs.)*

| Tool | Description |
|---|---|
| `load_capture` | Registers a PCAP/PCAPNG file and assigns it a `capture_id`. Validates the file path and creates a reusable capture context. |
| `list_loaded_captures` | *(Added)* Lists all currently registered `capture_id`s with basic metadata (file name, size, load time). |
| `unload_capture` | *(Added)* Releases a capture context and frees associated resources/cache. |
| `export_filtered_capture` | *(Added)* Applies a display filter and writes the matching packets to a new PCAP file — useful for handing a trimmed capture back to the user or another tool. |
| `reload_capture` | *(Added)* Re-parses a capture in place, e.g. after the underlying file changed or a decode preference (custom dissector, secrets/keys file) was updated. |
| `set_decryption_keys` | *(Added)* Supplies WPA/WPA2 PSK, SAE password, or 802.1X keys so TShark can decrypt EAPOL-protected data frames for deeper analysis. |

### B. Capture Intelligence

| Tool | Description |
|---|---|
| `get_summary` | Basic overview: packet count, protocol layers present, start/end time, capture duration. |
| `get_capture_metadata` | Full PCAP/PCAPNG metadata: file format, size, encapsulation, link-layer type, snaplen, interfaces, interface metadata, capture comments, start/end timestamps. |
| `get_capture_statistics` | Aggregate statistics: total packets, total bytes, packets/sec, bytes/sec, bits/sec, average/min/max packet size, duration. |
| `validate_capture` | Integrity check: corrupted/malformed/truncated packets, invalid timestamps, unsupported protocols, decode failures, missing packet info. |
| `get_capture_interfaces` | Identifies interfaces/radio adapters represented in the capture (ID, name, link type, packet count). |
| `get_capture_time_range` | First packet, last packet, duration, timestamp range, and packet distribution over time. |

### C. Packet Intelligence

| Tool | Description |
|---|---|
| `dissect_packet` | Field-level dissection of one packet: frame number, timestamp, protocol layers, summary, decoded fields per layer. |
| `filter_packets` | Runs a Wireshark display filter (e.g. `wlan.fc.type_subtype == 0x08`, `tcp.port == 443`, `dns`) against the capture. |
| `get_packet_by_number` | Retrieves a specific packet by its Wireshark frame number. |
| `get_packets_by_time_range` | Retrieves packets between `start_time` and `end_time`. |
| `get_packets_between_frames` | Retrieves packets between `start_frame` and `end_frame`. |
| `get_related_packets` | Given one packet, finds related packets in its exchange (e.g. Association Request → Response → EAPOL → DHCP). |
| `get_packet_timeline` | Generates a chronological packet/event timeline. |
| `get_flow_packets` | Returns all packets belonging to a specific flow. |
| `get_client_packets` | Returns packets associated with a specific Wi-Fi client (by MAC). |
| `get_ap_packets` | Returns packets associated with a specific AP/BSSID. |
| `get_transaction_packets` | Returns all packets belonging to a transaction (DHCP, DNS, TCP, EAPOL, ARP, etc.). |

### D. Protocol Intelligence

| Tool | Description |
|---|---|
| `get_protocol_statistics` | Protocol hierarchy breakdown (802.11, LLC, ARP, IPv4/6, TCP, UDP, DNS, DHCP, TLS, HTTP, QUIC) with packet count, %, and bytes. |
| `get_protocol_distribution_over_time` | Shows how the mix of protocols changes across the capture timeline. |
| `get_unknown_protocols` | Identifies protocols/payloads TShark cannot properly decode. |
| `get_packet_size_distribution` | Analyzes the distribution of packet sizes. |
| `get_packet_rate` | Packets/sec over configurable intervals. |
| `get_bandwidth_usage` | Bytes/sec, bits/sec, peak and average bandwidth. |

### E. Wi-Fi Network Discovery

| Tool | Description |
|---|---|
| `get_wifi_networks` | Discovers all Wi-Fi networks: SSID, BSSID, channel, frequency, band, security, encryption, first/last seen, beacon count. |
| `get_access_points` | Discovers all APs: BSSID, SSID, vendor, channel, frequency, PHY, packet count, first/last seen. |
| `get_wifi_clients` | Discovers Wi-Fi clients: MAC, vendor, associated AP, SSID, first/last seen, packet count, data volume. |
| `get_bssid_details` | Deep-dive analysis of a specific BSSID. |
| `get_client_details` | Deep-dive analysis of a specific client. |
| `get_ssid_details` | Analyzes one SSID across all observed BSSIDs (multi-AP/ESS view). |
| `get_vendor_statistics` | Device manufacturer breakdown via MAC OUI lookup. |
| `get_hidden_ssid_detection` | *(Added)* Flags APs broadcasting a cloaked/empty SSID in beacons, correlated with probe responses that reveal the real SSID. |

### F. Wi-Fi Channel Analysis

| Tool | Description |
|---|---|
| `get_channel_statistics` | Per-channel AP count, client count, packet count, traffic volume, signal stats, activity level. |
| `get_channel_distribution` | Which channels are in use and how heavily. |
| `get_band_statistics` | Breakdown across 2.4 GHz / 5 GHz / 6 GHz. |
| `get_channel_width_statistics` | Breakdown across 20/40/80/160/320 MHz where the capture supports it. |
| `get_channel_overlap` | Identifies networks on potentially overlapping/adjacent channels. |
| `get_channel_congestion` | Ranks channels by observed wireless activity/contention. |
| `get_airtime_utilization` | *(Added)* Estimates the percentage of channel airtime consumed by beacons, management, control, and data frames per channel/BSS — a core RF-planning metric the original spec omitted. |

### G. Wi-Fi PHY / RF Analysis

| Tool | Description |
|---|---|
| `get_phy_statistics` | Observed PHY generations in use (802.11a/b/g/n/ac/ax/be). |
| `get_data_rate_statistics` | Distribution of observed transmission rates. |
| `get_mcs_statistics` | MCS index usage distribution. |
| `get_nss_statistics` | Number of spatial streams in use. |
| `get_guard_interval_statistics` | Guard interval (short/long, or HE/EHT GI options) usage. |
| `get_signal_statistics` | RSSI/signal strength distribution — min, max, average. |
| `get_snr_statistics` | SNR where both signal and noise floor are available. |
| `get_radio_quality` | Composite, evidence-based RF quality assessment. |
| `get_ofdma_statistics` | *(Added)* Analyzes 802.11ax/be OFDMA resource-unit (RU) allocation and usage where trigger/HE-info fields are present. |
| `get_mu_mimo_statistics` | *(Added)* Detects and summarizes multi-user MIMO group usage from VHT/HE group-ID fields. |

### H. Wi-Fi Management Frames

| Tool | Description |
|---|---|
| `get_beacon_analysis` | Decodes beacons: SSID, BSSID, interval, channel, supported rates, capabilities, security, HT/VHT/HE/EHT capabilities. |
| `get_probe_request_analysis` | Analyzes client probe requests (including SSID-specific vs. broadcast probing behavior). |
| `get_probe_response_analysis` | Analyzes AP probe responses. |
| `get_association_analysis` | Analyzes association requests/responses: success/failure, status codes, latency. |
| `get_reassociation_analysis` | Analyzes client reassociation events. |
| `get_authentication_analysis` | Analyzes 802.11 authentication exchanges (Open, SAE, 802.1X trigger). |
| `get_deauthentication_analysis` | Analyzes deauthentication events and stated reason codes. |
| `get_disassociation_analysis` | Analyzes disassociation events and reason codes. |
| `get_action_frame_analysis` | Analyzes 802.11 action frames (e.g. BA setup, spectrum management, radio measurement, FT). |
| `get_management_frame_statistics` | Aggregates counts across all management-frame subtypes. |
| `get_information_elements` | *(Added)* Extracts and lists 802.11 Information Elements (vendor-specific, WMM, HT/VHT/HE/EHT capability IEs, RSN, etc.) from a given frame or frame set — a building block many other tools depend on. |

### I. Wi-Fi Frame Exchange & MAC-Layer Efficiency

*(Added section — MAC-layer efficiency/retry behavior is central to real-world Wi-Fi troubleshooting and was missing entirely from the original spec.)*

| Tool | Description |
|---|---|
| `get_retry_statistics` | Analyzes the 802.11 retry bit across data frames to quantify retransmission rate per client/AP/channel. |
| `get_rts_cts_analysis` | Analyzes RTS/CTS exchange usage and effectiveness (hidden-node mitigation). |
| `get_ampdu_analysis` | Analyzes A-MPDU aggregation: aggregate sizes, sub-frame counts, aggregation efficiency. |
| `get_block_ack_analysis` | Analyzes Block ACK setup/teardown and bitmap efficiency. |
| `detect_hidden_node_indicators` | Flags patterns (elevated retries without proportional RSSI drop, RTS/CTS spikes) consistent with hidden-node conditions. |
| `get_frame_control_statistics` | Breaks down frames by type/subtype, ToDS/FromDS, protected flag, and other Frame Control bits. |

### J. Wi-Fi Power Save & QoS

*(Added section.)*

| Tool | Description |
|---|---|
| `get_power_save_analysis` | Analyzes power-management bit transitions and U-APSD/PS-Poll behavior per client. |
| `get_dtim_analysis` | Analyzes DTIM period/count consistency in beacons and its effect on multicast delivery latency. |
| `get_wmm_qos_analysis` | Analyzes WMM/802.11e access-category usage (AC_VO/VI/BE/BK) and EDCA parameters. |
| `get_beacon_interval_consistency` | Detects beacon interval drift or missed beacons, a common symptom of AP CPU/RF overload. |

### K. Wi-Fi Security

| Tool | Description |
|---|---|
| `get_wifi_security_analysis` | Identifies security mode in use: Open, WEP, WPA/WPA2/WPA3, Personal/Enterprise, 802.1X, SAE, PSK. |
| `get_eapol_analysis` | Analyzes EAPOL exchanges generally. |
| `get_four_way_handshake` | Analyzes the WPA/WPA2 4-way handshake: AP, client, M1–M4, timing, replay counters, missing messages. |
| `get_eap_analysis` | Analyzes EAP method negotiation and exchange (PEAP, EAP-TLS, etc.) for 802.1X. |
| `get_roaming_security_analysis` | Analyzes authentication/security behavior specifically during roaming events. |
| `detect_security_anomalies` | Detects unusual authentication/security behavior generally. |
| `get_sae_handshake_analysis` | *(Added)* Analyzes WPA3 SAE (Dragonfly) commit/confirm exchange timing and failures. |
| `detect_pmkid_exposure` | *(Added)* Flags RSN PMKID presence in the first EAPOL message, a known WPA2 attack surface engineers audit for. |
| `get_krack_indicators` | *(Added)* Flags anomalous EAPOL message-3/message-1 retransmission patterns consistent with KRACK-style nonce reuse. |

### L. Wi-Fi Roaming & 802.11k/v/r

| Tool | Description |
|---|---|
| `get_roaming_events` | Detects clients moving between APs. |
| `get_client_roaming_history` | Builds a client's AP-to-AP roaming path with timestamps. |
| `get_roaming_latency` | Measures authentication, association, reassociation latency, and total roaming interruption time. |
| `get_roaming_failures` | Identifies failed roaming attempts. |
| `get_roaming_anomalies` | Detects excessive roaming, sticky clients, roaming loops, unexpected AP transitions. |
| `get_fast_transition_analysis` | *(Added)* Analyzes 802.11r FT (Fast BSS Transition) frames and measures FT roam latency vs. full re-authentication. |
| `get_bss_transition_management` | *(Added)* Analyzes 802.11v BSS Transition Management requests/responses (network-assisted roaming). |
| `get_radio_measurement_analysis` | *(Added)* Analyzes 802.11k Radio Resource Measurement (beacon report, neighbor report) exchanges. |
| `detect_sticky_client` | *(Added)* Flags clients remaining associated to a distant/weak-signal AP despite better candidates being available (subset of roaming anomalies, exposed as a focused diagnostic tool). |

### M. Wi-Fi Connectivity

| Tool | Description |
|---|---|
| `get_association_failures` | Finds failed association attempts. |
| `get_authentication_failures` | Finds authentication failures. |
| `get_dhcp_failures` | Identifies DHCP failures following Wi-Fi connection. |
| `get_dns_failures` | Identifies DNS failures. |
| `get_gateway_failures` | Analyzes gateway (default route) reachability issues. |
| `get_client_connectivity` | Determines overall connectivity state for a specific client. |
| `get_connection_timeline` | Builds the full connect sequence: Probe → Auth → Assoc → EAPOL → DHCP → ARP → DNS → TCP → Application. One of the primary agent-facing tools. |

### N. DHCP Analysis

| Tool | Description |
|---|---|
| `get_dhcp_statistics` | General DHCP statistics. |
| `get_dhcp_clients` | Identifies DHCP clients. |
| `get_dhcp_servers` | Identifies DHCP servers (including detection of multiple/rogue servers). |
| `get_dhcp_transactions` | Tracks Discover → Offer → Request → ACK per transaction. |
| `get_dhcp_failures` | Detects Discover-without-Offer, Offer-without-Request, Request-without-ACK, NAK, duplicate servers. |
| `get_dhcp_latency` | Calculates DHCP transaction latency. |
| `get_dhcp_option_analysis` | *(Added)* Extracts and summarizes DHCP options in use (lease time, DNS servers, domain, vendor class) across clients/servers. |

### O. ARP Analysis

| Tool | Description |
|---|---|
| `get_arp_statistics` | General ARP statistics. |
| `get_arp_hosts` | Maps IP → MAC associations. |
| `get_arp_conversations` | Analyzes ARP request/reply conversations. |
| `get_arp_resolution_analysis` | Analyzes IP-to-MAC resolution success/latency. |
| `detect_arp_anomalies` | Detects duplicate IP, conflicting MAC, ARP storms, gratuitous ARP anomalies. |

### P. IP Analysis

| Tool | Description |
|---|---|
| `get_ip_statistics` | Analyzes IPv4/IPv6 traffic generally. |
| `get_ipv4_hosts` | Discovers IPv4 hosts. |
| `get_ipv6_hosts` | Discovers IPv6 hosts. |
| `get_ip_conversations` | Analyzes IP-level conversations. |
| `get_subnet_statistics` | Analyzes traffic grouped by subnet. |
| `get_ip_ttl_statistics` | Analyzes TTL distribution (useful for hop-count/NAT/spoofing inference). |
| `get_fragmentation_analysis` | Detects IP fragmentation and reassembly issues. |
| `get_ipv6_neighbor_discovery` | Analyzes IPv6 NDP (NS/NA/RS/RA). |
| `get_icmp_analysis` | Analyzes ICMP/ICMPv6 traffic (unreachable, TTL-exceeded, echo). |

### Q. TCP Analysis

| Tool | Description |
|---|---|
| `get_tcp_statistics` | General TCP statistics. |
| `get_tcp_conversations` | Identifies TCP conversations. |
| `get_tcp_connections` | Per-connection detail: client/server, ports, start/end, duration, packets, bytes. |
| `get_tcp_handshake_analysis` | Analyzes SYN / SYN-ACK / ACK exchanges. |
| `get_tcp_connection_failures` | Detects missing SYN-ACK, SYN retransmissions, connection failures, RST. |
| `get_tcp_retransmissions` | Detects TCP retransmissions. |
| `get_tcp_duplicate_ack_analysis` | Analyzes duplicate ACKs. |
| `get_tcp_out_of_order_analysis` | Detects out-of-order segments. |
| `get_tcp_lost_segment_analysis` | Identifies evidence of lost segments. |
| `get_tcp_zero_window_analysis` | Detects receiver-side window exhaustion. |
| `get_tcp_window_analysis` | Analyzes TCP receive window behavior/scaling. |
| `get_tcp_rtt_analysis` | Calculates RTT where derivable. |
| `get_tcp_throughput` | Calculates per-connection throughput. |
| `get_tcp_reset_analysis` | Analyzes TCP RST events and likely cause. |
| `get_tcp_connection_timeline` | Builds a full TCP state timeline for a connection. |

### R. UDP Analysis

| Tool | Description |
|---|---|
| `get_udp_statistics` | General UDP statistics. |
| `get_udp_conversations` | Analyzes UDP flows. |
| `get_udp_endpoints` | Identifies UDP endpoints. |
| `get_udp_loss_indicators` | Identifies evidence of loss where protocol/capture context permits (e.g. sequenced application protocols). |
| `get_udp_latency` | Analyzes response latency where request/response pairs can be correlated. |
| `get_udp_throughput` | Calculates UDP throughput. |
| `get_udp_port_statistics` | Analyzes UDP port usage. |

### S. DNS Analysis

| Tool | Description |
|---|---|
| `get_dns_statistics` | General DNS statistics. |
| `get_dns_servers` | Identifies DNS servers in use. |
| `get_dns_queries` | Extracts DNS queries. |
| `get_dns_responses` | Extracts DNS responses. |
| `get_dns_query_response_pairs` | Correlates queries with their responses. |
| `get_dns_latency` | Calculates DNS response latency. |
| `get_dns_failures` | Detects NXDOMAIN, SERVFAIL, REFUSED, missing response, timeout. |
| `get_dns_anomalies` | Identifies unusual DNS behavior (e.g. excessive NXDOMAIN, DNS tunneling patterns). |
| `get_dns_timeline` | Builds chronological DNS activity. |

### T. Application Protocol Analysis

| Tool | Description |
|---|---|
| `get_application_protocol_distribution` | Identifies application protocols present in the capture. |
| `get_http_statistics` | Analyzes HTTP traffic generally. |
| `get_http_requests` | Extracts HTTP requests where visible (unencrypted). |
| `get_http_responses` | Extracts HTTP responses. |
| `get_http_errors` | Identifies HTTP 4xx/5xx responses. |
| `get_tls_statistics` | Analyzes TLS traffic generally. |
| `get_tls_connections` | Identifies TLS sessions. |
| `get_tls_handshake_analysis` | Analyzes TLS handshake flow and timing. |
| `get_tls_version_distribution` | Analyzes TLS protocol version usage. |
| `get_tls_cipher_statistics` | Analyzes negotiated cipher suites. |
| `get_tls_sni_statistics` | *(Added)* Extracts SNI hostnames from ClientHello — the primary way to identify destinations in encrypted traffic. |
| `get_quic_statistics` | Analyzes QUIC traffic. |

### U. Conversation Analysis

| Tool | Description |
|---|---|
| `get_top_talkers` | Ranks hosts by packets, bytes, or connection count. |
| `get_conversations` | Generates complete conversation statistics. |
| `get_mac_conversations` | Analyzes MAC-level conversations. |
| `get_ip_conversations` | Analyzes IP-level conversations. |
| `get_tcp_conversations` | Analyzes TCP conversations. |
| `get_udp_conversations` | Analyzes UDP conversations. |
| `get_top_ports` | Ranks ports by traffic volume. |
| `get_top_services` | Identifies most-used services/applications. |

### V. Traffic Analysis

| Tool | Description |
|---|---|
| `get_traffic_timeline` | Shows overall traffic volume over time. |
| `get_packet_rate_timeline` | Shows packets/sec over time. |
| `get_bandwidth_timeline` | Shows bandwidth over time. |
| `get_broadcast_statistics` | Analyzes broadcast traffic. |
| `get_multicast_statistics` | Analyzes multicast traffic. |
| `get_unicast_statistics` | Analyzes unicast traffic. |
| `get_broadcast_storm_analysis` | Detects abnormal broadcast activity. |
| `get_multicast_analysis` | Analyzes multicast group behavior (IGMP/MLD joins/leaves). |
| `get_traffic_anomalies` | Identifies abnormal traffic patterns generally. |

### W. Performance Analysis

| Tool | Description |
|---|---|
| `get_latency_analysis` | Analyzes latency across supported protocols. |
| `get_packet_loss_indicators` | Identifies evidence of packet loss. |
| `get_retransmission_analysis` | Correlates retransmissions across the whole capture (L2 and L4). |
| `get_throughput_analysis` | Calculates throughput generally. |
| `get_jitter_analysis` | Analyzes packet timing variation. |
| `get_qos_analysis` | Analyzes DSCP, 802.11 QoS, WMM, priority traffic marking. |
| `get_qos_statistics` | Provides QoS class distribution and behavior. |

### X. VoIP / Real-Time Analysis

| Tool | Description |
|---|---|
| `get_voip_statistics` | Identifies VoIP traffic in the capture. |
| `get_sip_analysis` | Analyzes SIP signaling. |
| `get_rtp_analysis` | Analyzes RTP streams generally. |
| `get_rtp_streams` | Identifies individual RTP streams. |
| `get_rtp_loss` | Analyzes RTP packet loss. |
| `get_rtp_jitter` | Analyzes RTP jitter. |
| `get_rtp_latency` | Analyzes RTP latency. |
| `get_call_quality` | Provides evidence-based call-quality (e.g. MOS-style) analysis. |

### Y. Security & Anomaly Detection

| Tool | Description |
|---|---|
| `detect_network_scanning` | Detects host/port scanning behavior. |
| `detect_tcp_scan` | Detects TCP scanning patterns (SYN scan, FIN scan, etc.). |
| `detect_arp_spoofing` | Identifies possible ARP spoofing indicators. |
| `detect_duplicate_ip` | Detects multiple MACs claiming the same IP. |
| `detect_mac_anomalies` | Identifies unusual MAC address behavior (e.g. randomization inconsistencies, spoofing). |
| `detect_deauth_storm` | Detects excessive deauthentication frames. |
| `detect_disassociation_storm` | Detects excessive disassociation frames. |
| `detect_beacon_anomalies` | Identifies unusual beacon behavior. |
| `detect_probe_anomalies` | Identifies unusual probing behavior. |
| `detect_rogue_ap_indicators` | Identifies indicators of potentially unauthorized APs. |
| `detect_evil_twin_indicators` | Identifies suspicious APs sharing SSID/characteristics with legitimate networks. |
| `detect_unusual_traffic` | Identifies statistically unusual traffic patterns generally. |
| `get_security_events` | Returns normalized, cross-protocol security-related events. |

### Z. Expert Diagnosis

| Tool | Description |
|---|---|
| `diagnose_wifi_client` | **Flagship tool.** Comprehensive client analysis across discovery, auth, association, AP, RSSI, SNR, PHY, MCS, retries, roaming, DHCP, ARP, DNS, TCP, application — returns problem, evidence, timeline, root cause, confidence, supporting packets, recommendations. |
| `diagnose_access_point` | Comprehensive AP analysis: clients, SSIDs, channels, PHY, beacons, auth, association, deauth, roaming, traffic, retries, performance, anomalies. |
| `diagnose_ssid` | Analyzes an SSID across all observed APs. |
| `diagnose_wifi_connectivity` | Stage-by-stage connectivity check (Discovery/Auth/Assoc/EAPOL/DHCP/ARP/DNS/TCP) reporting PASS/FAIL/NOT REACHED per stage. |
| `diagnose_roaming` | Determines why roaming happened, whether it succeeded, latency, AP transition, auth delay, sticky-client behavior. |
| `diagnose_authentication` | Determines where Wi-Fi authentication fails. |
| `diagnose_dhcp` | Traces Discover → Offer → Request → ACK and identifies the failure point. |
| `diagnose_dns` | Determines query success, response latency, server problems, NXDOMAIN/SERVFAIL, missing responses. |
| `diagnose_tcp` | Analyzes handshake, RTT, retransmissions, duplicate ACKs, out-of-order packets, window issues, RST, throughput. |

### AA. Network Health & Scoring

| Tool | Description |
|---|---|
| `analyze_network_health` | Full PCAP health analysis: Wi-Fi/network/connectivity/performance/security/DNS/DHCP/TCP/application health, major/minor problems, warnings, evidence, recommendations. |
| `analyze_capture_for_anomalies` | Automatically searches the whole capture for unusual behavior, correlating Wi-Fi, DHCP, ARP, DNS, IP, TCP, UDP, application, and security signals. |
| `calculate_wifi_health_score` | Composite Wi-Fi health score (RF quality, connectivity, authentication, DHCP, DNS, TCP, roaming, security → overall), grounded in observable evidence rather than arbitrary judgment. |
| `calculate_client_health_score` | Health score for an individual client. |
| `calculate_ap_health_score` | Health score for an individual AP. |
| `calculate_ssid_health_score` | Health score for an individual SSID. |

### AB. Correlation Engine

This is what makes the server genuinely AI-agent friendly rather than just a filter wrapper.

| Tool | Description |
|---|---|
| `correlate_wifi_events` | Correlates Probe → Auth → Assoc → EAPOL → DHCP → DNS → TCP into one coherent chain. |
| `correlate_client_session` | Follows one client through its entire observed session. |
| `correlate_roaming_session` | Follows a client as it moves between APs. |
| `correlate_connection` | Correlates all packets belonging to one connection. |
| `correlate_failure` | Given a failure event, searches surrounding packets for supporting evidence. |

### AC. Evidence Engine & Comparison

| Tool | Description |
|---|---|
| `get_evidence_packets` | Returns the specific packets supporting a given finding. |
| `get_first_occurrence` | Finds the first occurrence of an event type. |
| `get_last_occurrence` | Finds the last occurrence of an event type. |
| `get_event_timeline` | Normalizes important events into one chronological timeline. |
| `compare_time_periods` | Compares two time periods within a single capture. |
| `compare_clients` | Compares behavior between two clients. |
| `compare_access_points` | Compares behavior between two APs. |
| `compare_captures` | Compares two separate captures. |
| `compare_wifi_environments` | Compares two wireless environments (e.g. before/after a site survey change). |
| `compare_ap_performance` | Compares AP performance metrics. |
| `compare_protocol_statistics` | Compares protocol distributions between two captures/periods. |
| `compare_network_health` | Compares overall network health before vs. after a configuration change. |

### AD. Root Cause Analysis & Reporting

| Tool | Description |
|---|---|
| `analyze_wifi_issue` | High-level troubleshooting entry point. Input: `client_mac`, `problem_description`, optional `time_range`. Output: issue, affected device/AP, timeline, evidence, root cause, confidence, recommendations. |
| `generate_root_cause_analysis` | Correlates the entire capture stage-by-stage (association → auth → DHCP → DNS → TCP) and determines the most likely root cause with supporting evidence. |
| `generate_engineer_report` | Generates a full engineering report: executive summary, capture info, network overview, Wi-Fi environment, APs, clients, channel/PHY-RF analysis, auth, roaming, DHCP, ARP, DNS, IPv4/6, TCP, UDP, application traffic, performance, security, anomalies, root cause, evidence, recommendations. |

---

## Recommended Agent-Facing Tool Surface

Not every low-level tool above needs to be exposed directly to an AI coding agent — that produces a confusing, dozens-of-tools interface. Expose this curated high-level subset as the primary surface, and let those tools internally call the specialized ones:

```
load_capture
get_capture_summary
get_protocol_statistics

get_wifi_networks
get_access_points
get_wifi_clients

get_client_details
get_bssid_details

get_connection_timeline
get_client_roaming_history

diagnose_wifi_client
diagnose_access_point
diagnose_wifi_connectivity
diagnose_roaming

analyze_capture_for_anomalies
analyze_network_health

get_evidence_packets

generate_root_cause_analysis
generate_engineer_report
```

---

## Suggested Development Phases

### Phase 1 — Foundation
`load_capture`, `list_loaded_captures`, `unload_capture`, `get_capture_metadata`, `get_capture_statistics`, `get_summary`, `filter_packets`, `dissect_packet`, `get_packet_by_number`, `get_packets_by_time_range`, `get_protocol_statistics`

### Phase 2 — Wi-Fi Fundamentals
`get_wifi_networks`, `get_access_points`, `get_wifi_clients`, `get_bssid_details`, `get_client_details`, `get_beacon_analysis`, `get_information_elements`, `get_probe_request_analysis`, `get_association_analysis`, `get_authentication_analysis`, `get_deauthentication_analysis`, `get_disassociation_analysis`

### Phase 3 — RF / PHY / MAC Efficiency
`get_channel_statistics`, `get_band_statistics`, `get_channel_width_statistics`, `get_phy_statistics`, `get_data_rate_statistics`, `get_mcs_statistics`, `get_signal_statistics`, `get_snr_statistics`, `get_retry_statistics`, `get_ampdu_analysis`, `get_airtime_utilization`

### Phase 4 — Core Network Protocols
`get_arp_statistics`, `get_dhcp_statistics`, `get_dns_statistics`, `get_ip_statistics`, `get_tcp_statistics`, `get_udp_statistics`, `get_tcp_connections`, `get_tcp_retransmissions`, `get_tcp_rtt_analysis`, `get_tcp_throughput`, `get_top_talkers`, `get_conversations`

### Phase 5 — Correlation
`correlate_wifi_events`, `correlate_client_session`, `correlate_roaming_session`, `correlate_connection`, `get_connection_timeline`, `get_event_timeline`, `get_evidence_packets`

### Phase 6 — Diagnosis
`diagnose_wifi_client`, `diagnose_access_point`, `diagnose_wifi_connectivity`, `diagnose_roaming`, `diagnose_authentication`, `diagnose_dhcp`, `diagnose_dns`, `diagnose_tcp`

### Phase 7 — Security Depth
`get_wifi_security_analysis`, `get_four_way_handshake`, `get_sae_handshake_analysis`, `detect_pmkid_exposure`, `detect_arp_spoofing`, `detect_rogue_ap_indicators`, `detect_evil_twin_indicators`, `get_security_events`

### Phase 8 — AI-Level Analysis & Reporting
`analyze_capture_for_anomalies`, `analyze_network_health`, `generate_root_cause_analysis`, `calculate_wifi_health_score`, `generate_engineer_report`

---

## Target End-to-End Experience

```
User:
"Analyze this PCAP and tell me why the client
was experiencing poor Wi-Fi performance."

        ↓
   analyze_wifi_issue()
        ↓
Capture Intelligence → Wi-Fi Discovery → Client Analysis
   → AP Analysis → PHY/RF Analysis → Roaming Analysis
   → DHCP/ARP/DNS → TCP Analysis → Anomaly Detection
   → Evidence Correlation
        ↓
Root Cause:
Client experienced poor performance primarily due to a
high retransmission rate and low observed PHY rates
during the affected interval.

Evidence:
- Client: XX:XX:XX:XX:XX:XX
- AP: XX:XX:XX:XX:XX:XX
- Channel: 36
- Retransmission increase: ...
- MCS degradation: ...
- RSSI: ...
- Time window: ...

Confidence: High
Recommended Investigation: ...
```

The end goal is not "an MCP wrapper around PyShark" but an **AI-driven Wi-Fi and network troubleshooting engine backed by packet-level evidence** — every claim traceable back to `get_evidence_packets`.