# P2 — ESP-NOW Security SoK: Structured Bibliography

## Core ESP-NOW References

1. Espressif Systems. "ESP-NOW — A Connectionless Wi-Fi Communication Protocol." Espressif Documentation, 2024.
   - Protocol specification, frame format, security model, peer management.

2. CVE-2024-42483. "ESP-NOW Replay / Cache-Poisoning." MITRE, 2024.
   - Stale cached action frame replay; cache not cleared on peer disconnect.

3. Matheu-Garagnon, J. et al. "Security Analysis of ESP-NOW Protocol." Research Report, 2023.
   - Formal threat model for ESP-NOW at the data-link layer.

4. Espressif. "ESP32 Technical Reference Manual — Wi-Fi MAC Layer." 2023.
   - MAC-layer frame handling, action frame processing, rate limiting.

## 2.4 GHz Coexistence and Cross-Technology Interference

5. IEEE 802.15.4-2020. "Low-Rate Wireless Personal Area Networks." IEEE Standards, 2020.
   - Zigbee/BLE physical layer, coexistence mechanisms.

6. Bluetooth SIG. "Bluetooth Core Specification v5.4." 2023.
   - BLE advertising, connection management, frequency hopping.

7. Nordic Semiconductor. "nRF24L01+ Product Specification." 2020.
   - 2.4 GHz proprietary protocol, addressing, auto-ack.

8. IEEE 802.11-2020. "Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications." 2020.
   - Wi-Fi coexistence, CCA, ED threshold.

## Side-Channel and Power Analysis (Context)

9. Mangard, S. et al. "Power Analysis Attacks: Revealing the Secrets of Smart Cards." Springer, 2007.
   - CPA/DPA theory, leakage models, countermeasures.

10. XTS-AES Specification. NIST SP 800-38E. "Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Block-Oriented Storage Devices." 2010.
    - XTS-AES construction, tweakable block cipher, storage encryption context.

## Legal and Regulatory

11. Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
12. Wiretap Act, 18 U.S.C. § 2511.
13. FCC Part 15 Rules — Unlicensed 2.4 GHz Operation.
14. EU GDPR (Regulation 2016/679) — Data Protection.
