# SGKMS API Stress Testing Report

## Overview
This document summarizes the results of stress testing conducted on the SGKMS API to evaluate performance, capacity, and potential bottlenecks under varying user loads and payload sizes.

## Objectives
- **Max Capacity**: Identify maximum transactions per second (TPS) while maintaining stability.
- **Stability & Resilience**: Assess API reliability under high concurrent loads.
- **Bottleneck Identification**: Determine load and payload points that lead to latency and error rate spikes.

## Scope of Testing
- **API Functions**: MAC Generate (CMAC, GMAC-256, HMAC-SHA256), Encrypt (AES, RSA), Seal Data, Get Secret, Tokenize Data, and Sign (ECDSA, RSA).
- **Test Range**: Concurrent users from 10 to 3000, payload sizes from 0.1 KB to 50 KB.

## Key Findings
- **Max TPS**: Achieved a peak of 382.96 TPS; throughput declined as user load increased.
- **Latency**: Average latency spiked above 1000 concurrent users. Maximum latency (542,688.92 ms) observed at 3000 users.
- **Error Rates**: Significant error rate increase observed above 1000 users and for payloads larger than 20 KB.
- **Anomalies**:
  - **MAC Generation (CMAC)**: Higher initial error rates due to network configuration (Wi-Fi); resolved with LAN connection.
  - **Encrypt (RSA, no session key)**: Persistent error rates under high load, likely due to configuration inefficiencies.

## Testing Methodology
- **Load Simulation**: Custom JavaScript scripts to vary user loads and measure performance.
- **Metrics**: Latency (average and max), TPS, and error rates captured for analysis.

## Analysis & Insights
- **Latency Trends**: Spikes observed with high user loads, especially beyond 1000 users.
- **Throughput**: Max TPS reached at lower payload sizes; significant drop for payloads above 20 KB.
- **Error Patterns**: Increased with both high user loads and larger payload sizes.

## Recommendations
- **Code Optimization**: Enhance algorithm and process efficiency.
- **Hardware Scaling**: Upgrade CPU, memory, and network bandwidth to support higher loads.
- **Resource Management**: Implement load balancing and user throttling for peak demands.

## Visualizations
- **Latency and Throughput Charts**: Available in [Visualization Links].
- **Error Rate and Latency Heat Maps**: Insights into performance by API function and load level.

## Full Data Access
- **Dataset**: Full testing dataset available for download [here](#link-to-dataset).
- **Dashboard Links**:
  - [Error Rate Analysis](#link1)
  - [Heat Map of Maximum Latency](#link2)
  - [Throughput vs. Latency at Max Load](#link3)
  - [Latency Analysis](#link4)
  - [Throughput Analysis](#link5)

---

## Appendix
For detailed API function specifications, refer to the **API Operation Table** below.

| API Operation | Algorithm                | Key Length       | Additional Parameters            |
|---------------|--------------------------|------------------|----------------------------------|
| MAC Generation | CMAC, GMAC-256, HMAC-SHA256 | N/A              | Hash Algorithm Selection         |
| Encrypt       | AES                      | 256-bit          | -                                |
| Encrypt       | RSA                      | 2048, 3072, 4096-bit | Option for Session Key         |
| Seal Data     | AES, RSA                 | 256-bit, 2048+ bit | -                             |
| Get Secret    | N/A                      | N/A              | Retrieve secure secret          |
| Tokenize      | N/A                      | N/A              | Convert sensitive data to token |
| Sign          | ECDSA, RSA               | N/A              | -                                |

---

**Disclaimer**: For a complete performance analysis, please refer to the full [Stress Test Results CSV](#link-to-dataset) and visualizations.
