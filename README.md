## Mosdns-x PR (Privacy & Resilience)

Mosdns-x is a high-performance DNS forwarder written in Go. It features a plugin pipeline architecture, allowing users to customize DNS processing logic for any specific use case.

This version is a fork based on [pmkol/mosdns-x](https://github.com/pmkol/mosdns-x) and incorporates significant improvements and commits from [BaeKey/mosdns-x](https://github.com/BaeKey/mosdns-x), with a primary focus on privacy and connection resilience.

**Supported Protocols (Inbound & Outbound):**

* UDP and TCP
* DNS over TLS (DoT)
* DNS over QUIC (DoQ)
* DNS over HTTP/2 (DoH)
* DNS over HTTP/3 (DoH3)

For features, configuration guides, and tutorials, visit the [Wiki](https://github.com/pmkol/mosdns-x/wiki).

---

### Platform upgrade

* Update Go and all dependencies to the latest versions to improve performance, security, and stability.

### Server

* **Native processing at the server level**: pre-processing steps are now performed directly at the server instead of through plugins:
  * Strip EDNS0
  * Block ANY / AAAA / PTR / HTTPS
  * Domain validation
  * Lowercase conversion

* **Efficiency**: server-level processing reduces overhead by eliminating the need to create contexts for plugins, minimizing intermediate steps and decreasing overall latency.
* **Configuration options**: added options to filter queries at the earliest stage:
  * `block_aaaa`: false
  * `block_ptr`: true
  * `block_https`: true
  * `block_no_dot`: true
  * `strip_edns0`: true

* **Protocols**: all protocols including TCP, UDP, DoH, DoH3, DoT, and DoQ have been adjusted and optimized, focusing on performance and stability.
* **Health check and redirect**:
  * Add `health_path` to provide an endpoint for monitoring uptime.
  * Add `redirect_url`: automatically redirect non-DNS requests (excluding `health_path` and `/dns-query`) to a custom URL.

* **Security and privacy**:
  * `allowed_sni` inspects the SNI during the TLS handshake to filter unauthorized bots and scanners. blocked requests are excluded from logs.
  * The system has completely disabled client IP logging to ensure anonymity, even when logging is enabled.

### SSL

* **Connection speed**: improved reconnection capability after server restarts. keys are stored at `key/.mosdns_stateless_reset.key` to support 0-RTT and TLS session resumption.
* **Encryption algorithms**: utilize X25519 and ECDSA (P-256). this solution consumes less CPU and generates much smaller certificates compared to Post-Quantum (ML-KEM/Kyber).
* **Compression and packet optimization**:
  * Support certificate compression using Brotli if the client supports it.
  * Compress DNS packets before sending them to the client.

### Cache

* **Uint64 hashing**: use `GetMsgHash` to create 8-byte cache keys for faster lookups.
* **Pre-allocated memory**: the entire map is pre-allocated at startup based on the `size` parameter. it does not expand during runtime, ensuring stable RAM usage.
* **Zero allocation path**: when the `size` limit is reached, the system reuses existing elements instead of allocating new ones. this mechanism eliminates GC overhead and prevents RAM spikes under high traffic.
* **Lazy cache**: streamlined internal logic and removed redundant processing.
* **New options**: add `cleaner_interval` to customize cache key cleanup timing. support NXDOMAIN caching.
* **Data structure optimization**: improved `concurrent_lru`, `list`, and `lru` for more efficient cache storage and deletion in concurrent environments.

### ECS

* **Operational mechanism**: ECS is only processed at the location of the `ecs` plugin in the `.yaml` file. there is no longer a default global caching mechanism.
* **ECS normalization**: IPs in the same range (e.g., 1.2.3.4 and 1.2.3.5) are unified to `1.2.3.0/24` to ensure cache accuracy and prevent fragmentation.

### Upstream and Matcher

* **Upstream**: defaults to parallel logic and is optimized for DoH and DoT.
* **Matcher**: `response_matcher` and `query_matcher` have been rewritten for better processing efficiency.

### Plugin

* **General modifications**: most plugins have removed validation steps since they are now handled at the server level, reducing overall system latency.
* **Redirect**: removes CNAME but keeps A/AAAA according to the original query name, consistent with `_no_cname` logic.
* **Limit_ip**: limits the DNS response to a maximum of 2 IP addresses per query.
* **Dynamic_domain_collector**: automatically reads and writes domains to a file.
* **Query_summary**: disables client IP logging and limits logging of minor errors at the info level.

---

### Community and Resources

* **Telegram:** [Mosdns-x Group](https://t.me/mosdns)

### Related Projects

* **[pmkol/mosdns-x](https://github.com/pmkol/mosdns-x):** The base project for this high-performance DNS forwarder.
* **[BaeKey/mosdns-x](https://github.com/BaeKey/mosdns-x):** Key contributor to the enhanced features and logic implemented in this version.
* **[easymosdns](https://github.com/pmkol/easymosdns):** A Linux helper script to deploy ECS-supported, clean DNS servers quickly.
* **[mosdns-v4](https://github.com/IrineSistiana/mosdns/tree/v4):** The upstream project providing the modular plugin-based forwarder architecture.
