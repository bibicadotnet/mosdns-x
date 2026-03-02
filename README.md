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
### Changelog & Updates

* Updated Go and dependencies to the latest versions.
* **Added _DNS_ checks, sanitization, and server-side toggles to reduce overhead by eliminating the need for plugin contexts. This is a critical change: validation happens once at the entry, so subsequent plugins no longer need to re-validate.**
    * ANY queries are always blocked; exactly 1 question required; Opcode = QUERY; Qclass = INET; header must be a pure query.
    * Automatic domain lowercase conversion.
    * Block IPv6 AAAA queries (if `block_aaaa` is enabled).
    * Block PTR reverse queries (if `block_ptr` is enabled).
    * Block HTTPS queries (if `block_https` is enabled).
    * Block domains without dots, e.g., localhost (if `block_no_dot` is enabled).
    * Strip EDNS extensions (if `strip_edns0` is enabled).
* TCP, UDP, DoH, DoH3, DoT, and DoQ protocols have been refined and optimized, focusing on bug fixes, performance, and stability.
* **Health check and redirect:**
    * Added `health_path` to provide an operational status endpoint.
    * Added `redirect_url` to automatically redirect non-DNS requests (except `health_path` and `/dns-query`) to a custom URL.
* **Security and Privacy:**
    * `allowed_sni` validates SNI during the TLS handshake to filter bots and unauthorized scanners; blocked requests are not logged.
    * Completely disabled client IP logging to ensure anonymity, even when logging is turned on.
* **SSL:**
    * Connection speed: improved reconnection after server restarts; keys are stored in the `key` directory to support 0-RTT and TLS session resumption.
    * Encryption algorithms: uses X25519 and ECDSA (P-256), consuming less CPU and producing smaller certificates compared to Post-Quantum (ML-KEM/Kyber).
    * Supports Brotli certificate compression if the client supports it (DoH/DoT only).
    * More accurate `certFile` and `keyFile` checks during renewal.
* Compress DNS packets before sending to clients via `msg_buf`.
* **_Cache_: Major changes from original mosdns-x; `cache_everything` is deprecated in favor of pipeline management. _ECS_ is only processed at the specific _ecs_ plugin location in the YAML.**
    * Uses `GetMsgHash` to create 8-byte cache keys (uint64 hashing), which are smaller and faster.
    * All maps are pre-allocated based on the `size` parameter in the config and do not expand during runtime, keeping RAM usage stable.
    * When the size limit is reached, the system reuses old elements instead of allocating new ones; this mechanism eliminates GC overhead and prevents RAM spikes during high traffic.
    * Lazy cache: rewritten to be simpler, removing redundant processing.
    * Added `cleaner_interval` to allow custom cache key cleanup timing.
    * Supports `NXDOMAIN` caching.
    * Optimized `concurrent_lru`, `list`, and `lru` for more efficient cache storage and deletion.
* **_ECS_**:
    * **_ECS_** Normalization: IPs in the same range like `1.2.3.4` and `1.2.3.5` are converged to `1.2.3.0/24`, ensuring accurate cache hits.
* **Upstream:**
    * Runs in `parallel` when $\ge 2$ upstreams are present.
    * Uses X25519 and ECDSA (P-256), consuming less CPU and producing smaller certificates so it's lighter than Post-Quantum (ML-KEM/Kyber).
* **Matcher:**
    * `response_matcher` and `query_matcher` heavily rewritten for higher processing efficiency.
* **Plugin:** Most plugins have removed validation logic as it's now handled at the server level, reducing overall system latency.
    * `redirect`: removes CNAME but keeps A/AAAA records matching the original query name, synced with the `_no_cname` plugin.
    * `limit_ip`: limits each DNS response to a maximum of 2 IP addresses.
    * `dynamic_domain_collector`: automatically reads and writes domains to files.
    * `query_summary`: disables client IP logging and limits minor errors to info level.
---
### Community and Resources

* **Telegram:** [Mosdns-x Group](https://t.me/mosdns)

### Related Projects

* **[pmkol/mosdns-x](https://github.com/pmkol/mosdns-x):** The base project for this high-performance DNS forwarder.
* **[BaeKey/mosdns-x](https://github.com/BaeKey/mosdns-x):** Key contributor to the enhanced features and logic implemented in this version.
* **[easymosdns](https://github.com/pmkol/easymosdns):** A Linux helper script to deploy ECS-supported, clean DNS servers quickly.
* **[mosdns-v4](https://github.com/IrineSistiana/mosdns/tree/v4):** The upstream project providing the modular plugin-based forwarder architecture.
