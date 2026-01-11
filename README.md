## Mosdns-x PR (Privacy & Resilience)

Mosdns-x is a high-performance DNS forwarder written in Go. It features a plugin pipeline architecture, allowing users to customize DNS processing logic for any specific use case.

This version is a fork based on [pmkol/mosdns-x](https://github.com/pmkol/mosdns-x), focusing on privacy enhancements and connection resilience.

**Supported Protocols (Inbound & Outbound):**

* UDP and TCP
* DNS over TLS (DoT)
* DNS over QUIC (DoQ)
* DNS over HTTP/2 (DoH)
* DNS over HTTP/3 (DoH3)

For features, configuration guides, and tutorials, visit the [Wiki](https://github.com/pmkol/mosdns-x/wiki).

---

### New Features and Enhancements

**Resilience (Connection & Performance)**

* Improved reconnection speed after server restarts for all encrypted DNS protocols.
* **DoH3/DoQ:** Reconnection time reduced from 3-5 seconds to under 100ms.
* **DoH/DoT:** Reconnection time reduced from 500-700ms to 200-300ms.
* Persistent session keys stored in `key/.mosdns_stateless_reset.key` enable 0-RTT and TLS Session Resumption across restarts.
* Added a `/health` endpoint for lightweight uptime monitoring.

**Privacy and Security**

* Disabled client IP logging to ensure user anonymity, even when logs are active.
* Added `allowed_sni` validation to filter unauthorized scanners and bots during the TLS handshake. Blocked requests are excluded from logs.
* Automated redirection of non-DNS traffic (any path other than `/dns-query`) to a custom landing page.
* DNS responses limited to a maximum of 2 IP addresses per query to reduce payload overhead.

---

### Community and Resources

* **Telegram:** [Mosdns-x Group](https://t.me/mosdns)

### Related Projects

* **[pmkol/mosdns-x](https://github.com/pmkol/mosdns-x):** The base project for this high-performance DNS forwarder.
* **[easymosdns](https://github.com/pmkol/easymosdns):** A Linux helper script to deploy ECS-supported, clean DNS servers quickly.
* **[mosdns-v4](https://github.com/IrineSistiana/mosdns/tree/v4):** The upstream project providing the modular plugin-based forwarder architecture.
