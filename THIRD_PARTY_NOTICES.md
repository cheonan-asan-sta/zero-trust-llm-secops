# Third-party notices

The root `LICENSE` (MIT) applies to original code and documentation in this
repository. The three public replay fixtures in `app/data/replay/` retain their
upstream licenses and are **not relicensed** by the root `LICENSE`.

| Fixture | Upstream project | License and local copy |
| --- | --- | --- |
| `splunk-rdp-session-established.xml` | [Splunk Attack Data](https://github.com/splunk/attack_data) | Apache-2.0; [`third_party_licenses/Apache-2.0.txt`](third_party_licenses/Apache-2.0.txt) |
| `splunk-aws-console-login-failures.jsonl` | [Splunk Attack Data](https://github.com/splunk/attack_data) | Apache-2.0; [`third_party_licenses/Apache-2.0.txt`](third_party_licenses/Apache-2.0.txt) |
| `microsoft-sentinel-wiz-audit.json` | [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | MIT, Copyright (c) Microsoft Corporation; [`third_party_licenses/Azure-Sentinel-MIT.txt`](third_party_licenses/Azure-Sentinel-MIT.txt) |

The Splunk excerpts contain four records each. The AWS login excerpt was
format-normalized; the RDP excerpt is a four-record selection. The Microsoft
Sentinel fixture is a formatting-preserving snapshot. Exact source URLs,
immutable revisions, and source/fixture SHA-256 hashes are documented in
[`app/data/replay/manifest.json`](app/data/replay/manifest.json). Further
attribution is in [`app/data/replay/NOTICE.md`](app/data/replay/NOTICE.md).

The test fixtures are public sample data, not live enterprise telemetry.
