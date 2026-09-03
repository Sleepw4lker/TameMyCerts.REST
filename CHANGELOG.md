## Changelog for the TameMyCerts REST API

### Version 1.2.1341.391

_This version was released on Sep 03, 2026._

- Upgrade to .NET 10
- Replace all occurrences of HTTP 403 (Forbidden) errors with HTTP 401 (Unauthorized) (#3)
- Add certificate revocation endpoint (`POST v1/certificates/{caName}/revoke`), enforcing "Issue and Manage Certificates" permission on the certification authority

### Version 1.1.351.835

_This version was released on Dec 18, 2023._

- Migrate from .NET Framework 4.7.2 to .NET Core 8.0. Therefore also using OpenAPI 3.0 now.
- Implement support for the digital signature (DSA) algorithm.

### Version 1.0.345.1164

_This version was released on Dec 12, 2023._

This is the initial release made publicly available.