# Domain glossary

## Gateway vs. client

**Gateway** (`ICertificationAuthorityGateway`) is the seam a controller talks to: submit, retrieve, CA
metadata, revoke, and the CA-management permission check. One call per HTTP request's concern.

**Client** (`ICertAdminClient`) is a narrower seam *inside* the gateway's production implementation
(`ComCertificationAuthorityGateway`), wrapping only the late-bound `ICertAdmin`/`ICertAdmin2` COM calls
(revocation, reading the CA's own security descriptor). It exists because those calls had no seam narrower
than the whole gateway, so nothing could unit-test them - see the "Give the ICertAdmin2 calls a seam of their
own" architecture review candidate (2026-09-03) for the full history (three production bugs, each caught only
by a live AD CS server).

Don't use "gateway" and "client" interchangeably - a caller talks to the gateway; the gateway talks to the
client for CA-administration calls specifically, and directly to `CCertRequest` (CERTCLILib) for everything
else.

## Two permission mechanisms

A certification authority's permissions live in two unrelated places, checked two different ways - conflating
them was a real, shipped bug (commit `33872ae`):

- **Enroll** ("Request Certificates") - published to the `pKIEnrollmentService` object in Active Directory, as
  an `ObjectAce` keyed by the Enroll extended-right GUID. Checked by `EnrollmentPermission`, sourced from
  `ICertificationAuthorityDirectory`'s AD lookup - no DCOM call needed.
- **CA management** ("Issue and Manage Certificates", "Manage CA", "Read") - lives only on the certification
  authority itself (the `Security` entry of its own configuration root), as a `CommonAce` access-mask bit.
  Checked by `CertificateManagementPermission`, sourced from `ICertAdminClient.GetCaSecurityDescriptor` - a
  live, impersonated DCOM call, not an AD lookup.
