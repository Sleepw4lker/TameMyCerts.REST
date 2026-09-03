// Copyright (c) Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace TameMyCerts.REST.Models;

/// <summary>
///     Certificate revocation reason codes, as defined by RFC 5280 section 5.3.1 (CRLReason). Note that the
///     value 7 is intentionally not assigned to anything, matching the RFC.
/// </summary>
public enum RevocationReason
{
    /// <summary>
    ///     No reason given.
    /// </summary>
    Unspecified = 0,

    /// <summary>
    ///     The certificate's private key is suspected to have been compromised.
    /// </summary>
    KeyCompromise = 1,

    /// <summary>
    ///     The certification authority's private key is suspected to have been compromised.
    /// </summary>
    CaCompromise = 2,

    /// <summary>
    ///     The subject's name or other information in the certificate has changed.
    /// </summary>
    AffiliationChanged = 3,

    /// <summary>
    ///     The certificate has been superseded by another one.
    /// </summary>
    Superseded = 4,

    /// <summary>
    ///     The certificate is no longer needed for the purpose for which it was issued.
    /// </summary>
    CessationOfOperation = 5,

    /// <summary>
    ///     The certificate is temporarily on hold. Revoking again with RemoveFromCrl reverses this.
    /// </summary>
    CertificateHold = 6,

    /// <summary>
    ///     Removes a certificate previously revoked with CertificateHold from the CRL.
    /// </summary>
    RemoveFromCrl = 8,

    /// <summary>
    ///     An authority-granted privilege described by the certificate is suspected to have been compromised or
    ///     is no longer valid.
    /// </summary>
    PrivilegeWithdrawn = 9,

    /// <summary>
    ///     The attribute authority's private key is suspected to have been compromised.
    /// </summary>
    AaCompromise = 10
}
