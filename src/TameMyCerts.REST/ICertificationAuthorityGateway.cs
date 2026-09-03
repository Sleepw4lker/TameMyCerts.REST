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

using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Talks to a certification authority on behalf of the API. Submission and retrieval happen under
///     the impersonated identity of the enrolling user, so the certification authority applies that
///     user's own enrollment permissions; the read-only CA metadata calls do not impersonate.
/// </summary>
public interface ICertificationAuthorityGateway
{
    /// <summary>
    ///     Retrieves a previously submitted certificate request from a certification authority.
    /// </summary>
    SubmissionResponse RetrievePending(string configString, int requestId, WindowsIdentity identity,
        bool textualEncoding = false);

    /// <summary>
    ///     Submits a certificate request to a certification authority.
    /// </summary>
    SubmissionResponse Submit(string configString, string rawCertificateRequest, List<string> requestAttributes,
        int submissionFlags, WindowsIdentity identity, bool textualEncoding = false);

    /// <summary>
    ///     Retrieves the CA or CA exchange certificate of a certification authority.
    /// </summary>
    SubmissionResponse GetCaCertificate(string configString, bool textualEncoding = false,
        bool caExchangeCertificate = false);

    /// <summary>
    ///     Retrieves certificate revocation list distribution point information from a certification authority.
    /// </summary>
    CertificateRevocationListDistributionPointCollection GetCrlDpCollection(string configString,
        bool textualEncoding = false);

    /// <summary>
    ///     Retrieves authority information access information from a certification authority.
    /// </summary>
    AuthorityInformationAccessCollection GetAiaCollection(string configString, bool textualEncoding = false);

    /// <summary>
    ///     Revokes a previously issued certificate. Runs under the impersonated identity of the caller, so the
    ///     certification authority applies that user's own CA management permissions - a separate permission
    ///     from the "Request Certificates" (Enroll) right the other impersonated calls rely on.
    /// </summary>
    void RevokeCertificate(string configString, string serialNumber, RevocationReason reason,
        WindowsIdentity identity);
}
