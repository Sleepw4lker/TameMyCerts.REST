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

using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Talks to a certification authority's administrative COM interfaces (ICertAdmin/ICertAdmin2), for
///     revocation and reading the CA's own security descriptor. Callers are expected to already be running
///     under the impersonated identity whose permissions the certification authority should apply - this
///     client itself does not impersonate.
/// </summary>
public interface ICertAdminClient
{
    /// <summary>
    ///     Revokes a previously issued certificate.
    /// </summary>
    void RevokeCertificate(string configString, string serialNumber, RevocationReason reason, DateTime date);

    /// <summary>
    ///     Retrieves the certification authority's own security descriptor - the "Security" entry of its
    ///     configuration root, which carries CA security permissions (Manage CA / Issue and Manage
    ///     Certificates / Read). This is a different security descriptor from the pKIEnrollmentService Active
    ///     Directory object's, which only carries enrollment permissions.
    /// </summary>
    byte[] GetCaSecurityDescriptor(string configString);
}
