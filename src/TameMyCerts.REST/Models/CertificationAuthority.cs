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
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TameMyCerts.NetCore.Common.Models;

namespace TameMyCerts.REST.Models;

/// <summary>
///     A data structure holding information about a certification authority.
/// </summary>
public partial class CertificationAuthority : IEnrollmentSubject
{
    private readonly EnrollmentPermission _enrollmentPermission;

    /// <summary>
    ///     Builds the certification authority from already-resolved values.
    /// </summary>
    /// <param name="name">The common name of the certification authority.</param>
    /// <param name="dnsHostName">The DNS host name of the server hosting the certification authority.</param>
    /// <param name="certificate">The raw current certification authority certificate.</param>
    /// <param name="certificateTemplates">The certificate templates offered by the certification authority.</param>
    /// <param name="rawSecurityDescriptor">The raw security descriptor to determine enrollment permissions from.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    public CertificationAuthority(string name, string dnsHostName, byte[] certificate,
        List<string> certificateTemplates, byte[] rawSecurityDescriptor, bool textualEncoding = false)
    {
        Name = name;
        ConfigurationString = $"{dnsHostName}\\{name}";
        Certificate = GetCertificate(certificate, textualEncoding);
        CertificateTemplates = certificateTemplates;
        CertificateTemplates.Sort();
        _enrollmentPermission = new EnrollmentPermission(rawSecurityDescriptor);
    }

    /// <summary>
    ///     The common name of the certification authority.
    /// </summary>
    public string Name { get; }

    /// <summary>
    ///     The configuration string for this certification authority.
    /// </summary>
    [JsonIgnore]
    public string ConfigurationString { get; }

    /// <summary>
    ///     A list of all certificate templates offered by the certification authority.
    /// </summary>
    public List<string> CertificateTemplates { get; }

    /// <summary>
    ///     The current certification authority certificate of the certification authority.
    /// </summary>
    public string Certificate { get; }

    /// <summary>
    ///     Determines whether a given WindowsIdentity may enroll for certificates from this certification authority.
    /// </summary>
    /// <param name="identity">The Windows identity to check for permissions.</param>
    /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
    public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
    {
        return _enrollmentPermission.AllowsForEnrollment(identity, explicitlyPermitted);
    }

    private static string GetCertificate(byte[] rawData, bool textualEncoding = false)
    {
        var certificate = Convert.ToBase64String(rawData);

        if (!textualEncoding)
        {
            return certificate;
        }

        certificate = Base64EncodedDer().Replace(certificate, "$&\r\n");
        certificate = $"-----BEGIN CERTIFICATE-----\r\n{certificate}\r\n-----END CERTIFICATE-----";

        return certificate;
    }

    [GeneratedRegex(".{64}")]
    private static partial Regex Base64EncodedDer();
}
