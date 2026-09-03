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
using TameMyCerts.NetCore.Common.Enums;

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Information about a certificate template.
/// </summary>
public class CertificateTemplate : IEnrollmentSubject
{
    private readonly EnrollmentPermission _enrollmentPermission;

    /// <summary>
    ///     Builds the certificate template from already-resolved values.
    /// </summary>
    public CertificateTemplate(
        string name,
        string displayName,
        int minimumKeyLength,
        int majorVersion,
        int minorVersion,
        int schemaVersion,
        string objectIdentifier,
        List<string> keyStorageProviders,
        TimeSpan validityPeriod,
        TimeSpan renewalOverlap,
        bool enrolleeSuppliesSubject,
        KeyUsageExtension keyUsageExtension,
        ExtendedKeyUsageExtension extendedKeyUsageExtension,
        KeyAlgorithmType keyAlgorithm,
        byte[] rawSecurityDescriptor)
    {
        Name = name;
        DisplayName = displayName;
        MinimumKeyLength = minimumKeyLength;
        MajorVersion = majorVersion;
        MinorVersion = minorVersion;
        SchemaVersion = schemaVersion;
        ObjectIdentifier = objectIdentifier;
        KeyStorageProviders = keyStorageProviders;
        ValidityPeriod = validityPeriod;
        RenewalOverlap = renewalOverlap;
        EnrolleeSuppliesSubject = enrolleeSuppliesSubject;
        KeyUsageExtension = keyUsageExtension;
        ExtendedKeyUsageExtension = extendedKeyUsageExtension;
        KeyAlgorithm = keyAlgorithm;
        _enrollmentPermission = new EnrollmentPermission(rawSecurityDescriptor);
    }

    /// <summary>
    ///     The common name of the certificate template. Use this when submitting certificate requests.
    /// </summary>
    public string Name { get; }

    /// <summary>
    ///     The display name of the certificate template.
    /// </summary>
    public string DisplayName { get; }

    /// <summary>
    ///     The object identifier of the certificate template.
    /// </summary>
    public string ObjectIdentifier { get; }

    /// <summary>
    ///     Specifies if the enrollee may provide subject information with the certificate request.
    /// </summary>
    public bool EnrolleeSuppliesSubject { get; }

    /// <summary>
    ///     Specifies the key algorithm the certificate will be signed with.
    /// </summary>
    public KeyAlgorithmType KeyAlgorithm { get; }

    /// <summary>
    ///     The minimum accepted key length of the certificate template.
    /// </summary>
    public int MinimumKeyLength { get; }

    /// <summary>
    ///     The validity period of issued certificates for this certificate template.
    /// </summary>
    public TimeSpan ValidityPeriod { get; }

    /// <summary>
    ///     The desired renewal overlap period for this certificate template.
    /// </summary>
    public TimeSpan RenewalOverlap { get; }

    /// <summary>
    ///     Contains a list of the preferred key storage providers for this certificate template.
    /// </summary>
    public List<string> KeyStorageProviders { get; }

    /// <summary>
    ///     The major version of the certificate template.
    /// </summary>
    public int MajorVersion { get; }

    /// <summary>
    ///     The minor version of the certificate template.
    /// </summary>
    public int MinorVersion { get; }

    /// <summary>
    ///     The Active Directory schema version of the certificate template.
    /// </summary>
    public int SchemaVersion { get; }

    /// <summary>
    ///     Information about the key usage extension of the certificate template.
    /// </summary>
    public KeyUsageExtension KeyUsageExtension { get; }

    /// <summary>
    ///     Information about the extended key usage extension of the certificate template.
    /// </summary>
    public ExtendedKeyUsageExtension ExtendedKeyUsageExtension { get; }

    /// <summary>
    ///     Determines whether a given WindowsIdentity may enroll for this certificate template.
    /// </summary>
    /// <param name="identity">The Windows identity to check for permissions.</param>
    /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
    public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
    {
        return _enrollmentPermission.AllowsForEnrollment(identity, explicitlyPermitted);
    }
}
