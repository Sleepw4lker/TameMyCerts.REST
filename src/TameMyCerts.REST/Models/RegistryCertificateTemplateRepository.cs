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

using Microsoft.Win32;
using TameMyCerts.NetCore.Common.Enums;

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Looks up certificate templates from the machine's local certificate template cache registry key.
/// </summary>
public sealed class RegistryCertificateTemplateRepository : ICertificateTemplateRepository
{
    private const string CertificateTemplateCacheKey = "SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache";

    private static readonly string[] DefaultVersion2CertificateTemplates =
    [
        "CAExchange",
        "CrossCA",
        "DirectoryEmailReplication",
        "DomainControllerAuthentication",
        "KerberosAuthentication",
        "KeyRecoveryAgent",
        "OCSPResponseSigning",
        "RASAndIASServer",
        "Workstation"
    ];

    /// <inheritdoc />
    public CertificateTemplate? FindByName(string templateName)
    {
        using var templateBaseKey = OpenTemplateCacheKey();
        using var templateSubKey = templateBaseKey?.OpenSubKey(templateName);

        return templateSubKey is null ? null : BuildFromRegistry(templateName, templateSubKey);
    }

    /// <inheritdoc />
    public IReadOnlyList<CertificateTemplate> GetAll()
    {
        using var templateBaseKey = OpenTemplateCacheKey();

        if (templateBaseKey is null)
        {
            return [];
        }

        return templateBaseKey.GetSubKeyNames()
            .Where(templateName => !DefaultVersion2CertificateTemplates.Contains(templateName))
            .Select(FindByName)
            .OfType<CertificateTemplate>()
            .Where(certificateTemplate => certificateTemplate.SchemaVersion > 1)
            .ToList();
    }

    private static RegistryKey? OpenTemplateCacheKey()
    {
        var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return machineBaseKey.OpenSubKey(CertificateTemplateCacheKey);
    }

    private static CertificateTemplate BuildFromRegistry(string templateName, RegistryKey regKey)
    {
        var criticalExtensions = (string[])regKey.GetValue("CriticalExtensions")!;

        var applicationPoliciesValueData = (string[])regKey.GetValue("msPKI-RA-Application-Policies")!;

        var keyAlgorithm = applicationPoliciesValueData.Length > 0
            ? GetKeyAlgorithm(applicationPoliciesValueData[0])
            : KeyAlgorithmType.RSA;

        var enrolleeSuppliesSubject =
            (CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT &
             Convert.ToInt32(regKey.GetValue("msPKI-Certificate-Name-Flag"))) ==
            CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;

        return new CertificateTemplate(
            name: templateName,
            displayName: (string)regKey.GetValue("DisplayName")!,
            minimumKeyLength: (int)regKey.GetValue("msPKI-Minimal-Key-Size")!,
            majorVersion: (int)regKey.GetValue("Revision")!,
            minorVersion: (int)regKey.GetValue("msPKI-Template-Minor-Revision")!,
            schemaVersion: (int)regKey.GetValue("msPKI-Template-Schema-Version")!,
            objectIdentifier: ((string[])regKey.GetValue("msPKI-Cert-Template-OID")!)[0],
            keyStorageProviders: ((string[])regKey.GetValue("SupportedCSPs")!).ToList(),
            validityPeriod: PkiPeriodToTimeSpan((byte[])regKey.GetValue("ValidityPeriod")!),
            renewalOverlap: PkiPeriodToTimeSpan((byte[])regKey.GetValue("RenewalOverlap")!),
            enrolleeSuppliesSubject: enrolleeSuppliesSubject,
            keyUsageExtension: new KeyUsageExtension((byte[])regKey.GetValue("KeyUsage")!,
                criticalExtensions.Contains(WinCrypt.szOID_KEY_USAGE)),
            extendedKeyUsageExtension: new ExtendedKeyUsageExtension((string[])regKey.GetValue("ExtKeyUsageSyntax")!,
                criticalExtensions.Contains(WinCrypt.szOID_ENHANCED_KEY_USAGE) ||
                criticalExtensions.Contains(WinCrypt.szOID_APPLICATION_CERT_POLICIES)),
            keyAlgorithm: keyAlgorithm,
            rawSecurityDescriptor: (byte[])regKey.GetValue("Security")!);
    }

    private static KeyAlgorithmType GetKeyAlgorithm(string keyAlgorithmString)
    {
        foreach (var algorithmName in Enum.GetNames(typeof(KeyAlgorithmType)))
        {
            if (keyAlgorithmString.Contains($"msPKI-Asymmetric-Algorithm`PZPWSTR`{algorithmName}`"))
            {
                return (KeyAlgorithmType)Enum.Parse(typeof(KeyAlgorithmType), algorithmName);
            }
        }

        return KeyAlgorithmType.RSA;
    }

    private static TimeSpan PkiPeriodToTimeSpan(byte[] value)
    {
        var period = BitConverter.ToInt64(value, 0);
        period /= -10000000;
        return TimeSpan.FromSeconds(period);
    }
}
