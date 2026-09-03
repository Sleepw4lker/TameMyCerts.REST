// Copyright © Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CERTENROLLLib;
using TameMyCerts.NetCore.Common.Enums;

namespace TameMyCerts.NetCore.Common.ClassExtensions;

internal static class CX509CertificateRequestPkcs10Extensions
{
    public static Dictionary<string, byte[]> GetRequestExtensions(
        this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
    {
        var extensionList = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

        for (var i = 0; i < certificateRequestPkcs10.X509Extensions.Count; i++)
        {
            extensionList.Add(certificateRequestPkcs10.X509Extensions[i].ObjectId.Value,
                Convert.FromBase64String(certificateRequestPkcs10.X509Extensions[i]
                    .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)));
        }

        return extensionList;
    }

    public static bool TryInitializeFromInnerRequest(this IX509CertificateRequestPkcs10 certificateRequestPkcs10,
        string certificateRequest, int requestType)
    {
        switch (requestType)
        {
            case CertCli.CR_IN_CMC:

                var certificateRequestCmc =
                    (IX509CertificateRequestCmc)Activator.CreateInstance(
                        Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCmc"));

                try
                {
                    certificateRequestCmc.InitializeDecode(certificateRequest,
                        EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

                    var innerRequest = certificateRequestCmc.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                    certificateRequest = innerRequest.get_RawData();
                }
                catch
                {
                    return false;
                }
                finally
                {
                    Marshal.ReleaseComObject(certificateRequestCmc);
                }

                break;

            case CertCli.CR_IN_PKCS7:

                var certificateRequestPkcs7 =
                    (IX509CertificateRequestPkcs7)Activator.CreateInstance(
                        Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs7"));

                try
                {
                    certificateRequestPkcs7.InitializeDecode(certificateRequest,
                        EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

                    var innerRequest = certificateRequestPkcs7.GetInnerRequest(InnerRequestLevel.LevelInnermost);
                    certificateRequest = innerRequest.get_RawData();
                }
                catch
                {
                    return false;
                }
                finally
                {
                    Marshal.ReleaseComObject(certificateRequestPkcs7);
                }

                break;
        }

        try
        {
            certificateRequestPkcs10.InitializeDecode(certificateRequest, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public static string GetSubjectDistinguishedName(this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
    {
        try
        {
            return certificateRequestPkcs10.Subject.Name;
        }
        catch
        {
            // Subject DN is empty
            return string.Empty;
        }
    }

    public static Oid GetCertificateTemplateOid(this IX509CertificateRequestPkcs10 certificateRequestPkcs10)
    {
        var extensionList = certificateRequestPkcs10.GetRequestExtensions();

        if (!extensionList.ContainsKey(WinCrypt.szOID_CERTIFICATE_TEMPLATE))
        {
            return null;
        }

        var templateExtension = new CX509ExtensionTemplate();
        templateExtension.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64,
            Convert.ToBase64String(extensionList[WinCrypt.szOID_CERTIFICATE_TEMPLATE]));

        var templateOid = new Oid(templateExtension.TemplateOid.Value);
        Marshal.ReleaseComObject(templateExtension);
        return templateOid;
    }
}