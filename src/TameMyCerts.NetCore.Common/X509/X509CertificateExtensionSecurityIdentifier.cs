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

using System.Security.Principal;
using System.Text;

namespace TameMyCerts.NetCore.Common.X509;

/// <summary>
///     Builds the Active Directory security identifier (szOID_NTDS_CA_SECURITY_EXT, 1.3.6.1.4.1.311.25.2)
///     X.509 certificate extension.
/// </summary>
public class X509CertificateExtensionSecurityIdentifier : X509CertificateExtension
{
    /// <summary>
    ///     Builds the extension from the given security identifier.
    /// </summary>
    /// <param name="sid">The Active Directory security identifier of the certificate's subject.</param>
    public X509CertificateExtensionSecurityIdentifier(SecurityIdentifier sid)
    {
        var result = Encoding.ASCII.GetBytes(sid.ToString());

        result = Asn1BuildNode(0x04, result);
        result = Asn1BuildNode(0xA0, result);
        result = new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01 }
            .Concat(result).ToArray();
        result = Asn1BuildNode(0xA0, result);
        result = Asn1BuildNode(0x30, result);

        RawData = result;
    }
}