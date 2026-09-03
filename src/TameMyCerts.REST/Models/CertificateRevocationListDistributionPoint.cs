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
///     A data structure containing certificate revocation list distribution point information for a certification
///     authority.
/// </summary>
public class CertificateRevocationListDistributionPoint
{
    /// <summary>
    ///     Initiates a CertificateRevocationListDistributionPoint object.
    /// </summary>
    public CertificateRevocationListDistributionPoint(List<string> urls, string certificateRevocationList)
    {
        Urls = urls;
        CertificateRevocationList = certificateRevocationList;
    }

    /// <summary>
    ///     A collection of addresses under which the CRL is distributed by the certification authority.
    /// </summary>
    public List<string> Urls { get; }

    /// <summary>
    ///     The PKIX certificate revocation list.
    /// </summary>
    public string CertificateRevocationList { get; }
}