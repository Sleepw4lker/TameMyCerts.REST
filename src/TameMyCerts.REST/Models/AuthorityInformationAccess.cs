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
///     A data structure containing authority information access for a certification authority.
/// </summary>
public class AuthorityInformationAccess
{
    /// <summary>
    ///     Initiates an AuthorityInformationAccess object.
    /// </summary>
    public AuthorityInformationAccess(List<string> urls, List<string> ocspUrls, string certificate)
    {
        Urls = urls;
        OcspUrls = ocspUrls;
        Certificate = certificate;
    }

    /// <summary>
    ///     A collection of authority information access urls that are available for the certification authority certificate.
    /// </summary>
    public List<string> Urls { get; }

    /// <summary>
    ///     A collection of available online certificate status protocol urls.
    /// </summary>
    public List<string> OcspUrls { get; }

    /// <summary>
    ///     The PKIX certification authority certificate.
    /// </summary>
    public string Certificate { get; }
}