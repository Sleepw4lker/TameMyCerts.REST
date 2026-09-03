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

using System.DirectoryServices;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Looks up certification authorities registered in Active Directory (pKIEnrollmentService objects).
/// </summary>
public sealed class ActiveDirectoryCertificationAuthorityDirectory : ICertificationAuthorityDirectory
{
    /// <inheritdoc />
    public CertificationAuthority? FindByName(string caName, bool textualEncoding = false)
    {
        var searchResults = ActiveDirectory.GetEnrollmentServiceCollection(caName);

        return searchResults.Count == 1 ? BuildFromSearchResult(searchResults[0], textualEncoding) : null;
    }

    /// <inheritdoc />
    public IReadOnlyList<CertificationAuthority> GetAll(bool textualEncoding = false)
    {
        var searchResults = ActiveDirectory.GetEnrollmentServiceCollection();

        return (from SearchResult searchResult in searchResults
            select BuildFromSearchResult(searchResult, textualEncoding)).ToList();
    }

    private static CertificationAuthority BuildFromSearchResult(SearchResult searchResult, bool textualEncoding)
    {
        var name = (string)searchResult.Properties["cn"][0];

        var certificateTemplates =
            (from object certificateTemplate in searchResult.Properties["certificateTemplates"]
                select certificateTemplate.ToString()).ToList();

        return new CertificationAuthority(
            name,
            (string)searchResult.Properties["dNSHostName"][0],
            (byte[])searchResult.Properties["cACertificate"][0],
            certificateTemplates!,
            (byte[])searchResult.Properties["ntSecurityDescriptor"][0],
            textualEncoding);
    }
}
