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
///     Looks up certification authorities registered in Active Directory.
/// </summary>
public interface ICertificationAuthorityDirectory
{
    /// <summary>
    ///     Looks up a certification authority by name.
    /// </summary>
    /// <param name="caName">The common name of the certification authority.</param>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    /// <returns><see langword="null" /> if no such certification authority is registered.</returns>
    CertificationAuthority? FindByName(string caName, bool textualEncoding = false);

    /// <summary>
    ///     Retrieves all certification authorities registered in Active Directory.
    /// </summary>
    /// <param name="textualEncoding">
    ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
    /// </param>
    IReadOnlyList<CertificationAuthority> GetAll(bool textualEncoding = false);
}
