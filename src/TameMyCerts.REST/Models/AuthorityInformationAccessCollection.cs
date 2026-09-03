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
///     Contains a list of authority information access distribution points.
/// </summary>
public class AuthorityInformationAccessCollection
{
    /// <summary>
    ///     Builds the collection out of a given list of authority information access distribution points.
    /// </summary>
    public AuthorityInformationAccessCollection(List<AuthorityInformationAccess> authorityInformationAccess)
    {
        AuthorityInformationAccess = authorityInformationAccess;
    }

    /// <summary>
    ///     Contains a list of authority information access distribution points.
    /// </summary>
    public List<AuthorityInformationAccess> AuthorityInformationAccess { get; }
}