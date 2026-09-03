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

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Information about the extended key usage extension of the certificate template.
/// </summary>
public class ExtendedKeyUsageExtension
{
    /// <summary>
    ///     Builds an EnhancedKeyUsageExtension out of a given list of object identifiers.
    /// </summary>
    /// <param name="extendedKeyUsages">The list of object identifiers to build the object from.</param>
    /// <param name="critical">Indicates whether the extension is critical or not.</param>
    public ExtendedKeyUsageExtension(IEnumerable<string> extendedKeyUsages, bool critical)
    {
        Critical = critical;
        ExtendedKeyUsages = (from string extendedKeyUsage in extendedKeyUsages
                select new ExtendedKeyUsage(extendedKeyUsage))
            .OrderBy(extendedKeyUsage => extendedKeyUsage.FriendlyName).ToList();
    }

    /// <summary>
    ///     Indicates whether the extension is critical or not.
    /// </summary>
    public bool Critical { get; }

    /// <summary>
    ///     A list of extended key usages of the certificate template.
    /// </summary>
    public List<ExtendedKeyUsage> ExtendedKeyUsages { get; }
}