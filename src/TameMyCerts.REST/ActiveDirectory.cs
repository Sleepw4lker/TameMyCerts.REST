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

namespace TameMyCerts.REST;

/// <summary>
///     A class holding methods that help acquiring PKI related information from Active Directory.
/// </summary>
public static class ActiveDirectory
{
    /// <summary>
    ///     Returns a SearchResultCollection holding pKIEnrollmentService objects found in the directory.
    /// </summary>
    /// <param name="cn">Common name of a specific ca.</param>
    /// <returns></returns>
    public static SearchResultCollection GetEnrollmentServiceCollection(string cn = null)
    {
        var forestRootDomain = new DirectoryEntry("LDAP://RootDSE").Properties["rootDomainNamingContext"][0].ToString();

        var additionalCriteria = string.Empty;

        if (cn != null)
        {
            additionalCriteria += $"(cn={cn})";
        }

        var enrollmentContainer =
            $"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{forestRootDomain}";

        var directoryEntry = new DirectoryEntry(enrollmentContainer);

        var directorySearcher = new DirectorySearcher(directoryEntry)
        {
            Filter = $"(&{additionalCriteria}(objectCategory=pKIEnrollmentService))",
            Sort = new SortOption("cn", SortDirection.Ascending),
            PropertiesToLoad =
                { "cn", "certificateTemplates", "dNSHostName", "cACertificate", "ntSecurityDescriptor" },
            SecurityMasks = SecurityMasks.Dacl
        };

        return directorySearcher.FindAll();
    }
}