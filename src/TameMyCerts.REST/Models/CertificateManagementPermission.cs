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

using System.Security.AccessControl;
using System.Security.Principal;

namespace TameMyCerts.REST.Models;

/// <summary>
///     Decides whether a Windows identity has the "Issue and Manage Certificates" permission on a
///     certification authority (the right that governs revocation, among other CA management operations).
///     This is a different permission from "Request Certificates" (Enroll), which
///     <see cref="EnrollmentPermission" /> checks - and a different kind of ACE: a plain, non-object access
///     mask bit (CA_ACCESS_OFFICER, from certsrv.h) rather than an object ACE tied to an extended-right GUID.
/// </summary>
public sealed class CertificateManagementPermission
{
    private const int CertificateManagementAccessMask = 0x2; // CA_ACCESS_OFFICER

    private readonly List<SecurityIdentifier> _allowedPrincipals = [];
    private readonly List<SecurityIdentifier> _disallowedPrincipals = [];

    /// <summary>
    ///     Parses the "Issue and Manage Certificates" ACEs out of a raw security descriptor.
    /// </summary>
    /// <param name="rawSecurityDescriptor">The ASN.1/binary security descriptor to parse.</param>
    public CertificateManagementPermission(byte[] rawSecurityDescriptor)
    {
        var securityDescriptor = new RawSecurityDescriptor(rawSecurityDescriptor, 0);

        foreach (var genericAce in securityDescriptor.DiscretionaryAcl!)
        {
            if (genericAce is not CommonAce commonAce)
            {
                continue;
            }

            if ((commonAce.AccessMask & CertificateManagementAccessMask) == 0)
            {
                continue;
            }

            switch (commonAce.AceType)
            {
                case AceType.AccessAllowed:
                    _allowedPrincipals.Add(commonAce.SecurityIdentifier);
                    break;
                case AceType.AccessDenied:
                    _disallowedPrincipals.Add(commonAce.SecurityIdentifier);
                    break;
            }
        }
    }

    /// <summary>
    ///     Determines whether a given WindowsIdentity may issue and manage certificates.
    /// </summary>
    /// <param name="identity">The Windows identity to check for permissions.</param>
    public bool AllowsForCertificateManagement(WindowsIdentity identity)
    {
        var isAllowed = false;
        var isDenied = false;

        for (var index = 0; index < identity.Groups?.Count; index++)
        {
            var group = (SecurityIdentifier)identity.Groups[index];
            isAllowed = _allowedPrincipals.Contains(group) || isAllowed;
            isDenied = _disallowedPrincipals.Contains(group) || isDenied;
        }

        isAllowed = _allowedPrincipals.Contains(identity.User!) || isAllowed;
        isDenied = _disallowedPrincipals.Contains(identity.User!) || isDenied;

        return isAllowed && !isDenied;
    }
}
