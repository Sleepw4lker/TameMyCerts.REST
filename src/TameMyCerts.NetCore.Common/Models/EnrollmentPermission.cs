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

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Decides whether a Windows identity may enroll for certificates, based on the "Enroll" object ACEs
///     of a certification authority's or certificate template's security descriptor.
/// </summary>
public sealed class EnrollmentPermission
{
    private const string EnrollPermission = "0E10C968-78FB-11D2-90D4-00C04F79DC55";

    private readonly List<SecurityIdentifier> _allowedPrincipals = [];
    private readonly List<SecurityIdentifier> _disallowedPrincipals = [];

    /// <summary>
    ///     Parses the "Enroll" object ACEs out of a raw security descriptor.
    /// </summary>
    /// <param name="rawSecurityDescriptor">The ASN.1/binary security descriptor to parse.</param>
    public EnrollmentPermission(byte[] rawSecurityDescriptor)
    {
        var securityDescriptor = new RawSecurityDescriptor(rawSecurityDescriptor, 0);

        foreach (var genericAce in securityDescriptor.DiscretionaryAcl!)
        {
            if (genericAce is not ObjectAce objectAce)
            {
                continue;
            }

            if (objectAce.ObjectAceType != new Guid(EnrollPermission))
            {
                continue;
            }

            switch (objectAce.AceType)
            {
                case AceType.AccessAllowedObject:
                    _allowedPrincipals.Add(objectAce.SecurityIdentifier);
                    break;
                case AceType.AccessDeniedObject:
                    _disallowedPrincipals.Add(objectAce.SecurityIdentifier);
                    break;
            }
        }
    }

    /// <summary>
    ///     Determines whether a given WindowsIdentity may enroll.
    /// </summary>
    /// <param name="identity">The Windows identity to check for permissions.</param>
    /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
    public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
    {
        var isAllowed = false;
        var isDenied = false;

        if (!explicitlyPermitted)
        {
            for (var index = 0; index < identity.Groups?.Count; index++)
            {
                var group = (SecurityIdentifier)identity.Groups[index];
                isAllowed = _allowedPrincipals.Contains(group) || isAllowed;
                isDenied = _disallowedPrincipals.Contains(group) || isDenied;
            }
        }

        isAllowed = _allowedPrincipals.Contains(identity.User!) || isAllowed;
        isDenied = _disallowedPrincipals.Contains(identity.User!) || isDenied;

        return isAllowed && !isDenied;
    }
}
