using System.Security.AccessControl;
using System.Security.Principal;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Builds raw (binary) security descriptors carrying a single "Enroll" object ACE, for feeding
///     <see cref="TameMyCerts.NetCore.Common.Models.EnrollmentPermission" /> and the model constructors that
///     build one, without needing a real Active Directory object or registry key.
/// </summary>
internal static class TestSecurityDescriptors
{
    private static readonly Guid EnrollPermission = new("0E10C968-78FB-11D2-90D4-00C04F79DC55");

    public static byte[] Empty()
    {
        return Build([]);
    }

    public static byte[] Allowing(SecurityIdentifier sid)
    {
        return Build([BuildAce(AceQualifier.AccessAllowed, sid)]);
    }

    public static byte[] Denying(SecurityIdentifier sid)
    {
        return Build([BuildAce(AceQualifier.AccessDenied, sid)]);
    }

    public static byte[] AllowingButDenying(SecurityIdentifier allowed, SecurityIdentifier denied)
    {
        return Build([BuildAce(AceQualifier.AccessAllowed, allowed), BuildAce(AceQualifier.AccessDenied, denied)]);
    }

    private static ObjectAce BuildAce(AceQualifier qualifier, SecurityIdentifier sid)
    {
        return new ObjectAce(
            AceFlags.None,
            qualifier,
            0,
            sid,
            ObjectAceFlags.ObjectAceTypePresent,
            EnrollPermission,
            Guid.Empty,
            false,
            null);
    }

    private static byte[] Build(IReadOnlyList<ObjectAce> aces)
    {
        var acl = new RawAcl(RawAcl.AclRevisionDS, aces.Count);

        for (var index = 0; index < aces.Count; index++)
        {
            acl.InsertAce(index, aces[index]);
        }

        var securityDescriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null,
            acl);

        var result = new byte[securityDescriptor.BinaryLength];
        securityDescriptor.GetBinaryForm(result, 0);
        return result;
    }
}
