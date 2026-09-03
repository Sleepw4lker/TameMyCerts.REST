using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class EnrollmentPermissionTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();
    private static SecurityIdentifier UserSid => Identity.User!;

    [Fact]
    public void AllowsForEnrollment_ReturnsTrue_WhenUserIsExplicitlyAllowed()
    {
        var permission = new EnrollmentPermission(TestSecurityDescriptors.Allowing(UserSid));

        Assert.True(permission.AllowsForEnrollment(Identity, true));
    }

    [Fact]
    public void AllowsForEnrollment_ReturnsFalse_WhenUserIsExplicitlyDenied()
    {
        var permission = new EnrollmentPermission(TestSecurityDescriptors.Denying(UserSid));

        Assert.False(permission.AllowsForEnrollment(Identity, true));
    }

    [Fact]
    public void AllowsForEnrollment_ReturnsFalse_WhenNoAceMatchesTheUser()
    {
        var permission = new EnrollmentPermission(TestSecurityDescriptors.Empty());

        Assert.False(permission.AllowsForEnrollment(Identity, true));
    }

    [Fact]
    public void AllowsForEnrollment_DenyWinsOverAllow_ForTheSameUser()
    {
        var permission =
            new EnrollmentPermission(TestSecurityDescriptors.AllowingButDenying(UserSid, UserSid));

        Assert.False(permission.AllowsForEnrollment(Identity, true));
    }
}
