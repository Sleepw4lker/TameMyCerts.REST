using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class CertificateManagementPermissionTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();
    private static SecurityIdentifier UserSid => Identity.User!;

    [Fact]
    public void AllowsForCertificateManagement_ReturnsTrue_WhenUserIsExplicitlyAllowed()
    {
        var permission =
            new CertificateManagementPermission(TestSecurityDescriptors.AllowingCertificateManagement(UserSid));

        Assert.True(permission.AllowsForCertificateManagement(Identity));
    }

    [Fact]
    public void AllowsForCertificateManagement_ReturnsFalse_WhenUserIsExplicitlyDenied()
    {
        var permission =
            new CertificateManagementPermission(TestSecurityDescriptors.DenyingCertificateManagement(UserSid));

        Assert.False(permission.AllowsForCertificateManagement(Identity));
    }

    [Fact]
    public void AllowsForCertificateManagement_ReturnsFalse_WhenNoAceMatchesTheUser()
    {
        var permission = new CertificateManagementPermission(TestSecurityDescriptors.Empty());

        Assert.False(permission.AllowsForCertificateManagement(Identity));
    }

    [Fact]
    public void AllowsForCertificateManagement_ReturnsFalse_WhenOnlyAnEnrollAceMatchesTheUser()
    {
        // An "Enroll" object ACE is a different ACE type/semantics entirely - it must not be mistaken for the
        // "Issue and Manage Certificates" access-mask ACE this permission looks for.
        var permission = new CertificateManagementPermission(TestSecurityDescriptors.Allowing(UserSid));

        Assert.False(permission.AllowsForCertificateManagement(Identity));
    }

    [Fact]
    public void AllowsForCertificateManagement_DenyWinsOverAllow_ForTheSameUser()
    {
        var permission = new CertificateManagementPermission(
            TestSecurityDescriptors.AllowingButDenyingCertificateManagement(UserSid, UserSid));

        Assert.False(permission.AllowsForCertificateManagement(Identity));
    }

    [Fact]
    public void AllowsForCertificateManagement_IsIndependentOfEnrollmentPermission()
    {
        // The two permissions are checked from entirely different ACE types on the same security descriptor -
        // a principal may hold one, both, or neither, independently.
        var permission = new CertificateManagementPermission(
            TestSecurityDescriptors.Combined(UserSid, allowEnrollment: false, allowCertificateManagement: true));

        Assert.True(permission.AllowsForCertificateManagement(Identity));
    }
}
