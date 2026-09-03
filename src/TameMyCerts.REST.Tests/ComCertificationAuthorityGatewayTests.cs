using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Covers the parts of <see cref="ComCertificationAuthorityGateway" /> that don't need a live COM object:
///     everything routed through the injected <see cref="ICertAdminClient" /> (revocation, CA-management
///     permission). The CCertRequest/CERTCLILib side (submit, retrieve, CA metadata) still needs a real COM
///     object and is out of scope here.
/// </summary>
public class ComCertificationAuthorityGatewayTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();
    private static SecurityIdentifier CurrentUserSid => Identity.User!;

    [Fact]
    public void RevokeCertificate_DelegatesToCertAdminClient()
    {
        var certAdminClient = new FakeCertAdminClient();
        var gateway = new ComCertificationAuthorityGateway(certAdminClient);
        var date = new DateTime(2026, 1, 15, 0, 0, 0, DateTimeKind.Utc);

        gateway.RevokeCertificate("ca.contoso.com\\Contoso CA", "1a2b3c", RevocationReason.KeyCompromise, date,
            Identity);

        Assert.NotNull(certAdminClient.RevokeCertificateCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", certAdminClient.RevokeCertificateCall.Value.ConfigString);
        Assert.Equal("1a2b3c", certAdminClient.RevokeCertificateCall.Value.SerialNumber);
        Assert.Equal(RevocationReason.KeyCompromise, certAdminClient.RevokeCertificateCall.Value.Reason);
        Assert.Equal(date, certAdminClient.RevokeCertificateCall.Value.Date);
    }

    [Fact]
    public void AllowsForCertificateManagement_ReturnsTrue_WhenTheCaSecurityDescriptorAllowsTheUser()
    {
        var certAdminClient = new FakeCertAdminClient
        {
            GetCaSecurityDescriptorResult = TestSecurityDescriptors.AllowingCertificateManagement(CurrentUserSid)
        };
        var gateway = new ComCertificationAuthorityGateway(certAdminClient);

        var result = gateway.AllowsForCertificateManagement("ca.contoso.com\\Contoso CA", Identity);

        Assert.True(result);
        Assert.Equal("ca.contoso.com\\Contoso CA", certAdminClient.GetCaSecurityDescriptorCall);
    }

    [Fact]
    public void AllowsForCertificateManagement_ReturnsFalse_WhenTheCaSecurityDescriptorDeniesTheUser()
    {
        var certAdminClient = new FakeCertAdminClient
        {
            GetCaSecurityDescriptorResult = TestSecurityDescriptors.DenyingCertificateManagement(CurrentUserSid)
        };
        var gateway = new ComCertificationAuthorityGateway(certAdminClient);

        var result = gateway.AllowsForCertificateManagement("ca.contoso.com\\Contoso CA", Identity);

        Assert.False(result);
    }
}
