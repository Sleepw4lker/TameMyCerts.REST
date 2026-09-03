using System.Security.Principal;
using Microsoft.Extensions.Caching.Memory;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class CachingCertificationAuthorityGatewayTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();

    private static CachingCertificationAuthorityGateway BuildGateway(FakeCertificationAuthorityGateway inner)
    {
        return new CachingCertificationAuthorityGateway(inner, new MemoryCache(new MemoryCacheOptions()));
    }

    [Fact]
    public void AllowsForCertificateManagement_CachesResult_ForTheSameCaAndUser()
    {
        var inner = new FakeCertificationAuthorityGateway { AllowsForCertificateManagementResult = true };
        var gateway = BuildGateway(inner);

        var first = gateway.AllowsForCertificateManagement("ca.contoso.com\\Contoso CA", Identity);

        // If the second call reached the inner gateway again, it would pick up this new result instead.
        inner.AllowsForCertificateManagementResult = false;
        var second = gateway.AllowsForCertificateManagement("ca.contoso.com\\Contoso CA", Identity);

        Assert.True(first);
        Assert.True(second);
    }

    [Fact]
    public void AllowsForCertificateManagement_DoesNotShareCache_AcrossDifferentCertificationAuthorities()
    {
        var inner = new FakeCertificationAuthorityGateway { AllowsForCertificateManagementResult = true };
        var gateway = BuildGateway(inner);

        gateway.AllowsForCertificateManagement("ca.contoso.com\\Contoso CA", Identity);

        inner.AllowsForCertificateManagementResult = false;
        var result = gateway.AllowsForCertificateManagement("ca.contoso.com\\Fabrikam CA", Identity);

        Assert.False(result);
    }

    [Fact]
    public void RevokeCertificate_DelegatesToInner_WithoutCaching()
    {
        var inner = new FakeCertificationAuthorityGateway();
        var gateway = BuildGateway(inner);
        var date = new DateTime(2026, 1, 15, 0, 0, 0, DateTimeKind.Utc);

        gateway.RevokeCertificate("ca.contoso.com\\Contoso CA", "1a2b3c", RevocationReason.KeyCompromise, date,
            Identity);

        Assert.NotNull(inner.RevokeCertificateCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", inner.RevokeCertificateCall.Value.ConfigString);
        Assert.Equal("1a2b3c", inner.RevokeCertificateCall.Value.SerialNumber);
        Assert.Equal(RevocationReason.KeyCompromise, inner.RevokeCertificateCall.Value.Reason);
        Assert.Equal(date, inner.RevokeCertificateCall.Value.Date);
        Assert.Same(Identity, inner.RevokeCertificateCall.Value.Identity);
    }
}
