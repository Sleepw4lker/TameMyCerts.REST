using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Confirms the fake gateway is a faithful stand-in for <see cref="ICertificationAuthorityGateway" />:
///     it records exactly what it was called with and returns exactly what was configured. Any future test
///     of code that depends on <see cref="ICertificationAuthorityGateway" /> (controllers included, once the
///     certification authority lookup itself has a seam) builds on this.
/// </summary>
public class FakeCertificationAuthorityGatewayTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();

    [Fact]
    public void RetrievePending_RecordsCallAndReturnsConfiguredResult()
    {
        var gateway = new FakeCertificationAuthorityGateway
        {
            RetrievePendingResult = new SubmissionResponse(0, requestId: 42,
                dispositionCode: (int)SubmissionResponse.DispositionCode.Issued)
        };

        var result = gateway.RetrievePending("ca.contoso.com\\Contoso CA", 42, Identity, textualEncoding: true);

        Assert.Same(gateway.RetrievePendingResult, result);
        Assert.NotNull(gateway.RetrievePendingCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.RetrievePendingCall.Value.ConfigString);
        Assert.Equal(42, gateway.RetrievePendingCall.Value.RequestId);
        Assert.Same(Identity, gateway.RetrievePendingCall.Value.Identity);
        Assert.True(gateway.RetrievePendingCall.Value.TextualEncoding);
    }

    [Fact]
    public void Submit_RecordsCallAndReturnsConfiguredResult()
    {
        var gateway = new FakeCertificationAuthorityGateway
        {
            SubmitResult = new SubmissionResponse(0, dispositionCode: (int)SubmissionResponse.DispositionCode.Pending)
        };
        var requestAttributes = new List<string> { "CertificateTemplate:WebServer" };

        var result = gateway.Submit("ca.contoso.com\\Contoso CA", "MIIB...", requestAttributes, 0x101, Identity);

        Assert.Same(gateway.SubmitResult, result);
        Assert.NotNull(gateway.SubmitCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.SubmitCall.Value.ConfigString);
        Assert.Equal("MIIB...", gateway.SubmitCall.Value.RawCertificateRequest);
        Assert.Same(requestAttributes, gateway.SubmitCall.Value.RequestAttributes);
        Assert.Equal(0x101, gateway.SubmitCall.Value.SubmissionFlags);
        Assert.Same(Identity, gateway.SubmitCall.Value.Identity);
        Assert.False(gateway.SubmitCall.Value.TextualEncoding);
    }

    [Fact]
    public void GetCaCertificate_RecordsCallAndReturnsConfiguredResult()
    {
        var gateway = new FakeCertificationAuthorityGateway
        {
            GetCaCertificateResult = new SubmissionResponse(0, certificate: "MIIC...")
        };

        var result = gateway.GetCaCertificate("ca.contoso.com\\Contoso CA", textualEncoding: true,
            caExchangeCertificate: true);

        Assert.Same(gateway.GetCaCertificateResult, result);
        Assert.NotNull(gateway.GetCaCertificateCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetCaCertificateCall.Value.ConfigString);
        Assert.True(gateway.GetCaCertificateCall.Value.TextualEncoding);
        Assert.True(gateway.GetCaCertificateCall.Value.CaExchangeCertificate);
    }

    [Fact]
    public void GetCrlDpCollection_RecordsCallAndReturnsConfiguredResult()
    {
        var gateway = new FakeCertificationAuthorityGateway();

        var result = gateway.GetCrlDpCollection("ca.contoso.com\\Contoso CA");

        Assert.Same(gateway.GetCrlDpCollectionResult, result);
        Assert.NotNull(gateway.GetCrlDpCollectionCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetCrlDpCollectionCall.Value.ConfigString);
        Assert.False(gateway.GetCrlDpCollectionCall.Value.TextualEncoding);
    }

    [Fact]
    public void GetAiaCollection_RecordsCallAndReturnsConfiguredResult()
    {
        var gateway = new FakeCertificationAuthorityGateway();

        var result = gateway.GetAiaCollection("ca.contoso.com\\Contoso CA", textualEncoding: true);

        Assert.Same(gateway.GetAiaCollectionResult, result);
        Assert.NotNull(gateway.GetAiaCollectionCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetAiaCollectionCall.Value.ConfigString);
        Assert.True(gateway.GetAiaCollectionCall.Value.TextualEncoding);
    }
}
