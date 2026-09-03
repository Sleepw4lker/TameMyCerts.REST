using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.REST.Controllers;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class CertificationAuthoritiesControllerTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();

    private static CertificationAuthoritiesController BuildController(
        FakeCertificationAuthorityDirectory caDirectory, FakeCertificationAuthorityGateway? gateway = null)
    {
        return new CertificationAuthoritiesController(gateway ?? new FakeCertificationAuthorityGateway(),
            caDirectory)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(Identity)
                }
            }
        };
    }

    [Fact]
    public void GetAllCas_ReturnsOnlyCasTheIdentityMayEnrollFor()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Allowed CA"));
        caDirectory.Add(TestModels.CertificationAuthority("Denied CA", false));
        var controller = BuildController(caDirectory);

        var result = controller.GetAllCas();

        var collection = Assert.IsType<CertificationAuthorityCollection>(result.Value);
        var name = Assert.Single(collection.CertificationAuthorities).Name;
        Assert.Equal("Allowed CA", name);
    }

    [Fact]
    public void GetCaByName_ReturnsNotFound_WhenCaDoesNotExist()
    {
        var controller = BuildController(new FakeCertificationAuthorityDirectory());

        var result = controller.GetCaByName("missing-ca");

        Assert.IsType<NotFoundObjectResult>(result.Result);
    }

    [Fact]
    public void GetCaByName_ReturnsUnauthorized_WhenEnrollmentIsDenied()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA", false));
        var controller = BuildController(caDirectory);

        var result = controller.GetCaByName("Contoso CA");

        Assert.IsType<UnauthorizedObjectResult>(result.Result);
    }

    [Fact]
    public void GetCaByName_ReturnsCa_WhenFoundAndAllowed()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var controller = BuildController(caDirectory);

        var result = controller.GetCaByName("Contoso CA");

        Assert.Equal("Contoso CA", result.Value!.Name);
    }

    [Fact]
    public void GetCaCertificate_CallsGatewayWithResolvedConfigurationString()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway
        {
            GetCaCertificateResult = new SubmissionResponse(0, certificate: "MIIC...")
        };
        var controller = BuildController(caDirectory, gateway);

        var result = controller.GetCaCertificate("Contoso CA", true);

        Assert.Same(gateway.GetCaCertificateResult, result.Value);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetCaCertificateCall!.Value.ConfigString);
        Assert.True(gateway.GetCaCertificateCall.Value.TextualEncoding);
        Assert.False(gateway.GetCaCertificateCall.Value.CaExchangeCertificate);
    }

    [Fact]
    public void GetCaExchangeCertificate_RequestsTheExchangeCertificateFromTheGateway()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway();
        var controller = BuildController(caDirectory, gateway);

        controller.GetCaExchangeCertificate("Contoso CA");

        Assert.True(gateway.GetCaCertificateCall!.Value.CaExchangeCertificate);
    }

    [Fact]
    public void GetCrlDp_ReturnsUnauthorized_WhenEnrollmentIsDenied()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA", false));
        var controller = BuildController(caDirectory);

        var result = controller.GetCrlDp("Contoso CA");

        Assert.IsType<UnauthorizedObjectResult>(result.Result);
    }

    [Fact]
    public void GetCrlDp_ReturnsGatewayResult_WhenAllowed()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway();
        var controller = BuildController(caDirectory, gateway);

        var result = controller.GetCrlDp("Contoso CA");

        Assert.Same(gateway.GetCrlDpCollectionResult, result.Value);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetCrlDpCollectionCall!.Value.ConfigString);
    }

    [Fact]
    public void GetAia_ReturnsGatewayResult_WhenAllowed()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway();
        var controller = BuildController(caDirectory, gateway);

        var result = controller.GetAia("Contoso CA");

        Assert.Same(gateway.GetAiaCollectionResult, result.Value);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.GetAiaCollectionCall!.Value.ConfigString);
    }
}
