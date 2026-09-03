using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.REST.Controllers;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class CertificatesControllerTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();

    private static CertificatesController BuildController(FakeCertificationAuthorityDirectory caDirectory,
        FakeCertificationAuthorityGateway? gateway = null)
    {
        return new CertificatesController(gateway ?? new FakeCertificationAuthorityGateway(), caDirectory)
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
    public void GetCertificateByRequestId_ReturnsNotFound_WhenCaDoesNotExist()
    {
        var controller = BuildController(new FakeCertificationAuthorityDirectory());

        var result = controller.GetCertificateByRequestId("missing-ca", 42);

        Assert.IsType<NotFoundObjectResult>(result.Result);
    }

    [Fact]
    public void GetCertificateByRequestId_ReturnsUnauthorized_WhenEnrollmentIsDenied()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA", false));
        var controller = BuildController(caDirectory);

        var result = controller.GetCertificateByRequestId("Contoso CA", 42);

        Assert.IsType<UnauthorizedObjectResult>(result.Result);
    }

    [Fact]
    public void GetCertificateByRequestId_CallsGatewayWithResolvedCaAndIdentity_WhenAllowed()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway
        {
            RetrievePendingResult = new SubmissionResponse(0, 42)
        };
        var controller = BuildController(caDirectory, gateway);

        var result = controller.GetCertificateByRequestId("Contoso CA", 42, true);

        Assert.Same(gateway.RetrievePendingResult, result.Value);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.RetrievePendingCall!.Value.ConfigString);
        Assert.Equal(42, gateway.RetrievePendingCall.Value.RequestId);
        Assert.Same(Identity, gateway.RetrievePendingCall.Value.Identity);
        Assert.True(gateway.RetrievePendingCall.Value.TextualEncoding);
    }

    [Fact]
    public void SubmitCertificateRequest_ReturnsNotFound_WhenCaDoesNotExist()
    {
        var controller = BuildController(new FakeCertificationAuthorityDirectory());

        var result = controller.SubmitCertificateRequest("missing-ca", new CertificateRequest { Request = "abc" });

        Assert.IsType<NotFoundObjectResult>(result.Result);
    }

    [Fact]
    public void SubmitCertificateRequest_ReturnsBadRequest_WhenRequestBodyIsEmpty()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var controller = BuildController(caDirectory);

        var result = controller.SubmitCertificateRequest("Contoso CA",
            new CertificateRequest { Request = "" });

        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public void SubmitCertificateRequest_ReturnsBadRequest_WhenCsrCannotBeParsed()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var controller = BuildController(caDirectory);

        var result = controller.SubmitCertificateRequest("Contoso CA",
            new CertificateRequest { Request = Convert.ToBase64String("not a csr"u8.ToArray()) });

        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    [Fact]
    public void SubmitCertificateRequest_SubmitsToGateway_WithDetectedRequestTypeAndTemplateAttribute()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway
        {
            SubmitResult = new SubmissionResponse(0, dispositionCode: (int)SubmissionResponse.DispositionCode.Pending)
        };
        var controller = BuildController(caDirectory, gateway);
        var csr = TestCertificateRequests.CreatePkcs10RequestBase64();

        var result = controller.SubmitCertificateRequest("Contoso CA",
            new CertificateRequest { Request = csr }, "WebServer");

        Assert.Same(gateway.SubmitResult, result.Value);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.SubmitCall!.Value.ConfigString);
        Assert.Same(Identity, gateway.SubmitCall.Value.Identity);
        Assert.Contains("CertificateTemplate:WebServer", gateway.SubmitCall.Value.RequestAttributes);
    }
}
