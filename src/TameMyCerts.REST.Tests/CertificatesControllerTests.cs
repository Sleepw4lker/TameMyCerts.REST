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

    [Fact]
    public void RevokeCertificate_ReturnsNotFound_WhenCaDoesNotExist()
    {
        var controller = BuildController(new FakeCertificationAuthorityDirectory());

        var result = controller.RevokeCertificate("missing-ca", new RevocationRequest { SerialNumber = "1a2b3c" });

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public void RevokeCertificate_ReturnsUnauthorized_WhenCertificateManagementIsDenied()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway { AllowsForCertificateManagementResult = false };
        var controller = BuildController(caDirectory, gateway);

        var result = controller.RevokeCertificate("Contoso CA", new RevocationRequest { SerialNumber = "1a2b3c" });

        Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("ca.contoso.com\\Contoso CA",
            gateway.AllowsForCertificateManagementCall!.Value.ConfigString);
        Assert.Null(gateway.RevokeCertificateCall);
    }

    [Fact]
    public void RevokeCertificate_ReturnsBadRequest_WhenSerialNumberIsEmpty()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var controller = BuildController(caDirectory);

        var result = controller.RevokeCertificate("Contoso CA", new RevocationRequest { SerialNumber = "" });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public void RevokeCertificate_DoesNotCheckEnrollmentPermission_AndReturnsNoContent()
    {
        // Revoking requires the CA's "Issue and Manage Certificates" permission, not "Request Certificates"
        // (Enroll) - a CA the identity is denied enrollment on must still allow the revoke call through to the
        // gateway; the CA itself is the one that would reject it, server-side, if manage rights were missing.
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA", allowed: false));
        var gateway = new FakeCertificationAuthorityGateway();
        var controller = BuildController(caDirectory, gateway);

        var result = controller.RevokeCertificate("Contoso CA",
            new RevocationRequest { SerialNumber = "1a2b3c", Reason = RevocationReason.KeyCompromise });

        Assert.IsType<NoContentResult>(result);
        Assert.NotNull(gateway.RevokeCertificateCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", gateway.RevokeCertificateCall.Value.ConfigString);
        Assert.Equal("1a2b3c", gateway.RevokeCertificateCall.Value.SerialNumber);
        Assert.Equal(RevocationReason.KeyCompromise, gateway.RevokeCertificateCall.Value.Reason);
        Assert.Same(Identity, gateway.RevokeCertificateCall.Value.Identity);
    }

    [Fact]
    public void RevokeCertificate_DefaultsReasonToUnspecified_WhenNotGiven()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Contoso CA"));
        var gateway = new FakeCertificationAuthorityGateway();
        var controller = BuildController(caDirectory, gateway);

        controller.RevokeCertificate("Contoso CA", new RevocationRequest { SerialNumber = "1a2b3c" });

        Assert.Equal(RevocationReason.Unspecified, gateway.RevokeCertificateCall!.Value.Reason);
    }
}
