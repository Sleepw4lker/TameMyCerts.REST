using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.REST.Controllers;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class CertificateTemplatesControllerTests
{
    private static readonly WindowsIdentity Identity = WindowsIdentity.GetCurrent();

    private static CertificateTemplatesController BuildController(
        FakeCertificateTemplateRepository templateRepository, FakeCertificationAuthorityDirectory? caDirectory = null)
    {
        return new CertificateTemplatesController(templateRepository,
            caDirectory ?? new FakeCertificationAuthorityDirectory())
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
    public void GetCertificateTemplateCollection_ReturnsOnlyTemplatesTheIdentityMayEnrollFor()
    {
        var templateRepository = new FakeCertificateTemplateRepository();
        templateRepository.Add(TestModels.CertificateTemplate("Allowed"));
        templateRepository.Add(TestModels.CertificateTemplate("Denied", false));
        var controller = BuildController(templateRepository);

        var result = controller.GetCertificateTemplateCollection();

        var collection = Assert.IsType<CertificateTemplateCollection>(result.Value);
        var name = Assert.Single(collection.CertificateTemplates).Name;
        Assert.Equal("Allowed", name);
    }

    [Fact]
    public void GetCertificateTemplate_ReturnsPlainNotFound_WhenTemplateDoesNotExist()
    {
        var controller = BuildController(new FakeCertificateTemplateRepository());

        var result = controller.GetCertificateTemplate("missing-template");

        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public void GetCertificateTemplate_ReturnsUnauthorized_WhenEnrollmentIsDenied()
    {
        var templateRepository = new FakeCertificateTemplateRepository();
        templateRepository.Add(TestModels.CertificateTemplate("WebServer", false));
        var controller = BuildController(templateRepository);

        var result = controller.GetCertificateTemplate("WebServer");

        Assert.IsType<UnauthorizedObjectResult>(result.Result);
    }

    [Fact]
    public void GetCertificateTemplate_ReturnsTemplate_WhenFoundAndAllowed()
    {
        var templateRepository = new FakeCertificateTemplateRepository();
        templateRepository.Add(TestModels.CertificateTemplate("WebServer"));
        var controller = BuildController(templateRepository);

        var result = controller.GetCertificateTemplate("WebServer");

        Assert.Equal("WebServer", result.Value!.Name);
    }

    [Fact]
    public void GetCertificateTemplateIssuers_ReturnsOnlyCasOfferingTheTemplate()
    {
        var caDirectory = new FakeCertificationAuthorityDirectory();
        caDirectory.Add(TestModels.CertificationAuthority("Issuing CA",
            certificateTemplates: ["WebServer"]));
        caDirectory.Add(TestModels.CertificationAuthority("Other CA",
            certificateTemplates: ["KerberosAuthentication"]));
        var controller = BuildController(new FakeCertificateTemplateRepository(), caDirectory);

        var result = controller.GetCertificateTemplateIssuers("WebServer");

        var collection = Assert.IsType<CertificationAuthorityCollection>(result.Value);
        var name = Assert.Single(collection.CertificationAuthorities).Name;
        Assert.Equal("Issuing CA", name);
    }
}
