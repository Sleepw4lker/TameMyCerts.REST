using TameMyCerts.REST.Enums;

namespace TameMyCerts.REST.Tests;

public class CertificateRequestIntegrityChecksTests
{
    [Fact]
    public void DetectRequestType_RecognizesPkcs10Request()
    {
        var csr = TestCertificateRequests.CreatePkcs10RequestBase64();

        var requestType = CertificateRequestIntegrityChecks.DetectRequestType(csr, out var rawCertificateRequest);

        Assert.Equal(CertCli.CR_IN_PKCS10, requestType);
        Assert.NotEmpty(rawCertificateRequest);
    }

    [Fact]
    public void DetectRequestType_ReturnsZero_ForUnparsableInput()
    {
        var garbage = Convert.ToBase64String("this is not a certificate request"u8.ToArray());

        var requestType = CertificateRequestIntegrityChecks.DetectRequestType(garbage, out var rawCertificateRequest);

        Assert.Equal(0, requestType);
        Assert.Equal(string.Empty, rawCertificateRequest);
    }

    [Fact]
    public void DetectRequestType_ReturnsZero_ForEmptyInput()
    {
        var requestType = CertificateRequestIntegrityChecks.DetectRequestType(string.Empty,
            out var rawCertificateRequest);

        Assert.Equal(0, requestType);
        Assert.Equal(string.Empty, rawCertificateRequest);
    }
}
