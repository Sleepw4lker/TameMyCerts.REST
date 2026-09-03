using System.Security.Cryptography;
using X509CertificateRequest = System.Security.Cryptography.X509Certificates.CertificateRequest;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     Generates real, valid certificate requests for tests, so tests exercise the actual ASN.1 parsing
///     instead of a hand-rolled or hardcoded blob.
/// </summary>
internal static class TestCertificateRequests
{
    public static string CreatePkcs10RequestBase64(string subject = "CN=test.contoso.com")
    {
        using var rsa = RSA.Create(2048);
        var request = new X509CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(request.CreateSigningRequest());
    }
}
