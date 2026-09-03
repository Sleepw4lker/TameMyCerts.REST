namespace TameMyCerts.NetCore.Common.X509;

/// <summary>
///     Builds the Authority Key Identifier (AKI) X.509 certificate extension (RFC 5280, section 4.2.1.1).
/// </summary>
public class X509CertificateExtensionAuthorityKeyIdentifier : X509CertificateExtension
{
    /// <summary>
    ///     Builds the extension from the raw key identifier.
    /// </summary>
    /// <param name="authorityKeyIdentifer">The key identifier of the issuing CA's public key.</param>
    public X509CertificateExtensionAuthorityKeyIdentifier(byte[] authorityKeyIdentifer)
    {
        var result = Asn1BuildNode(0x80, authorityKeyIdentifer);
        result = Asn1BuildNode(0x30, result);
        RawData = result;
    }
}