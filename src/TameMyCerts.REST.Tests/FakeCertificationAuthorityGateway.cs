using System.Security.Principal;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     A fake <see cref="ICertificationAuthorityGateway" /> for tests: no DCOM, no certification authority
///     required. Records the arguments of the last call to each method and returns a configurable canned
///     result.
/// </summary>
internal sealed class FakeCertificationAuthorityGateway : ICertificationAuthorityGateway
{
    public (string ConfigString, int RequestId, WindowsIdentity Identity, bool TextualEncoding)? RetrievePendingCall
    {
        get;
        private set;
    }

    public (string ConfigString, string RawCertificateRequest, List<string> RequestAttributes, int SubmissionFlags,
        WindowsIdentity Identity, bool TextualEncoding)? SubmitCall
    {
        get;
        private set;
    }

    public (string ConfigString, bool TextualEncoding, bool CaExchangeCertificate)? GetCaCertificateCall
    {
        get;
        private set;
    }

    public (string ConfigString, bool TextualEncoding)? GetCrlDpCollectionCall { get; private set; }

    public (string ConfigString, bool TextualEncoding)? GetAiaCollectionCall { get; private set; }

    public (string ConfigString, string SerialNumber, RevocationReason Reason, WindowsIdentity Identity)?
        RevokeCertificateCall
    {
        get;
        private set;
    }

    public SubmissionResponse RetrievePendingResult { get; set; } = new(0);
    public SubmissionResponse SubmitResult { get; set; } = new(0);
    public SubmissionResponse GetCaCertificateResult { get; set; } = new(0);

    public CertificateRevocationListDistributionPointCollection GetCrlDpCollectionResult { get; set; } =
        new([]);

    public AuthorityInformationAccessCollection GetAiaCollectionResult { get; set; } = new([]);

    public SubmissionResponse RetrievePending(string configString, int requestId, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        RetrievePendingCall = (configString, requestId, identity, textualEncoding);
        return RetrievePendingResult;
    }

    public SubmissionResponse Submit(string configString, string rawCertificateRequest,
        List<string> requestAttributes, int submissionFlags, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        SubmitCall = (configString, rawCertificateRequest, requestAttributes, submissionFlags, identity,
            textualEncoding);
        return SubmitResult;
    }

    public SubmissionResponse GetCaCertificate(string configString, bool textualEncoding = false,
        bool caExchangeCertificate = false)
    {
        GetCaCertificateCall = (configString, textualEncoding, caExchangeCertificate);
        return GetCaCertificateResult;
    }

    public CertificateRevocationListDistributionPointCollection GetCrlDpCollection(string configString,
        bool textualEncoding = false)
    {
        GetCrlDpCollectionCall = (configString, textualEncoding);
        return GetCrlDpCollectionResult;
    }

    public AuthorityInformationAccessCollection GetAiaCollection(string configString, bool textualEncoding = false)
    {
        GetAiaCollectionCall = (configString, textualEncoding);
        return GetAiaCollectionResult;
    }

    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason,
        WindowsIdentity identity)
    {
        RevokeCertificateCall = (configString, serialNumber, reason, identity);
    }
}
