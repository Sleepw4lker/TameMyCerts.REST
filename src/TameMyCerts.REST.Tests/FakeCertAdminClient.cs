using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     A fake <see cref="ICertAdminClient" /> for tests: no DCOM, no certification authority required. Records
///     the arguments of the last call to each method and returns a configurable canned result.
/// </summary>
internal sealed class FakeCertAdminClient : ICertAdminClient
{
    public (string ConfigString, string SerialNumber, RevocationReason Reason, DateTime Date)? RevokeCertificateCall
    {
        get;
        private set;
    }

    public string? GetCaSecurityDescriptorCall { get; private set; }

    public byte[] GetCaSecurityDescriptorResult { get; set; } = [];

    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason, DateTime date)
    {
        RevokeCertificateCall = (configString, serialNumber, reason, date);
    }

    public byte[] GetCaSecurityDescriptor(string configString)
    {
        GetCaSecurityDescriptorCall = configString;
        return GetCaSecurityDescriptorResult;
    }
}
