using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class FakeCertAdminClientTests
{
    [Fact]
    public void RevokeCertificate_RecordsCall()
    {
        var client = new FakeCertAdminClient();
        var date = new DateTime(2026, 1, 15, 0, 0, 0, DateTimeKind.Utc);

        client.RevokeCertificate("ca.contoso.com\\Contoso CA", "1a2b3c4d", RevocationReason.KeyCompromise, date);

        Assert.NotNull(client.RevokeCertificateCall);
        Assert.Equal("ca.contoso.com\\Contoso CA", client.RevokeCertificateCall.Value.ConfigString);
        Assert.Equal("1a2b3c4d", client.RevokeCertificateCall.Value.SerialNumber);
        Assert.Equal(RevocationReason.KeyCompromise, client.RevokeCertificateCall.Value.Reason);
        Assert.Equal(date, client.RevokeCertificateCall.Value.Date);
    }

    [Fact]
    public void GetCaSecurityDescriptor_RecordsCallAndReturnsConfiguredResult()
    {
        var client = new FakeCertAdminClient { GetCaSecurityDescriptorResult = [0x30, 0x03, 0x02, 0x01, 0x00] };

        var result = client.GetCaSecurityDescriptor("ca.contoso.com\\Contoso CA");

        Assert.Same(client.GetCaSecurityDescriptorResult, result);
        Assert.Equal("ca.contoso.com\\Contoso CA", client.GetCaSecurityDescriptorCall);
    }
}
