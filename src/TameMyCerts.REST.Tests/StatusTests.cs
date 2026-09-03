using TameMyCerts.REST.Enums;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class StatusTests
{
    [Fact]
    public void Constructor_Success_DescriptionHasNoErrorCodeSuffix()
    {
        var status = new Status(WinError.ERROR_SUCCESS);

        Assert.Equal(WinError.ERROR_SUCCESS, status.StatusCode);
        Assert.DoesNotContain("0x", status.Description);
    }

    [Fact]
    public void Constructor_Failure_DescriptionIncludesErrorCode()
    {
        const int errorAccessDenied = 5;

        var status = new Status(errorAccessDenied);

        Assert.Equal(errorAccessDenied, status.StatusCode);
        Assert.Contains($"0x{errorAccessDenied:X}", status.Description);
        Assert.Contains($"({errorAccessDenied})", status.Description);
    }
}
