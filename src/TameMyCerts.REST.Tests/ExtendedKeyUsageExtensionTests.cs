using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class ExtendedKeyUsageExtensionTests
{
    [Fact]
    public void Constructor_SetsCriticalFlag()
    {
        var extension = new ExtendedKeyUsageExtension([], true);

        Assert.True(extension.Critical);
    }

    [Fact]
    public void Constructor_EmptyList_ReturnsEmptyExtendedKeyUsages()
    {
        var extension = new ExtendedKeyUsageExtension([], false);

        Assert.Empty(extension.ExtendedKeyUsages);
    }

    [Fact]
    public void Constructor_ResolvesFriendlyNameForKnownOid()
    {
        var extension = new ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"], false);

        var usage = Assert.Single(extension.ExtendedKeyUsages);
        Assert.Equal("1.3.6.1.5.5.7.3.1", usage.ObjectIdentifier);
        Assert.Equal("Server Authentication", usage.FriendlyName);
    }

    [Fact]
    public void Constructor_FallsBackToUnknown_ForUnrecognizedOid()
    {
        var extension = new ExtendedKeyUsageExtension(["1.2.3.4.5.6.7.8.9"], false);

        var usage = Assert.Single(extension.ExtendedKeyUsages);
        Assert.Equal("unknown", usage.FriendlyName);
    }

    [Fact]
    public void Constructor_OrdersResultsByFriendlyName()
    {
        // Server Authentication (1.3.6.1.5.5.7.3.1) sorts after Client Authentication (...3.2) alphabetically.
        var extension = new ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"], false);

        Assert.Equal(["Client Authentication", "Server Authentication"],
            extension.ExtendedKeyUsages.Select(usage => usage.FriendlyName));
    }
}
