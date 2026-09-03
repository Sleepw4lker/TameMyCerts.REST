using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

public class KeyUsageExtensionTests
{
    [Fact]
    public void Constructor_SetsCriticalFlag()
    {
        var extension = new KeyUsageExtension([0x00], true);

        Assert.True(extension.Critical);
    }

    [Fact]
    public void Constructor_NoFlagsSet_ReturnsEmptyKeyUsages()
    {
        var extension = new KeyUsageExtension([0x00]);

        Assert.Empty(extension.KeyUsages);
    }

    [Fact]
    public void Constructor_ParsesSingleFlag()
    {
        var extension = new KeyUsageExtension([(byte)KeyUsage.KeyUsageType.digitalSignature]);

        var usage = Assert.Single(extension.KeyUsages);
        Assert.Equal(KeyUsage.KeyUsageType.digitalSignature, usage.FriendlyName);
    }

    [Fact]
    public void Constructor_ParsesCombinedFlags()
    {
        var value = (byte)(KeyUsage.KeyUsageType.digitalSignature | KeyUsage.KeyUsageType.keyEncipherment);
        var extension = new KeyUsageExtension([value]);

        Assert.Equal(2, extension.KeyUsages.Count);
        Assert.Contains(extension.KeyUsages, usage => usage.FriendlyName == KeyUsage.KeyUsageType.digitalSignature);
        Assert.Contains(extension.KeyUsages, usage => usage.FriendlyName == KeyUsage.KeyUsageType.keyEncipherment);
    }
}
