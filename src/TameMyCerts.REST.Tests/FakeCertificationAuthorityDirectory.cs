using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     A fake <see cref="ICertificationAuthorityDirectory" /> for tests: no Active Directory needed.
/// </summary>
internal sealed class FakeCertificationAuthorityDirectory : ICertificationAuthorityDirectory
{
    private readonly Dictionary<string, CertificationAuthority> _byName = new(StringComparer.OrdinalIgnoreCase);

    public void Add(CertificationAuthority certificationAuthority)
    {
        _byName[certificationAuthority.Name] = certificationAuthority;
    }

    public CertificationAuthority? FindByName(string caName, bool textualEncoding = false)
    {
        return _byName.GetValueOrDefault(caName);
    }

    public IReadOnlyList<CertificationAuthority> GetAll(bool textualEncoding = false)
    {
        return _byName.Values.ToList();
    }
}
