using TameMyCerts.REST.Models;

namespace TameMyCerts.REST.Tests;

/// <summary>
///     A fake <see cref="ICertificateTemplateRepository" /> for tests: no registry needed.
/// </summary>
internal sealed class FakeCertificateTemplateRepository : ICertificateTemplateRepository
{
    private readonly Dictionary<string, CertificateTemplate> _byName = new(StringComparer.OrdinalIgnoreCase);

    public void Add(CertificateTemplate certificateTemplate)
    {
        _byName[certificateTemplate.Name] = certificateTemplate;
    }

    public CertificateTemplate? FindByName(string templateName)
    {
        return _byName.GetValueOrDefault(templateName);
    }

    public IReadOnlyList<CertificateTemplate> GetAll()
    {
        return _byName.Values.ToList();
    }
}
