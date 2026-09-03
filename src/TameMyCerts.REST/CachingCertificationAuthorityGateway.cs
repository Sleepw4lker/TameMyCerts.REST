// Copyright (c) Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Security.Principal;
using Microsoft.Extensions.Caching.Memory;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Decorates an <see cref="ICertificationAuthorityGateway" />, caching the result of
///     <see cref="AllowsForCertificateManagement" /> per certification authority and user for a short time.
///     Unlike the other gateway calls, this one runs on every single revoke request before the request even
///     reaches the certification authority - without caching, a client that repeatedly calls the revoke
///     endpoint (whether legitimately or not) would force a live DCOM round-trip to the CA on every single
///     call just to answer the same permission question.
/// </summary>
public sealed class CachingCertificationAuthorityGateway : ICertificationAuthorityGateway
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(15);

    private readonly IMemoryCache _cache;
    private readonly ICertificationAuthorityGateway _inner;

    /// <summary>
    ///     Builds the decorator around another gateway.
    /// </summary>
    /// <param name="inner">The gateway to delegate to, and whose AllowsForCertificateManagement result to cache.</param>
    /// <param name="cache">The cache to hold results in.</param>
    public CachingCertificationAuthorityGateway(ICertificationAuthorityGateway inner, IMemoryCache cache)
    {
        _inner = inner;
        _cache = cache;
    }

    /// <inheritdoc />
    public SubmissionResponse RetrievePending(string configString, int requestId, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return _inner.RetrievePending(configString, requestId, identity, textualEncoding);
    }

    /// <inheritdoc />
    public SubmissionResponse Submit(string configString, string rawCertificateRequest,
        List<string> requestAttributes, int submissionFlags, WindowsIdentity identity,
        bool textualEncoding = false)
    {
        return _inner.Submit(configString, rawCertificateRequest, requestAttributes, submissionFlags, identity,
            textualEncoding);
    }

    /// <inheritdoc />
    public SubmissionResponse GetCaCertificate(string configString, bool textualEncoding = false,
        bool caExchangeCertificate = false)
    {
        return _inner.GetCaCertificate(configString, textualEncoding, caExchangeCertificate);
    }

    /// <inheritdoc />
    public CertificateRevocationListDistributionPointCollection GetCrlDpCollection(string configString,
        bool textualEncoding = false)
    {
        return _inner.GetCrlDpCollection(configString, textualEncoding);
    }

    /// <inheritdoc />
    public AuthorityInformationAccessCollection GetAiaCollection(string configString, bool textualEncoding = false)
    {
        return _inner.GetAiaCollection(configString, textualEncoding);
    }

    /// <inheritdoc />
    public void RevokeCertificate(string configString, string serialNumber, RevocationReason reason,
        WindowsIdentity identity)
    {
        _inner.RevokeCertificate(configString, serialNumber, reason, identity);
    }

    /// <inheritdoc />
    public bool AllowsForCertificateManagement(string configString, WindowsIdentity identity)
    {
        var cacheKey = (Method: nameof(AllowsForCertificateManagement), configString, Sid: identity.User);

        return _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = CacheDuration;
            return _inner.AllowsForCertificateManagement(configString, identity);
        });
    }
}
