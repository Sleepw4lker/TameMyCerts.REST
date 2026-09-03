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

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Looks up certificate templates from the machine's local certificate template cache.
/// </summary>
public interface ICertificateTemplateRepository
{
    /// <summary>
    ///     Looks up a certificate template by name.
    /// </summary>
    /// <param name="templateName">The name of the certificate template.</param>
    /// <returns><see langword="null" /> if no such certificate template is cached.</returns>
    CertificateTemplate? FindByName(string templateName);

    /// <summary>
    ///     Retrieves all (non-default, schema version 2 or higher) cached certificate templates.
    /// </summary>
    IReadOnlyList<CertificateTemplate> GetAll();
}
