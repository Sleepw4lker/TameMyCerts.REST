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

using System.ComponentModel.DataAnnotations;

namespace TameMyCerts.REST.Models;

/// <summary>
///     A data structure describing a certificate to revoke.
/// </summary>
public class RevocationRequest
{
    /// <summary>
    ///     The serial number of the certificate to revoke, as a hexadecimal string.
    /// </summary>
    [Required]
    public required string SerialNumber { get; set; }

    /// <summary>
    ///     The reason for the revocation.
    /// </summary>
    public RevocationReason Reason { get; set; } = RevocationReason.Unspecified;
}
