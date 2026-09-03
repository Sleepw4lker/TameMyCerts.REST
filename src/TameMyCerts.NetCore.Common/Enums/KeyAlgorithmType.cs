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

namespace TameMyCerts.NetCore.Common.Enums;

/// <summary>
///     Supported public key algorithm types.
/// </summary>
public enum KeyAlgorithmType
{
    /// <summary>
    ///     The RSA algorithm.
    /// </summary>
    RSA = 1,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp256 curve.
    /// </summary>
    ECDSA_P256 = 2,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp384 curve.
    /// </summary>
    ECDSA_P384 = 3,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp521 curve.
    /// </summary>
    ECDSA_P521 = 4,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp256 curve.
    /// </summary>
    ECDH_P256 = 5,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp384 curve.
    /// </summary>
    ECDH_P384 = 6,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp521 curve.
    /// </summary>
    ECDH_P521 = 7,

    /// <summary>
    ///     The digital signature algorithm.
    /// </summary>
    DSA = 8
}