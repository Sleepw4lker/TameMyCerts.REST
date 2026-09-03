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

public class KeyUsage
{
    /// <summary>
    ///     Key Usage types according to RFC 5280.
    /// </summary>
    public enum KeyUsageType
    {
        /// <summary>
        ///     The digitalSignature bit is asserted when the subject public key is used for verifying digital signatures, other
        ///     than signatures on certificates , such as those used  in an entity authentication service, a data origin
        ///     authentication service, and/or an integrity service.
        /// </summary>
        digitalSignature = 0x80,

        /// <summary>
        ///     The nonRepudiation bit is asserted when the subject public key is used to verify digital signatures, other than
        ///     signatures on certificates , used to provide a non-repudiation service that protects against the signing entity
        ///     falsely denying some action. In the case of later conflict, a reliable third party may determine the authenticity
        ///     of the signed data.
        /// </summary>
        nonRepudiation = 0x40,

        /// <summary>
        ///     The keyEncipherment bit is asserted when the subject public key is used for enciphering private or secret keys,
        ///     i.e., for key transport. For example, this bit shall be set when an RSA public key is to be used for encrypting a
        ///     symmetric content-decryption key or an asymmetric private key.
        /// </summary>
        keyEncipherment = 0x20,

        /// <summary>
        ///     The dataEncipherment bit is asserted when the subject public key is used for directly enciphering raw user data
        ///     without the use of an intermediate symmetric cipher.
        /// </summary>
        dataEncipherment = 0x10,

        /// <summary>
        ///     The keyAgreement bit is asserted when the subject public key is used for key agreement. For example, when a
        ///     Diffie-Hellman key is to be used for key management, then this bit is set.
        /// </summary>
        keyAgreement = 0x8,

        /// <summary>
        ///     The keyCertSign bit is asserted when the subject public key is used for verifying signatures on public key
        ///     certificates.
        /// </summary>
        keyCertSign = 0x4,

        /// <summary>
        ///     The cRLSign bit is asserted when the subject public key is used for verifying signatures on certificate revocation
        ///     lists (e.g., CRLs, delta CRLs, or ARLs).
        /// </summary>
        cRLSign = 0x2,

        /// <summary>
        ///     The meaning of the encipherOnly bit is undefined in the absence of the keyAgreement bit.  When the encipherOnly bit
        ///     is asserted and the keyAgreement bit is also set,  the subject public key may be used only for enciphering data
        ///     while performing key agreement.
        /// </summary>
        encipherOnly = 0x1
    }

    /// <summary>
    ///     Builds a KeyUsage out of the given integer value.
    /// </summary>
    /// <param name="value">The value to build the object from.</param>
    public KeyUsage(int value)
    {
        Value = value;
        FriendlyName = (KeyUsageType)value;
    }

    /// <summary>
    ///     The numerical value of the key usage.
    /// </summary>
    public int Value { get; }

    /// <summary>
    ///     The friendly name of the key usage.
    /// </summary>
    public KeyUsageType FriendlyName { get; }
}