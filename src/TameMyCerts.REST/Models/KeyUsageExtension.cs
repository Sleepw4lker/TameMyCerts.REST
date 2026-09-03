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
///     Information about the key usage extension of the certificate template.
/// </summary>
public class KeyUsageExtension
{
    /// <summary>
    ///     Builds a KeyUsageExtension out of a given byte array.
    /// </summary>
    /// <param name="bytes">The byte array to build the object from.</param>
    /// <param name="critical">Indicates whether the extension is critical or not.</param>
    public KeyUsageExtension(IReadOnlyList<byte> bytes, bool critical = false)
    {
        // BitConverter expects 4 Bytes, whereas we have only one
        var newBytes = new byte[] { bytes[0], 0, 0, 0 };
        var keyUsage = BitConverter.ToInt32(newBytes, 0);

        Value = keyUsage;
        Critical = critical;
        KeyUsages = (from int keyUsageFlag in Enum.GetValues(typeof(KeyUsage.KeyUsageType))
            where (keyUsage & keyUsageFlag) == keyUsageFlag
            select new KeyUsage(keyUsageFlag)).ToList();
    }

    /// <summary>
    ///     The numerical value of the extension.
    /// </summary>
    public int Value { get; }

    /// <summary>
    ///     Indicates whether the extension is critical or not.
    /// </summary>
    public bool Critical { get; }

    /// <summary>
    ///     A list of key usages of the certificate template.
    /// </summary>
    public List<KeyUsage> KeyUsages { get; }
}