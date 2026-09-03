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

using System.Runtime.InteropServices;
using CERTENROLLLib;

namespace TameMyCerts.NetCore.Common.Models;

/// <summary>
///     Information about an extended key usage.
/// </summary>
public class ExtendedKeyUsage
{
    /// <summary>
    ///     Builds the ExtendedKeyUsage out of a given object identifier.
    /// </summary>
    /// <param name="objectIdentifier">The object identifier of the extended key usage.</param>
    public ExtendedKeyUsage(string objectIdentifier)
    {
        ObjectIdentifier = objectIdentifier;

        var cObjectId = new CObjectId();

        try
        {
            cObjectId.InitializeFromValue(objectIdentifier);
            FriendlyName = cObjectId.FriendlyName;
        }
        catch
        {
            FriendlyName = "unknown";
        }
        finally
        {
            Marshal.ReleaseComObject(cObjectId);
        }
    }

    /// <summary>
    ///     The object identifier of the extended key usage.
    /// </summary>
    public string ObjectIdentifier { get; }

    /// <summary>
    ///     The friendly name of the extended key usage.
    /// </summary>
    public string FriendlyName { get; }
}