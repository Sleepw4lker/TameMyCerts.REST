// Copyright 2022 Uwe Gradenegger

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

namespace AdcsToRest.Models
{
    /// <summary>
    ///     Information about an extended key usage.
    /// </summary>
    public class ExtendedKeyUsage
    {
        /// <summary>
        ///     Builds the ExtendedKeyUsage out of a given object identifier.
        /// </summary>
        /// <param name="oid">The object identifier of the extended key usage.</param>
        public ExtendedKeyUsage(string oid)
        {
            Oid = oid;

            var cObjectId = new CObjectId();

            try
            {
                cObjectId.InitializeFromValue(oid);
                FriendlyName = cObjectId.FriendlyName;
            }
            catch
            {
                FriendlyName = LocalizedStrings.UNKNOWN;
            }
            finally
            {
                Marshal.ReleaseComObject(cObjectId);
            }
        }

        /// <summary>
        ///     The object identifier of the extended key usage.
        /// </summary>
        public string Oid { get; }

        /// <summary>
        ///     The friendly name of the extended key usage.
        /// </summary>
        public string FriendlyName { get; }
    }
}