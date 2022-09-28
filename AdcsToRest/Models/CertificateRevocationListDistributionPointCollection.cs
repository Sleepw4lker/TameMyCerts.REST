// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Collections.Generic;

namespace AdcsToRest.Models
{
    /// <summary>
    ///     Contains a list of certificate revocation list distribution points.
    /// </summary>
    public class CertificateRevocationListDistributionPointCollection
    {
        /// <summary>
        ///     Builds the collection out of a given list of certificate revocation list distribution points.
        /// </summary>
        public CertificateRevocationListDistributionPointCollection(
            List<CertificateRevocationListDistributionPoint> certificateRevocationListDistributionPoints)
        {
            CertificateRevocationListDistributionPoints = certificateRevocationListDistributionPoints;
        }

        /// <summary>
        ///     Contains a list of certificate revocation list distribution points.
        /// </summary>
        public List<CertificateRevocationListDistributionPoint> CertificateRevocationListDistributionPoints
        {
            get;
            set;
        }
    }
}