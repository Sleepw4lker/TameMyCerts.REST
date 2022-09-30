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

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using AdcsToRest.Models;

namespace AdcsToRest.Controllers
{
    /// <summary>
    ///     An API controller for all operations related to certificate templates.
    /// </summary>
    public class CertificateTemplatesController : ApiController
    {
        /// <summary>
        ///     Retrieves a collection of all certificate templates in the underlying Active Directory environment.
        /// </summary>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-templates")]
        public CertificateTemplateCollection GetCertificateTemplateCollection()
        {
            return new CertificateTemplateCollection();
        }

        /// <summary>
        ///     Retrieves details for a certificate template.
        /// </summary>
        /// <param name="certificateTemplate">The name of the target certificate template.</param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-templates/{certificateTemplate}")]
        public CertificateTemplate GetCertificateTemplate(string certificateTemplate)
        {
            try
            {
                return new CertificateTemplate(certificateTemplate);
            }
            catch (ArgumentException ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.NotFound)
                {
                    Content = new StringContent(ex.Message)
                });
            }
        }

        /// <summary>
        ///     Retrieves a collection of certification authorities that issue certificates for a given certificate template.
        /// </summary>
        /// <param name="certificateTemplate">The name of the target certificate template.</param>
        /// <param name="textualEncoding">
        ///     Causes returned PKIX data to be encoded according to RFC 7468 instead of a plain BASE64 stream.
        /// </param>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-templates/{certificateTemplate}/issuers")]
        public CertificationAuthorityCollection GetCertificateTemplateIssuers(string certificateTemplate,
            [FromUri] bool textualEncoding = false)
        {
            return new CertificationAuthorityCollection(ActiveDirectory
                .GetCertificationAuthorityCollection(textualEncoding).CertificationAuthorities.Where(
                    certificationAuthority =>
                        certificationAuthority.CertificateTemplates.Contains(certificateTemplate,
                            StringComparer.InvariantCultureIgnoreCase)).ToList());
        }
    }
}