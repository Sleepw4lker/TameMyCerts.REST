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

using System.Net;
using System.Web.Http;
using AdcsToRest.Models;

namespace AdcsToRest.Controllers
{
    public class CertificateTemplatesController : ApiController
    {
        /// <summary>
        ///     Retrieves a list of all certificate templates in the underlying Active Directory environment.
        /// </summary>
        [HttpGet]
        [Authorize]
        [Route("v1/certificate-templates")]
        public CertificateTemplateCollection GetCertificateTemplateCollection()
        {
            return ActiveDirectory.GetCertificateTemplateCollection();
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
            return ActiveDirectory.GetCertificateTemplate(certificateTemplate);
        }
    }
}