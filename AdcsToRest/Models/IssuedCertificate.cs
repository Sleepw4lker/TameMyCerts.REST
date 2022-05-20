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

namespace AdcsToRest.Models
{
    public class IssuedCertificate
    {
        /// <summary>
        ///     A textual description of the outcome of the submission process.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        ///     Status code for the processing of incoming API requests and the connection to the certification authority, Contains
        ///     HResult error codes as defined in WinErr.h.
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        ///     A textual description of the HResult error code.
        /// </summary>
        public string StatusMessage { get; set; }

        /// <summary>
        ///     The request ID of the issued certificate, or the pending request.
        /// </summary>
        public int RequestId { get; set; } = 0;

        /// <summary>
        ///     The disposition code returned by the certification authority for the certificate request as defined in CertCli.h.
        /// </summary>
        public int DispositionCode { get; set; } = 0;

        /// <summary>
        ///     A textual description of the disposition status returned by the certification authority.
        /// </summary>
        public string DispositionMessage { get; set; }

        /// <summary>
        ///     The issued certificate, if issued by the certification authority. Always returned as BASE64-encoded DER (also known
        ///     as PEM).
        /// </summary>
        public string Certificate { get; set; } = null;
    }
}