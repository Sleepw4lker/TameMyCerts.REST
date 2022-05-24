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

using System.ComponentModel;

namespace AdcsToRest.Models
{
    public class IssuedCertificate
    {
        public IssuedCertificate(int statusCode, int requestId = 0, int dispositionCode = 0,
            string dispositionMessage = null, string certificate = null)
        {
            StatusCode = statusCode;
            StatusMessage = new Win32Exception(statusCode).Message;
            RequestId = requestId;
            DispositionCode = dispositionCode;
            DispositionMessage = dispositionMessage;
            Certificate = certificate;
        }

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
        public int RequestId { get; set; }

        /// <summary>
        ///     The disposition code returned by the certification authority for the certificate request as defined in CertCli.h.
        ///     Can be one of: 0 (Request did not complete), 1 (Request failed), 2 (Request denied), 3 (Certificate issued), 4
        ///     (Certificate issued separately), 5 (Request taken under submission).
        /// </summary>
        public int DispositionCode { get; set; }

        /// <summary>
        ///     A textual description of the disposition status returned by the certification authority.
        /// </summary>
        public string DispositionMessage { get; set; }

        /// <summary>
        ///     The issued certificate, if issued by the certification authority. Always returned as BASE64-encoded DER (also known
        ///     as PEM).
        /// </summary>
        public string Certificate { get; set; }
    }
}