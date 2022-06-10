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
    /// <summary>
    ///     A data structure containing the result of a DCOM based operation against the CerSrv.request Interface of a
    ///     certification authority.
    /// </summary>
    public class SubmissionResponse
    {
        /// <summary>
        ///     Builds a SubmissionResponse data structure.
        /// </summary>
        /// <param name="statusCode">The HResult status code.</param>
        /// <param name="requestId">The request id, if any.</param>
        /// <param name="dispositionCode">The disposition code returned by the certificate authority, if any.</param>
        /// <param name="dispositionMessage">The disposition message text, if any.</param>
        /// <param name="certificate">The certificate, if any.</param>
        public SubmissionResponse(int statusCode, int requestId = 0, int dispositionCode = 0,
            string dispositionMessage = null, string certificate = null)
        {
            var statusMessage = new Win32Exception(statusCode).Message;

            StatusCode = statusCode;
            StatusMessage = statusCode == WinError.ERROR_SUCCESS ? statusMessage : $"{statusMessage}. 0x{statusCode:X} ({statusCode})";
            RequestId = requestId;
            DispositionCode = dispositionCode;
            DispositionMessage = dispositionMessage;
            Certificate = certificate;
        }

        /// <summary>
        ///     Status code for the connection to the certificate authority. Contains HResult error codes as defined in WinErr.h.
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        ///     A textual description of the HResult error code in statusCode.
        /// </summary>
        public string StatusMessage { get; set; }

        /// <summary>
        ///     The request ID of the issued certificate, or the pending request.
        /// </summary>
        public int RequestId { get; set; }

        /// <summary>
        ///     The disposition code returned by the certificate authority for the certificate request as defined in CertCli.h.
        ///     Can be one of: 0 (Request did not complete), 1 (Request failed), 2 (Request denied), 3 (Certificate issued), 4
        ///     (Certificate issued separately), 5 (Request taken under submission).
        /// </summary>
        public int DispositionCode { get; set; }

        /// <summary>
        ///     A textual description of the disposition status returned by the certificate authority.
        /// </summary>
        public string DispositionMessage { get; set; }

        /// <summary>
        ///     The issued X.509 V3 certificate, if issued by the certificate authority. Always returned as BASE64-encoded DER
        ///     with header (also known as PEM).
        /// </summary>
        public string Certificate { get; set; }
    }
}