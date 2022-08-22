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
    ///     A data structure containing the result of an operation against a certification authority.
    /// </summary>
    public class SubmissionResponse
    {
        /// <summary>
        ///     The possible disposition values returned by the certification authority.
        /// </summary>
        public enum DispositionCode
        {
            /// <summary>
            ///     Request did not complete
            /// </summary>
            Incomplete = 0,

            /// <summary>
            ///     Request failed
            /// </summary>
            Failed = 1,

            /// <summary>
            ///     Request denied
            /// </summary>
            Denied = 2,

            /// <summary>
            ///     Certificate issued
            /// </summary>
            Issued = 3,

            /// <summary>
            ///     Certificate issued separately
            /// </summary>
            IssuedSeparately = 4,

            /// <summary>
            ///     Request taken under submission
            /// </summary>
            Pending = 5
        }

        /// <summary>
        ///     Builds a SubmissionResponse data structure.
        /// </summary>
        /// <param name="statusCode">The HResult status code.</param>
        /// <param name="requestId">The request id, if any.</param>
        /// <param name="dispositionCode">The disposition code returned by the certificate authority, if any.</param>
        /// <param name="certificate">The certificate, if any.</param>
        public SubmissionResponse(int statusCode, int requestId = 0, int dispositionCode = 0, string certificate = null)
        {
            var statusMessage = new Win32Exception(statusCode).Message;
            Status = new Status(statusCode,
                statusCode == WinError.ERROR_SUCCESS
                    ? statusMessage
                    : $"{statusMessage}. 0x{statusCode:X} ({statusCode})");
            RequestId = requestId;
            Certificate = certificate;
            Disposition = (DispositionCode) dispositionCode;
        }

        /// <summary>
        ///     The request ID of the issued certificate, or the pending request.
        /// </summary>
        public int RequestId { get; set; }

        /// <summary>
        ///     The disposition status of the submission or retrieval request.
        /// </summary>
        public DispositionCode Disposition { get; set; }

        /// <summary>
        ///     Additional status information about the outcome of the submission process.
        /// </summary>
        public Status Status { get; set; }

        /// <summary>
        ///     The issued X.509 V3 certificate, if issued by the certificate authority, as BASE64-encoded DER.
        /// </summary>
        public string Certificate { get; set; }
    }
}