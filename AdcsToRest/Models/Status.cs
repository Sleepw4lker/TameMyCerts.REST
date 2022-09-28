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
    ///     Additional status information about the outcome of the submission process.
    /// </summary>
    public class Status
    {
        public Status(int statusCode)
        {
            var statusMessage = new Win32Exception(statusCode).Message;

            StatusCode = statusCode;
            Description = statusCode == WinError.ERROR_SUCCESS
                ? statusMessage
                : $"{statusMessage}. 0x{statusCode:X} ({statusCode})";
        }

        /// <summary>
        ///     The result code returned by the certification authority during the submission process.
        /// </summary>
        public int StatusCode { get; set; }

        /// <summary>
        ///     The message the certification authority returned alongside with the result code.
        /// </summary>
        public string Description { get; set; }
    }
}