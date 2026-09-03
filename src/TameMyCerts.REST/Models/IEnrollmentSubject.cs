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

using System.Security.Principal;

namespace TameMyCerts.REST.Models;

/// <summary>
///     Something an identity may or may not be permitted to enroll for, such as a certification authority
///     or a certificate template.
/// </summary>
public interface IEnrollmentSubject
{
    /// <summary>
    ///     Determines whether a given WindowsIdentity may enroll for this subject.
    /// </summary>
    /// <param name="identity">The Windows identity to check for permissions.</param>
    /// <param name="explicitlyPermitted">Return true only if the identity is explicitly mentioned in the acl.</param>
    bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false);
}
