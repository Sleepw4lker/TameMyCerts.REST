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
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.REST.Models;

namespace TameMyCerts.REST;

/// <summary>
///     Resolves the Windows identity for a request, looks up an enrollment subject (a certification
///     authority or a certificate template), and checks whether the identity may enroll for it.
/// </summary>
public static class EnrollmentAuthorizationGate
{
    /// <summary>
    ///     Resolves the Windows identity for the current request.
    /// </summary>
    /// <param name="identity">The identity presented on the request.</param>
    /// <param name="user">The resolved Windows identity, when successful.</param>
    /// <param name="error">The response to return, when unsuccessful.</param>
    public static bool TryGetIdentity(IIdentity? identity, out WindowsIdentity user, out ActionResult error)
    {
        if (identity is WindowsIdentity windowsIdentity)
        {
            user = windowsIdentity;
            error = null!;
            return true;
        }

        user = null!;
        error = IdentityUnavailable();
        return false;
    }

    /// <summary>
    ///     Resolves the Windows identity for the current request, looks up the enrollment subject, and
    ///     checks whether the identity may enroll for it.
    /// </summary>
    /// <param name="identity">The identity presented on the request.</param>
    /// <param name="lookup">Resolves the subject to authorize against, e.g. by name.</param>
    /// <param name="notFoundMessage">
    ///     The message to return when the subject cannot be found, or <see langword="null" /> for a plain 404.
    /// </param>
    /// <param name="deniedMessage">The message to return when the identity may not enroll for the subject.</param>
    /// <param name="subject">The resolved subject, when successful.</param>
    /// <param name="user">The resolved Windows identity, when successful.</param>
    /// <param name="error">The response to return, when unsuccessful.</param>
    public static bool TryAuthorize<T>(
        IIdentity? identity,
        Func<T?> lookup,
        Func<string>? notFoundMessage,
        Func<T, string> deniedMessage,
        out T subject,
        out WindowsIdentity user,
        out ActionResult error)
        where T : class, IEnrollmentSubject
    {
        subject = null!;

        if (!TryGetIdentity(identity, out user, out error))
        {
            return false;
        }

        var found = lookup();

        if (found is null)
        {
            error = notFoundMessage is null ? new NotFoundResult() : new NotFoundObjectResult(notFoundMessage());
            return false;
        }

        if (!found.AllowsForEnrollment(user))
        {
            error = new UnauthorizedObjectResult(deniedMessage(found));
            return false;
        }

        subject = found;
        error = null!;
        return true;
    }

    private static ActionResult IdentityUnavailable()
    {
        return new ObjectResult(new ProblemDetails { Status = StatusCodes.Status500InternalServerError })
        {
            StatusCode = StatusCodes.Status500InternalServerError
        };
    }
}
