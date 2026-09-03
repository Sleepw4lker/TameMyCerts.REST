using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TameMyCerts.NetCore.Common.Models;

namespace TameMyCerts.REST.Tests;

public class EnrollmentAuthorizationGateTests
{
    private static readonly IIdentity WindowsUser = WindowsIdentity.GetCurrent();
    private static readonly IIdentity NonWindowsUser = new GenericIdentity("someone");

    private sealed class FakeSubject(bool allowed) : IEnrollmentSubject
    {
        public bool AllowsForEnrollment(WindowsIdentity identity, bool explicitlyPermitted = false)
        {
            return allowed;
        }
    }

    [Fact]
    public void TryGetIdentity_ReturnsWindowsIdentity_WhenIdentityIsWindows()
    {
        var result = EnrollmentAuthorizationGate.TryGetIdentity(WindowsUser, out var user, out var error);

        Assert.True(result);
        Assert.Same(WindowsUser, user);
        Assert.Null(error);
    }

    [Fact]
    public void TryGetIdentity_ReturnsServerError_WhenIdentityIsNotWindows()
    {
        var result = EnrollmentAuthorizationGate.TryGetIdentity(NonWindowsUser, out _, out var error);

        Assert.False(result);
        var objectResult = Assert.IsType<ObjectResult>(error);
        Assert.Equal(StatusCodes.Status500InternalServerError, objectResult.StatusCode);
    }

    [Fact]
    public void TryGetIdentity_ReturnsServerError_WhenIdentityIsNull()
    {
        var result = EnrollmentAuthorizationGate.TryGetIdentity(null, out _, out var error);

        Assert.False(result);
        Assert.IsType<ObjectResult>(error);
    }

    [Fact]
    public void TryAuthorize_ReturnsServerError_WhenIdentityIsNotWindows()
    {
        // Regression guard: this used to be the one call site (GetCertificateTemplate) that
        // returned Unauthorized() here instead of the 500 every other gated action returns.
        var result = EnrollmentAuthorizationGate.TryAuthorize<FakeSubject>(
            NonWindowsUser,
            () => new FakeSubject(true),
            (Func<string>?)null,
            _ => "denied",
            out _, out _, out var error);

        Assert.False(result);
        var objectResult = Assert.IsType<ObjectResult>(error);
        Assert.Equal(StatusCodes.Status500InternalServerError, objectResult.StatusCode);
    }

    [Fact]
    public void TryAuthorize_ReturnsPlainNotFound_WhenSubjectMissingAndNoMessageGiven()
    {
        var result = EnrollmentAuthorizationGate.TryAuthorize<FakeSubject>(
            WindowsUser,
            () => (FakeSubject?)null,
            (Func<string>?)null,
            _ => "denied",
            out _, out _, out var error);

        Assert.False(result);
        var notFound = Assert.IsType<NotFoundResult>(error);
        Assert.Equal(StatusCodes.Status404NotFound, notFound.StatusCode);
    }

    [Fact]
    public void TryAuthorize_ReturnsNotFoundWithMessage_WhenSubjectMissingAndMessageGiven()
    {
        var result = EnrollmentAuthorizationGate.TryAuthorize<FakeSubject>(
            WindowsUser,
            () => (FakeSubject?)null,
            () => "no such thing",
            _ => "denied",
            out _, out _, out var error);

        Assert.False(result);
        var notFound = Assert.IsType<NotFoundObjectResult>(error);
        Assert.Equal("no such thing", notFound.Value);
    }

    [Fact]
    public void TryAuthorize_ReturnsUnauthorized_WhenSubjectDeniesEnrollment()
    {
        var result = EnrollmentAuthorizationGate.TryAuthorize<FakeSubject>(
            WindowsUser,
            () => new FakeSubject(false),
            (Func<string>?)null,
            _ => "not permitted",
            out _, out _, out var error);

        Assert.False(result);
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(error);
        Assert.Equal("not permitted", unauthorized.Value);
    }

    [Fact]
    public void TryAuthorize_ReturnsSubjectAndIdentity_WhenAllowed()
    {
        var subject = new FakeSubject(true);

        var result = EnrollmentAuthorizationGate.TryAuthorize<FakeSubject>(
            WindowsUser,
            () => subject,
            (Func<string>?)null,
            _ => "not permitted",
            out var resolvedSubject, out var user, out var error);

        Assert.True(result);
        Assert.Same(subject, resolvedSubject);
        Assert.Same(WindowsUser, user);
        Assert.Null(error);
    }
}
