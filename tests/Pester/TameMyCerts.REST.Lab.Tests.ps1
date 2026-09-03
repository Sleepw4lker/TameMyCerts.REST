#Requires -Modules @{ ModuleName = "Pester"; ModuleVersion = "5.0" }

<#
    .SYNOPSIS
    Pester integration tests for the TameMyCerts REST API, run against a fully deployed lab:
    one Active Directory domain, one AD CS certification authority, and the API itself
    reachable over HTTPS.

    .DESCRIPTION
    Deliberately minimal. Anything already covered by the xUnit unit test suite under
    src/TameMyCerts.REST.Tests (permission-check logic, request-type detection, ACL
    parsing, DTO shape, etc. - all exercised there against fakes) is NOT retested here.

    This suite exists only to prove the things that can't be unit tested because they need
    real infrastructure: the actual LDAP query against Active Directory, the actual
    registry-backed certificate template cache, the actual DCOM round-trip to a live CA
    (submit, retrieve, CA/CRL/AIA property reads), and real AD ACL enforcement against a
    real domain identity - plus the real HTTP/JSON wiring in front of all of it.

    .PARAMETER BaseUri
    Base URL of the deployed API, e.g. https://ca01.contoso.com/TameMyCerts.REST

    .PARAMETER Credential
    Credentials of a domain user with enrollment permission on at least one certification
    authority and one certificate template reachable through the API, and with "Issue and
    Manage Certificates" permission on that same certification authority (needed for the
    revoke tests).

    .PARAMETER CertificateTemplate
    Name (not display name) of a certificate template the above user may enroll for, that
    issues certificates automatically (no manager approval), used for the submit/retrieve
    tests.

    .PARAMETER DeniedCredential
    Optional. Credentials of a domain user WITHOUT enrollment permission on anything the API
    exposes, and WITHOUT "Issue and Manage Certificates" permission on the certification
    authority under test. If supplied, extra tests confirm real AD ACL enforcement for both
    permission kinds. Skipped otherwise.

    .PARAMETER SkipCertificateCheck
    Pass-through for labs serving the API over HTTPS with a self-signed or otherwise
    untrusted certificate.

    .EXAMPLE
    $cred = Get-Credential CONTOSO\svc-enrollment-test
    $data = @{
        BaseUri               = 'https://ca01.contoso.com/TameMyCerts.REST'
        Credential            = $cred
        CertificateTemplate   = 'RESTWebServer'
        SkipCertificateCheck  = $true
    }
    Invoke-Pester -Container (New-PesterContainer -Path .\TameMyCerts.REST.Lab.Tests.ps1 -Data $data)
#>

param(
    [Parameter(Mandatory)]
    [string]
    $BaseUri,

    [Parameter(Mandatory)]
    [PSCredential]
    $Credential,

    [Parameter(Mandatory)]
    [string]
    $CertificateTemplate,

    [PSCredential]
    $DeniedCredential,

    [switch]
    $SkipCertificateCheck
)

BeforeAll {
    $script:BaseUri = $BaseUri.TrimEnd('/')
    $script:Credential = $Credential
    $script:CertificateTemplate = $CertificateTemplate
    $script:SkipCertificateCheck = $SkipCertificateCheck.IsPresent

    # Invokes the API and returns the deserialized response. Throws on non-2xx, same as
    # Invoke-RestMethod normally does - callers that expect an error use Invoke-ApiStatusCode
    # instead of wrapping this in their own try/catch.
    function script:Invoke-Api {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [ValidateSet('GET', 'POST')] [string] $Method = 'GET',
            [hashtable] $Body,
            [PSCredential] $Credential,
            [switch] $NoAuth
        )

        if (-not $Credential) { $Credential = $script:Credential }

        $params = @{
            Uri    = "$script:BaseUri/$($Path.TrimStart('/'))"
            Method = $Method
        }
        if ($script:SkipCertificateCheck) { $params['SkipCertificateCheck'] = $true }
        if (-not $NoAuth) { $params['Credential'] = $Credential }
        if ($Body) {
            $params['Body'] = ($Body | ConvertTo-Json -Depth 5)
            $params['ContentType'] = 'application/json'
        }

        Invoke-RestMethod @params
    }

    # Runs an API call expected to fail and returns the HTTP status code, so negative-path
    # tests assert on the actual status rather than matching against exception text (which
    # differs between PowerShell 5.1's WebException and 7+'s HttpResponseException).
    function script:Invoke-ApiStatusCode {
        param([scriptblock] $ScriptBlock)

        try {
            & $ScriptBlock | Out-Null
            return $null
        }
        catch {
            return [int]$_.Exception.Response.StatusCode
        }
    }

    # Generates a fresh, real PKCS#10 CSR - no external module or certreq.exe dependency.
    function script:New-TestCertificateRequestBase64 {
        param([string] $Subject = 'CN=pester-test.contoso.com')

        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                $Subject,
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            [Convert]::ToBase64String($req.CreateSigningRequest())
        }
        finally {
            $rsa.Dispose()
        }
    }

    function script:Test-ParseableCertificate {
        param([Parameter(Mandatory)] [string] $Base64Der)

        $bytes = [Convert]::FromBase64String($Base64Der)
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes) | Out-Null
    }
}

Describe 'TameMyCerts REST API - lab integration' {

    Context 'Authentication' {
        It 'rejects requests without credentials' {
            Invoke-ApiStatusCode { Invoke-Api -Path 'v1/certification-authorities' -NoAuth } | Should -Be 401
        }
    }

    Context 'Certification authorities (real Active Directory lookup)' {

        BeforeAll {
            $script:Ca = (Invoke-Api -Path 'v1/certification-authorities').certificationAuthorities |
                Select-Object -First 1
            if (-not $script:Ca) {
                throw 'No certification authority was returned for the test credential - cannot continue this Context.'
            }
        }

        It 'returns at least one CA the test user may enroll from' {
            $script:Ca | Should -Not -BeNullOrEmpty
        }

        It 'returns details for that CA by name' {
            (Invoke-Api -Path "v1/certification-authorities/$($script:Ca.name)").name | Should -Be $script:Ca.name
        }

        It 'returns 404 for a certification authority that does not exist' {
            Invoke-ApiStatusCode { Invoke-Api -Path 'v1/certification-authorities/this-ca-does-not-exist' } |
                Should -Be 404
        }

        It 'returns a real, parseable CA certificate' {
            $result = Invoke-Api -Path "v1/certification-authorities/$($script:Ca.name)/ca-certificate"
            { Test-ParseableCertificate -Base64Der $result.certificate } | Should -Not -Throw
        }

        It 'returns CRL distribution point information' {
            { Invoke-Api -Path "v1/certification-authorities/$($script:Ca.name)/crl-distribution-points" } |
                Should -Not -Throw
        }

        It 'returns authority information access data' {
            { Invoke-Api -Path "v1/certification-authorities/$($script:Ca.name)/authority-information-access" } |
                Should -Not -Throw
        }
    }

    Context 'Certificate templates (real registry template cache lookup)' {

        It 'returns at least one certificate template the test user may enroll for' {
            (Invoke-Api -Path 'v1/certificate-templates').certificateTemplates | Should -Not -BeNullOrEmpty
        }

        It "returns details for the configured test template ($CertificateTemplate)" {
            (Invoke-Api -Path "v1/certificate-templates/$CertificateTemplate").name |
                Should -Be $script:CertificateTemplate
        }

        It 'returns 404 for a certificate template that does not exist' {
            Invoke-ApiStatusCode { Invoke-Api -Path 'v1/certificate-templates/this-template-does-not-exist' } |
                Should -Be 404
        }

        It 'lists at least one issuing CA for the configured test template' {
            (Invoke-Api -Path "v1/certificate-templates/$CertificateTemplate/issuers").certificationAuthorities |
                Should -Not -BeNullOrEmpty
        }
    }

    Context 'Certificate submission and retrieval (real DCOM round-trip to the CA)' {

        BeforeAll {
            $script:Ca = (Invoke-Api -Path "v1/certificate-templates/$CertificateTemplate/issuers").certificationAuthorities |
                Select-Object -First 1
            if (-not $script:Ca) {
                throw "No certification authority offers the configured test template '$CertificateTemplate' - cannot continue this Context."
            }

            $csr = New-TestCertificateRequestBase64
            $script:SubmitResponse = Invoke-Api -Method POST `
                -Path "v1/certificates/$($script:Ca.name)?certificateTemplate=$CertificateTemplate" `
                -Body @{ Request = $csr }
        }

        It 'issues or queues the request and returns a request id' {
            $script:SubmitResponse.disposition | Should -BeIn @('Issued', 'Pending')
            $script:SubmitResponse.requestId | Should -BeGreaterThan 0
        }

        It 'returns a real, parseable certificate when disposition is Issued' -Skip:($script:SubmitResponse.disposition -ne 'Issued') {
            { Test-ParseableCertificate -Base64Der $script:SubmitResponse.certificate } | Should -Not -Throw
        }

        It 'can retrieve the same request again by its request id' {
            $retrieved = Invoke-Api -Path "v1/certificates/$($script:Ca.name)/$($script:SubmitResponse.requestId)"
            $retrieved.requestId | Should -Be $script:SubmitResponse.requestId
            $retrieved.disposition | Should -Be $script:SubmitResponse.disposition
        }

        It 'rejects a request body that cannot be parsed as a certificate request' {
            $garbage = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('this is not a certificate request'))
            Invoke-ApiStatusCode {
                Invoke-Api -Method POST -Path "v1/certificates/$($script:Ca.name)" -Body @{ Request = $garbage }
            } | Should -Be 400
        }

        It 'revokes the issued certificate (real DCOM round-trip to ICertAdmin::RevokeCertificate)' -Skip:($script:SubmitResponse.disposition -ne 'Issued') {
            $certBytes = [Convert]::FromBase64String($script:SubmitResponse.certificate)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
            $script:RevokedSerialNumber = $cert.SerialNumber

            {
                Invoke-Api -Method POST -Path "v1/certificates/$($script:Ca.name)/revoke" `
                    -Body @{ SerialNumber = $script:RevokedSerialNumber; Reason = 'Superseded' }
            } | Should -Not -Throw
        }

        It 'reflects the revoked disposition on retrieval' -Skip:($script:SubmitResponse.disposition -ne 'Issued') {
            $retrieved = Invoke-Api -Path "v1/certificates/$($script:Ca.name)/$($script:SubmitResponse.requestId)"
            $retrieved.disposition | Should -Be 'Revoked'
        }
    }

    Context 'Real Active Directory permission enforcement' -Skip:(-not $DeniedCredential) {
        It 'returns no certification authorities to a user without enrollment permission on any of them' {
            $result = Invoke-Api -Path 'v1/certification-authorities' -Credential $DeniedCredential
            $result.certificationAuthorities | Should -BeNullOrEmpty
        }

        It 'returns 401 when a user without "Issue and Manage Certificates" permission attempts to revoke a certificate' {
            Invoke-ApiStatusCode {
                Invoke-Api -Method POST -Path "v1/certificates/$($script:Ca.name)/revoke" `
                    -Body @{ SerialNumber = '00' } -Credential $DeniedCredential
            } | Should -Be 401
        }
    }
}
