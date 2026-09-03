<#
    .SYNOPSIS
    Sample PowerShell client for the ADCS to REST API. It will automatically determine certificate request properties, 
    create a certificate request, find a certification authority to submit the request to, and install the issued certificate 
    after successful submission.

    .Parameter ComputerName
    The host name of the API endpoint, assuming that the API is installed under the /TameMyCerts.REST directory.

    .Parameter CertificateTemplate
    The certificate template to use.

    .Parameter Credential
    The logon credentials to use for authentication against the API.
#>

#requires -Modules @{ ModuleName="PSCertificateEnrollment"; ModuleVersion="1.0.6" }

[cmdletbinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ComputerName,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateTemplate,

    [Parameter(Mandatory=$false)]
    [PSCredential]
    $Credential = (Get-Credential)
)

process {

    # First we search for a certification authority that offers the desired certificate template.
    # If there is more than one, choose one by random. If there is none, it makes no sense to continue.

    $CertificationAuthority = (Invoke-RestMethod `
        -Credential $Credential `
        -Uri "https://$ComputerName/TameMyCerts.REST/v1/certificate-templates/$CertificateTemplate/issuers"
        ).certificationAuthorities | Get-Random -Count 1

    if (-not $CertificationAuthority)
    {
        Write-Error -Message "No certification authority offering the certificate template $CertificateTemplate was found."
        return
    }
    
    # Now we determine properties of the certificate template like key length and algorithm

    $CertificateTemplateInfo = Invoke-RestMethod `
        -Credential $Credential `
        -Uri "https://$ComputerName/TameMyCerts.REST/v1/certificate-templates/$CertificateTemplate/"

    # Now we create a certificate request based on the information we found. We assume this is an online template, thus the empty subject DN.

    $CertificateRequest = New-CertificateRequest `
        -Subject "CN=" `
        -KeyAlgorithm $CertificateTemplateInfo.keyAlgorithm `
        -KeyLength $CertificateTemplateInfo.minimumKeyLength

    # Now we can submit the certificate request to the certification authority

    $Body = @{
        Request = $CertificateRequest
        RequestAttributes = @("CertificateTemplate:$CertificateTemplate")
    }

    $Parameters = @{
        Method = "POST"
        Body = ($Body | ConvertTo-Json)
        ContentType = "application/json"
        Credential = $Credential
        Uri = "https://$ComputerName/TameMyCerts.REST/v1/certificates/$($CertificationAuthority.Name)"
    }

    $Response = (Invoke-RestMethod @Parameters)

    if ($Response.Disposition -ne "issued")
    {
        Write-Error -Message "Submission to $CertificationAuthority was not successful. $($Response.Status.Message)"
        return
    }

    # Finally, we install the returned certificate

    $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $CertificateObject.Import([Convert]::FromBase64String($Response.Certificate))
    $CertificateObject | Install-IssuedCertificate
}