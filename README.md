# The TameMyCerts REST API
_(this project was renamed from "AdcsToRest")_

A simple, yet powerful REST API for submitting certificates to one or more Microsoft [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/windows/win32/seccrypto/certificate-services) certification authorities, written in C#.

## Introduction

The API allows for requesting certificates from systems that are not joined to the same Active Directory domain as the certification authorities (or not joined to any domain at all). It can serve any client operating system that is capable of submitting a REST API call. It converts certificate requests submitted via REST to the DCOM protocol. 

Therefore...

- It is perfectly suited for certificate issuance scenarios from Linux, BSD, cloud services and the like.
- It can also be used to connect cloud-native certificate management solutions (like [cert-manager](https://cert-manager.io]) or open source implementations of the ACME protocol (like [the Serles project](https://github.com/dvtirol/serles-acme)) to a Microsoft certification authority with this API.
- An awesome use case is to implement **certificate AutoEnrollment across Active Directory Forest boundaries** leveraging the [TameMyCerts WSTEP Proxy](https://github.com/Sleepw4lker/TameMyCerts.WSTEP).

> Sample client implementations are to be found in the [clients](clients/) directory.

## Getting started

Find the most recent version as a ready-to-use binary package on the [releases page](https://github.com/Sleepw4lker/TameMyCerts.REST/releases).

### Security and Implementation considerations

You don't (necessarily) need a service account. The integrated IIS application pool identity is sufficient if you use HTTP basic authentication ([RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617)). The chosen service account must have the _SeImpersonatePrivilege_ ("Impersonate a client after authentication") on the API web server, which by default is granted through membership of the local IIS_IUSRS security group.

Certificate requests appear on the certification authority under the security context of the Active Directory user that was authenticated at the API. Therfore, enrollment permissions are handled on the CA/Template level, exactly as you would do with the native RPC/DCOM protocol. You may want to combine the API with the [TameMyCerts policy module](https://github.com/Sleepw4lker/TameMyCerts) on your certification authorities to be able to strictly restrict requested certificate content.

I suggest using the API with [HTTP basic authentication](https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/basic-authentication). Windows Authentication (NTLM/Kerberos) and Client Certificate Authentication work as well, but I advise against these because you will need Kerberos Delegation which can be a very dangerous topic that should be used with extreme caution.

As the API requires authentication, it should only be used over HTTPS, and the HTTPS connection should be secured against replay attacks and the like.

You should easily be able to implement a high-availability setup behind a load balancer, as all API calls are stateless.

The API web server must be a domain member and able to contact both Active Directory Domain Controllers as well as each certification authority. For API to CA communications, you must allow ports 135/tcp and 49152-65535/tcp.

The API honors security permissions on certificate templates and certification authorities. A user will only get certificates and certification authorities presented on which he has the permissions to request certificates. Also, a user will only be able to communicate with a certification authority when he has permissions to request certificates on it. Therefore, you are able to control which certification authorities get presented through the "Request certificates" permission on the certification authority level.

### Supported Operating Systems and Prerequisites

The API was successfully tested with the following operating systems:

- Windows Server 2022
- Windows Server 2019

It *should* work as well with the following ones but this is yet to be tested.

- Windows Server 2016

Older Microsoft Windows operating systems are not supported.

For Windows Server 2016 and below, [.NET Framework 4.7.2](https://support.microsoft.com/en-us/topic/microsoft-net-framework-4-7-2-offline-installer-for-windows-05a72734-2127-a15d-50cf-daf56d5faec2) must be installed.

### Configuring Group Policy

To reduce network load, the API uses the _CertificateTemplateCache_ registry key of the web server, which requires that AutoEnrollment is enabled on the machine level (option "update certificates that use certificate templates"). Please ensure this is configured via group policy for the API server.

### Installing IIS

Install IIS with the following feature set:

```powershell
Install-WindowsFeature -Name Web-Server,Web-Basic-Auth,Web-Filtering,Web-IP-Security -IncludeManagementTools
```
Download and install the ASP .NET Core 8.0 [hosting bundle](https://dotnet.microsoft.com/permalink/dotnetcore-current-windows-runtime-bundle-installer).

Then ensure you have a SSL certificate installed and require SSL on the web site you plan to install the API onto.

### Installing the API

Register the Event Source with the below PowerShell command (as Administrator):

```powershell
[System.Diagnostics.EventLog]::CreateEventSource("TameMyCerts.REST", "Application")
```

Then simply copy the files from the _"wwwroot"_ folder of the downloaded package into the designated Web Root. No application configuration required.

> If you plan to use the API behind a load balancer, you might want to tweak or disable the _dynamicIpSecurity_ section in the [Web.config](Web.config) file.

### Configuring IIS

Configure your SSL Binding and ensure the "Require SSL" configuration parameter is set.

For Basic Authentication, on the web site, in authentication settings, do the following:

- Disable anonymous Authentication
- Enable Basic Authentication
- Configure your Default Domain for Basic Authentication

> It is advised to implement additional server hardening.

## Using the API

The API incorporates Swagger for automated documentation of the API operations. You can reach it under the _/swagger_ directory, which is the default directory when you access it via browser. Consult this resource for detailled information. You can find the API specification [here](v1.json).

The basic operations are as follows:

|Operation|Path|Description|
|---|---|---|
|GET|/v1/certificates/{caName}/{requestId}|Retrieves an issued certificate from a certification authority.|
|POST|/v1/certificates/{caName}|Submits a certificate signing request to a certification authority.|
|GET|/v1/certificate-templates|Retrieves a list of all certificate templates in the underlying Active Directory environment.|
|GET|/v1/certificate-templates/{certificateTemplate}|Retrieves details for a certificate template.|
|GET|/v1/certificate-templates/{certificateTemplate}/issuers|Retrieves certification authorities that issue certificates for a given certificate template.|
|GET|/v1/certification-authorities|Retrieves a collection of all available certification authorities.|
|GET|/v1/certification-authorities/{caName}|Retrieves details for a certification authority.|
|GET|/v1/certification-authorities/{caName}/ca-certificate|Retrieves the current certification authority certificate for a certification authority.|
|GET|/v1/certification-authorities/{caName}/ca-exchange-certificate|Retrieves the current certification authority exchange certificate for a certification authority.|
|GET|/v1/certification-authorities/{caName}/crl-distribution-points|Retrieves a collection of certificate revocation list distribution points for a certification authority.|
|GET|/v1/certification-authorities/{caName}/authority-information-access|Retrieves a collection of authority information access distribution points for a certification authority.|