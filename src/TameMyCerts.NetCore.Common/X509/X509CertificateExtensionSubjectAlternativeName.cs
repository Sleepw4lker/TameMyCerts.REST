// Copyright © Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using CERTENROLLLib;
using TameMyCerts.NetCore.Common.Models;

namespace TameMyCerts.NetCore.Common.X509;

/// <summary>
///     Builds the Subject Alternative Name (SAN) X.509 certificate extension (RFC 5280, section 4.2.1.6).
/// </summary>
public class X509CertificateExtensionSubjectAlternativeName : X509CertificateExtension
{
    /// <summary>
    ///     An indicator if the extension was modified. If not, it returns the un-changed RawData.
    /// </summary>
    private bool _modified;

    /// <summary>
    ///     Builds an empty extension.
    /// </summary>
    public X509CertificateExtensionSubjectAlternativeName()
    {
    }

    /// <summary>
    ///     Builds the extension by decoding an existing, ASN.1 DER encoded extension value.
    /// </summary>
    /// <param name="rawData">The ASN.1 DER encoded extension value.</param>
    public X509CertificateExtensionSubjectAlternativeName(byte[] rawData)
    {
        InitializeDecode(Convert.ToBase64String(rawData));
    }

    /// <summary>
    ///     Builds the extension by decoding an existing, BASE64 encoded extension value.
    /// </summary>
    /// <param name="rawData">The BASE64 encoded extension value.</param>
    public X509CertificateExtensionSubjectAlternativeName(string rawData)
    {
        InitializeDecode(rawData);
    }

    /// <summary>
    ///     The alternative names contained in the extension, keyed by their <see cref="SanTypes" /> type.
    /// </summary>
    public List<KeyValuePair<string, string>> AlternativeNames { get; } = new();

    private void InitializeDecode(string rawData)
    {
        var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

        try
        {
            extensionAlternativeNames.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, rawData);

            RawData = Convert.FromBase64String(extensionAlternativeNames
                .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64).Replace(Environment.NewLine, string.Empty));

            foreach (IAlternativeName san in extensionAlternativeNames.AlternativeNames)
            {
                switch (san.Type)
                {
                    case AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME:

                        AlternativeNames.Add(
                            new KeyValuePair<string, string>(SanTypes.DnsName, san.strValue));
                        break;

                    case AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME:

                        AlternativeNames.Add(
                            new KeyValuePair<string, string>(SanTypes.Rfc822Name, san.strValue));
                        break;

                    case AlternativeNameType.XCN_CERT_ALT_NAME_URL:

                        AlternativeNames.Add(
                            new KeyValuePair<string, string>(SanTypes.UniformResourceIdentifier,
                                san.strValue));
                        break;

                    case AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME:

                        AlternativeNames.Add(
                            new KeyValuePair<string, string>(SanTypes.UserPrincipalName,
                                san.strValue));
                        break;

                    case AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS:

                        AlternativeNames.Add(new KeyValuePair<string, string>(SanTypes.IpAddress,
                            new IPAddress(
                                    Convert.FromBase64String(san.get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64)))
                                .ToString()));
                        break;

                    // Others are not supported and will be discarded without further notice, should the extension be modified.
                }

                Marshal.ReleaseComObject(san);
            }
        }
        catch
        {
            Marshal.ReleaseComObject(extensionAlternativeNames);
            throw;
        }

        Marshal.ReleaseComObject(extensionAlternativeNames);
    }

    /// <summary>
    ///     Builds <see cref="X509CertificateExtension.RawData" /> from the added or removed alternative names, if any.
    /// </summary>
    public void InitializeEncode()
    {
        // This ensures we return the unmodified original RawData if the Extension was not modified.
        if (!_modified)
        {
            return;
        }

        if (AlternativeNames.Count == 0)
        {
            RawData = Array.Empty<byte>();
            return;
        }

        var alternativeNames = new CAlternativeNames();

        foreach (var keyValuePair in AlternativeNames)
        {
            var alternativeName = new CAlternativeName();

            switch (keyValuePair.Key)
            {
                case SanTypes.DnsName:
                    alternativeName.InitializeFromString(
                        AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                        keyValuePair.Value);
                    break;

                case SanTypes.IpAddress:
                    alternativeName.InitializeFromRawData(
                        AlternativeNameType.XCN_CERT_ALT_NAME_IP_ADDRESS,
                        EncodingType.XCN_CRYPT_STRING_BASE64,
                        Convert.ToBase64String(IPAddress.Parse(keyValuePair.Value).GetAddressBytes()));
                    break;

                case SanTypes.UserPrincipalName:
                    alternativeName.InitializeFromString(
                        AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME,
                        keyValuePair.Value);
                    break;

                case SanTypes.Rfc822Name:
                    alternativeName.InitializeFromString(
                        AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME,
                        keyValuePair.Value);
                    break;

                case SanTypes.UniformResourceIdentifier:
                    alternativeName.InitializeFromString(
                        AlternativeNameType.XCN_CERT_ALT_NAME_URL,
                        keyValuePair.Value);
                    break;
            }

            alternativeNames.Add(alternativeName);
            Marshal.ReleaseComObject(alternativeName);
        }

        var extensionAlternativeNames = new CX509ExtensionAlternativeNames();

        extensionAlternativeNames.InitializeEncode(alternativeNames);
        Marshal.ReleaseComObject(alternativeNames);

        RawData = Convert.FromBase64String(extensionAlternativeNames
            .get_RawData(EncodingType.XCN_CRYPT_STRING_BASE64).Replace(Environment.NewLine, string.Empty));

        Marshal.ReleaseComObject(extensionAlternativeNames);
    }

    /// <summary>
    ///     Adds a dNSName alternative name.
    /// </summary>
    /// <param name="value">The DNS name to add.</param>
    public void AddDnsName(string value)
    {
        AddAlternativeName(SanTypes.DnsName, value);
    }

    /// <summary>
    ///     Adds an iPAddress alternative name.
    /// </summary>
    /// <param name="value">The IP address to add.</param>
    public void AddIpAddress(IPAddress value)
    {
        AddAlternativeName(SanTypes.IpAddress, value.ToString());
    }

    /// <summary>
    ///     Adds a userPrincipalName (otherName) alternative name.
    /// </summary>
    /// <param name="value">The user principal name to add.</param>
    public void AddUserPrincipalName(string value)
    {
        AddAlternativeName(SanTypes.UserPrincipalName, value);
    }

    /// <summary>
    ///     Adds an rfc822Name alternative name.
    /// </summary>
    /// <param name="value">The email address to add.</param>
    public void AddEmailAddress(string value)
    {
        AddAlternativeName(SanTypes.Rfc822Name, value);
    }

    /// <summary>
    ///     Adds an rfc822Name alternative name.
    /// </summary>
    /// <param name="value">The email address to add.</param>
    public void AddEmailAddress(MailAddress value)
    {
        AddAlternativeName(SanTypes.Rfc822Name, value.ToString());
    }

    /// <summary>
    ///     Adds a uniformResourceIdentifier alternative name, parsed from a string.
    /// </summary>
    /// <param name="value">The URI to add.</param>
    public void AddUniformResourceIdentifier(string value)
    {
        AddAlternativeName(SanTypes.UniformResourceIdentifier, value);
    }

    /// <summary>
    ///     Adds a uniformResourceIdentifier alternative name.
    /// </summary>
    /// <param name="value">The URI to add.</param>
    public void AddUniformResourceIdentifier(Uri value)
    {
        AddAlternativeName(SanTypes.UniformResourceIdentifier, value.ToString());
    }

    /// <summary>
    ///     Removes a dNSName alternative name.
    /// </summary>
    /// <param name="value">The DNS name to remove.</param>
    public void RemoveDnsName(string value)
    {
        RemoveAlternativeName(SanTypes.DnsName, value);
    }

    /// <summary>
    ///     Removes an iPAddress alternative name.
    /// </summary>
    /// <param name="value">The IP address to remove.</param>
    public void RemoveIpAddress(IPAddress value)
    {
        RemoveAlternativeName(SanTypes.IpAddress, value.ToString());
    }

    /// <summary>
    ///     Removes a userPrincipalName (otherName) alternative name.
    /// </summary>
    /// <param name="value">The user principal name to remove.</param>
    public void RemoveUserPrincipalName(string value)
    {
        RemoveAlternativeName(SanTypes.UserPrincipalName, value);
    }

    /// <summary>
    ///     Removes an rfc822Name alternative name.
    /// </summary>
    /// <param name="value">The email address to remove.</param>
    public void RemoveEmailAddress(string value)
    {
        RemoveAlternativeName(SanTypes.Rfc822Name, value);
    }

    /// <summary>
    ///     Removes an rfc822Name alternative name.
    /// </summary>
    /// <param name="value">The email address to remove.</param>
    public void RemoveEmailAddress(MailAddress value)
    {
        RemoveAlternativeName(SanTypes.Rfc822Name, value.ToString());
    }

    /// <summary>
    ///     Removes a uniformResourceIdentifier alternative name, parsed from a string.
    /// </summary>
    /// <param name="value">The URI to remove.</param>
    public void RemoveUniformResourceIdentifier(string value)
    {
        RemoveAlternativeName(SanTypes.UniformResourceIdentifier, value);
    }

    /// <summary>
    ///     Removes a uniformResourceIdentifier alternative name.
    /// </summary>
    /// <param name="value">The URI to remove.</param>
    public void RemoveUniformResourceIdentifier(Uri value)
    {
        RemoveAlternativeName(SanTypes.UniformResourceIdentifier, value.ToString());
    }

    /// <summary>
    ///     Essentially the same as TryAddAlternativeName but without caring for the result.
    /// </summary>
    /// <param name="type">The <see cref="SanTypes" /> type of the alternative name.</param>
    /// <param name="value">The value of the alternative name.</param>
    /// <param name="throwOnError">Throws an <see cref="ArgumentException" /> if the alternative name was rejected.</param>
    public void AddAlternativeName(string type, string value, bool throwOnError = false)
    {
        if (!TryAddAlternativeName(type, value) && throwOnError)
        {
            // TODO: Resource files...
            throw new ArgumentException();
        }
    }

    /// <summary>
    ///     Validates and adds an alternative name, unless it is already present.
    /// </summary>
    /// <param name="type">The <see cref="SanTypes" /> type of the alternative name.</param>
    /// <param name="value">The value of the alternative name.</param>
    /// <returns><see langword="false" /> if the value does not validate for the given type.</returns>
    public bool TryAddAlternativeName(string type, string value)
    {
        if (ContainsAlternativeName(type, value))
        {
            return true;
        }

        switch (type)
        {
            case SanTypes.DnsName:

                if (Uri.CheckHostName(value) != UriHostNameType.Dns)
                {
                    return false;
                }

                break;

            case SanTypes.Rfc822Name:
            case SanTypes.UserPrincipalName:

                try
                {
                    _ = new MailAddress(value);
                }
                catch
                {
                    return false;
                }

                break;

            case SanTypes.IpAddress:

                if (!IPAddress.TryParse(value, out _))
                {
                    return false;
                }

                break;

            case SanTypes.UniformResourceIdentifier:

                if (!Uri.TryCreate(value, UriKind.Absolute, out _))
                {
                    return false;
                }

                break;

            default: return false;
        }

        AlternativeNames.Add(new KeyValuePair<string, string>(type, value));
        _modified = true;

        return true;
    }

    /// <summary>
    ///     Determines whether the given alternative name is already present.
    /// </summary>
    /// <param name="type">The <see cref="SanTypes" /> type of the alternative name.</param>
    /// <param name="value">The value of the alternative name.</param>
    public bool ContainsAlternativeName(string type, string value)
    {
        return AlternativeNames.Contains(new KeyValuePair<string, string>(type, value));
    }

    /// <summary>
    ///     Removes an alternative name, if present.
    /// </summary>
    /// <param name="type">The <see cref="SanTypes" /> type of the alternative name.</param>
    /// <param name="value">The value of the alternative name.</param>
    public void RemoveAlternativeName(string type, string value)
    {
        if (!ContainsAlternativeName(type, value))
        {
            return;
        }

        AlternativeNames.Remove(new KeyValuePair<string, string>(type, value));
        _modified = true;
    }
}