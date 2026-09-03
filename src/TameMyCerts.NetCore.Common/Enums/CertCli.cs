namespace TameMyCerts.NetCore.Common.Enums;

/// <summary>
///     Constants from CertCli.h
/// </summary>
internal static class CertCli
{
    public const int CR_IN_BASE64 = 0x1;

    public const int CR_IN_PKCS10 = 0x100;
    public const int CR_IN_KEYGEN = 0x200;
    public const int CR_IN_PKCS7 = 0x300;
    public const int CR_IN_CMC = 0x400;
    public const int CR_IN_FULLRESPONSE = 0x40000;

    public const int CR_OUT_BASE64HEADER = 0x0;
    public const int CR_OUT_BASE64 = 0x1;
    public const int CR_OUT_CHAIN = 0x100;
    public const int CR_OUT_NOCRLF = 0x40000000;

    public const int CR_DISP_INCOMPLETE = 0;
    public const int CR_DISP_ERROR = 1;
    public const int CR_DISP_DENIED = 2;
    public const int CR_DISP_ISSUED = 3;
    public const int CR_DISP_ISSUED_OUT_OF_BAND = 4;
    public const int CR_DISP_UNDER_SUBMISSION = 5;
    public const int CR_DISP_REVOKED = 6;

    public const int CR_PROP_CASIGCERTCOUNT = 11;
    public const int CR_PROP_CASIGCERT = 12;
    public const int CR_PROP_BASECRL = 17;
    public const int CR_PROP_DELTACRL = 18;
    public const int CR_PROP_CRLSTATE = 20;
    public const int CR_PROP_CERTCDPURLS = 41;
    public const int CR_PROP_CERTAIAURLS = 42;
    public const int CR_PROP_CERTAIAOCSPURLS = 43;

    public const int FR_PROP_FULLRESPONSE = 1;
}