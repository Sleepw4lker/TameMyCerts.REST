namespace TameMyCerts.NetCore.Common.Enums;

// Constants from CertView.h
internal static class CertView
{
    public const int CV_OUT_BASE64HEADER = 0;
    public const int CV_OUT_BASE64 = 0x1;
    public const int CV_OUT_BASE64X509CRLHEADER = 0x9;
    public const int CV_OUT_NOCRLF = 0x40000000;
}