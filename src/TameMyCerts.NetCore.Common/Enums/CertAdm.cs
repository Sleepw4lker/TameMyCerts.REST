namespace TameMyCerts.NetCore.Common.Enums;

// Constants from CertAdm.h
internal static class CertAdm
{
    public const int CA_DISP_INCOMPLETE = 0;
    public const int CA_DISP_ERROR = 0x1;
    public const int CA_DISP_REVOKED = 0x2;
    public const int CA_DISP_VALID = 0x3;
    public const int CA_DISP_INVALID = 0x4;
    public const int CA_DISP_UNDER_SUBMISSION = 0x5;
}