// Some constants that are defined in Windows SDK header files

namespace AdcsToRest
{
    // Constants from CertCli.h
    internal static class CertCli
    {
        public const int CR_IN_BASE64 = 0x1;

        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;

        public const int CR_OUT_BASE64HEADER = 0x0;
        public const int CR_OUT_BASE64 = 0x1;
        public const int CR_OUT_CHAIN = 0x100;
        public const int CR_OUT_NOCRLF = 0x40000000;

        public const int CR_DISP_ISSUED = 0x3;
    }

    // Constants from WinError.h
    internal static class WinError
    {
        // The operation completed successfully.
        public const int ERROR_SUCCESS = 0x0;
    }
}