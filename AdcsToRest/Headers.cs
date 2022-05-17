// Some constants that are defined in Windows SDK header files

namespace AdcsToRest
{
    // Constants from CertCli.h
    static class CertCli
    {
        // See also https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_KEYGEN = 0x200;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;
        public const int CR_IN_FULLRESPONSE = 0x40000;

        public const int CR_IN_BASE64HEADER = 0;
        public const int CR_IN_BASE64 = 1;
        public const int CR_OUT_BASE64HEADER = 0;
        public const int CR_OUT_BASE64 = 1;
        public const int CR_OUT_CHAIN = 0x100;

        public const int CR_DISP_INCOMPLETE = 0;
        public const int CR_DISP_ERROR = 1;
        public const int CR_DISP_DENIED = 2;
        public const int CR_DISP_ISSUED = 3;
        public const int CR_DISP_ISSUED_OUT_OF_BAND = 4;
        public const int CR_DISP_UNDER_SUBMISSION = 5;
    }

    // Constants from WinError.h
    static class WinError
    {
        // The operation completed successfully.
        public const int ERROR_SUCCESS = 0;

        //  The data is invalid.
        public const int ERROR_INVALID_DATA = 13;

        // One or more arguments are not correct.
        public const int ERROR_BAD_ARGUMENTS = 160;
    }
}