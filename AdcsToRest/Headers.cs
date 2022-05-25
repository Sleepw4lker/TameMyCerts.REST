// Some constants that are defined in Windows SDK header files

namespace AdcsToRest
{
    // Constants from CertCli.h
    static class CertCli
    {
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

        public const int CR_PROP_CASIGCERTCOUNT = 0xB;
        public const int CR_PROP_BASECRL = 0x11;
        public const int CR_PROP_DELTACRL = 0x12;
        public const int CR_PROP_CRLSTATE = 0x14;
        public const int CR_PROP_CERTCDPURLS = 0x29;
        public const int CR_PROP_CERTAIAURLS = 0x30;
    }

    // Constants from CertSrv.h
    static class CertSrv
    {
        public const int PROPTYPE_LONG = 1;
        public const int PROPTYPE_BINARY = 3;
        public const int PROPTYPE_STRING = 4;
    }

    // Constants from CertView.h
    static class CertView
    {
        public const int CV_OUT_BASE64X509CRLHEADER = 0x9;
    }

    // Constants from CertAdm.h
    static class CertAdm
    {
        public const int CA_DISP_INCOMPLETE = 0;
        public const int CA_DISP_ERROR = 0x01;
        public const int CA_DISP_REVOKED = 0x02;
        public const int CA_DISP_VALID = 0x03;
        public const int CA_DISP_INVALID = 0x04;
        public const int CA_DISP_UNDER_SUBMISSION = 0x5;
    }

    // Constants from WinError.h
    static class WinError
    {
        // The operation completed successfully.
        public const int ERROR_SUCCESS = 0;
    }
}