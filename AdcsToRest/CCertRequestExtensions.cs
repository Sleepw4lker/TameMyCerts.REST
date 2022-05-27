using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Web.Http;
using AdcsToRest.Models;
using CERTCLILib;

namespace AdcsToRest
{
    public static class CCertRequestExtensions
    {
        public static List<CertificateRevocationListDistributionPoint> GetCrlDpCollection(this CCertRequest certRequestInterface,
            string configString)
        {
            try
            {
                int caCertCount = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERTCOUNT, 0,
                    CertSrv.PROPTYPE_LONG, 0);

                var crlList = new List<CertificateRevocationListDistributionPoint>();

                for (var index = caCertCount - 1; index >= 0; index--)
                {
                    int crlState = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CRLSTATE, index,
                        CertSrv.PROPTYPE_LONG, 0);

                    if (crlState != CertAdm.CA_DISP_VALID)
                    {
                        continue;
                    }

                    string crlDistributionPoints = certRequestInterface.GetCAProperty(configString,
                        CertCli.CR_PROP_CERTCDPURLS, index,
                        CertSrv.PROPTYPE_STRING, 0);

                    crlList.Add(new CertificateRevocationListDistributionPoint
                    {
                        Crl = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_BASECRL, index,
                            CertSrv.PROPTYPE_BINARY, CertView.CV_OUT_BASE64X509CRLHEADER),
                        Urls = crlDistributionPoints.Split(new[] {"\n"},
                            StringSplitOptions.RemoveEmptyEntries).ToList()
                    });
                }

                return crlList;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED,
                        ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }

        public static List<AuthorityInformationAccess> GetAiaCollection(this CCertRequest certRequestInterface,
            string configString)
        {
            try
            {
                int caCertCount = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERTCOUNT, 0,
                    CertSrv.PROPTYPE_LONG, 0);

                var aiaList = new List<AuthorityInformationAccess>();

                for (var index = caCertCount - 1; index >= 0; index--)
                {
                    string aiaUrls = certRequestInterface.GetCAProperty(configString,
                        CertCli.CR_PROP_CERTAIAURLS, index,
                        CertSrv.PROPTYPE_STRING, 0);

                    string aiaOcspUrls = certRequestInterface.GetCAProperty(configString,
                        CertCli.CR_PROP_CERTAIAOCSPURLS, index,
                        CertSrv.PROPTYPE_STRING, 0);

                    aiaList.Add(new AuthorityInformationAccess
                    {
                        Certificate = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERT, index,
                            CertSrv.PROPTYPE_BINARY, CertView.CV_OUT_BASE64HEADER),
                        Urls = aiaUrls.Split(new[] {"\n"},
                            StringSplitOptions.RemoveEmptyEntries).ToList(),
                        OcspUrls = aiaOcspUrls.Split(new[] {"\n"},
                            StringSplitOptions.RemoveEmptyEntries).ToList()
                    });
                }

                return aiaList;
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED,
                        ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }

        public static SubmissionResponse RetrievePending2(this CCertRequest certRequestInterface, string configString,
            int requestId, bool includeCertificateChain = false)
        {
            try
            {
                var submissionResult =
                    certRequestInterface.RetrievePending(requestId, configString);

                return certRequestInterface.ProcessEnrollmentResult(submissionResult, includeCertificateChain);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }

        public static SubmissionResponse Submit2(this CCertRequest certRequestInterface, string configString,
            string rawCertificateRequest, List<string> requestAttributes, int submissionFlags,
            bool includeCertificateChain)
        {
            try
            {
                var submissionResult = certRequestInterface.Submit(
                    submissionFlags,
                    rawCertificateRequest,
                    string.Join(Environment.NewLine, requestAttributes.ToArray()),
                    configString
                );

                return certRequestInterface.ProcessEnrollmentResult(submissionResult,
                    includeCertificateChain);
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }

        public static SubmissionResponse GetCaCertificate2(this CCertRequest certRequestInterface, string configString,
            bool includeCertificateChain,
            bool caExchangeCertificate = false)
        {
            try
            {
                var outputFlags = CertCli.CR_OUT_BASE64HEADER;
                if (includeCertificateChain)
                {
                    outputFlags |= CertCli.CR_OUT_CHAIN;
                }

                return new SubmissionResponse
                (
                    WinError.ERROR_SUCCESS,
                    0, 0, null,
                    certRequestInterface.GetCACertificate(caExchangeCertificate ? 1 : 0, configString, outputFlags)
                );
            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent(string.Format(LocalizedStrings.DESC_SUBMISSION_FAILED, ex.Message)),
                    ReasonPhrase = LocalizedStrings.ERR_SUBMISSION_FAILED
                });
            }
            finally
            {
                Marshal.ReleaseComObject(certRequestInterface);
            }
        }

        private static SubmissionResponse ProcessEnrollmentResult(this CCertRequest certRequestInterface,
            int disposition, bool includeCertificateChain = false)
        {
            var result = new SubmissionResponse
            (
                certRequestInterface.GetLastStatus(),
                certRequestInterface.GetRequestId(),
                disposition,
                certRequestInterface.GetDispositionMessage()
            );

            if (disposition != CertCli.CR_DISP_ISSUED)
            {
                return result;
            }

            var outputFlags = CertCli.CR_OUT_BASE64HEADER;

            if (includeCertificateChain)
            {
                outputFlags |= CertCli.CR_OUT_CHAIN;
            }

            result.Certificate = certRequestInterface.GetCertificate(outputFlags);

            return result;
        }
    }
}