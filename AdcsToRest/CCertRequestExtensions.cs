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
        public static List<CertificateRevocationList> GetCrlCollection(this CCertRequest certRequestInterface,
            string configString)
        {
            try
            {
                int caCertCount = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CASIGCERTCOUNT, 0,
                    CertSrv.PROPTYPE_LONG, 0);

                var crlList = new List<CertificateRevocationList>();

                for (var index = caCertCount - 1; index >= 0; index--)
                {
                    int crlState = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_CRLSTATE, index,
                        CertSrv.PROPTYPE_LONG, 0);

                    if (crlState != CertAdm.CA_DISP_VALID)
                    {
                        continue;
                    }

                    string y = certRequestInterface.GetCAProperty(configString,
                        CertCli.CR_PROP_CERTCDPURLS, index,
                        CertSrv.PROPTYPE_STRING, 0);

                    crlList.Add(new CertificateRevocationList
                    {
                        Crl = certRequestInterface.GetCAProperty(configString, CertCli.CR_PROP_BASECRL, index,
                            CertSrv.PROPTYPE_BINARY, CertView.CV_OUT_BASE64X509CRLHEADER),
                        CrlDistributionPoints = y.Split(new[] {"\n"},
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
                GC.Collect();
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
                GC.Collect();
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
                GC.Collect();
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
                    certRequestInterface.GetRequestId(),
                    0, null,
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
                GC.Collect();
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