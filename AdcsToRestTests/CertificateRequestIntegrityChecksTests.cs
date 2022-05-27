// Copyright 2022 Uwe Gradenegger

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using AdcsToRest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AdcsToRestTests
{
    // Constants from CertCli.h
    public static class CertCli
    {
        public const int CR_IN_PKCS10 = 0x100;
        public const int CR_IN_PKCS7 = 0x300;
        public const int CR_IN_CMC = 0x400;
    }

    [TestClass]
    public class CertificateRequestIntegrityChecksTests
    {
        private const string NoCsr = "this is not a csr";

        private const string CsrPkcs10 =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDbTCCAlUCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApucZpFuF0+fvdL5C3jggO6vO\n" +
            "9PA39MnPG0VQBy1n2pdhD/WwIt3St6UuMTXyNzEqSqm396Dw6+1iLCcP4DioLywd\n" +
            "9rVHOAFmYNeahM24rYk9z+8rgx5a4GhtK6uSXD87aNDwz7l+QCnjapZu1bqfe/s+\n" +
            "Wzo3e/jiSNIUUiY6/DQnHcZpPn/nBruLih0muZFWCevIRwu/w05DMrX9KTKax06l\n" +
            "TJw+bQshKasiVDDW+0K5eDzvLu7cS6/Z9vVYHD7gGJNmX+YaJY+JS9tGaGyvDUiV\n" +
            "ww+Do5S8p13dXqY/xwMngkq3kkvTB8hstxE1pd07OQojZ1SaLFEyh3pX7abXMQID\n" +
            "AQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUsp05C4spRvndIOKWrM7O\n" +
            "aXVZLCUwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1PVFRF\n" +
            "TFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBp\n" +
            "AGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABv\n" +
            "AHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggEB\n" +
            "ABCVBVb7DJjiDP5SbSpw08nvrwnx5kiQ21xR7AJmtSYPLmsmC7uIPxk8Jsq1hDUO\n" +
            "e2adcbMup6QY7GJGuc4OWhiaisKAeZB7Tcy5SEZIWe85DlkxEgLVFB9opmf+V3fA\n" +
            "d/ZtYS0J7MPg6F9UEra30T3CcHlH5Y8NlMtaZmqjfXyw2C5YkahEfSmk2WVaZiSf\n" +
            "8edZDjIw5eRZY/9QMi2JEcmSbq0DImiP4ou46aQ0U5iRGSNX+armMIhGJ1ycDXTM\n" +
            "SBDUN6qWGioX8NHTlUmebLijw3zSFMnIuYWhXF7FZ1IKMPySzVmquvBAjzT4kWSw\n" +
            "0bAr5OaOzHm7POogsgE8J1Y=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        private const string CsrPkcs7 =
            "-----BEGIN PKCS #7 SIGNED DATA-----\n" +
            "MIINmAYJKoZIhvcNAQcCoIINiTCCDYUCAQExDzANBglghkgBZQMEAgEFADCCBKcG\n" +
            "CSqGSIb3DQEHAaCCBJgEggSUMIIEkDCCAvgCAQAwGTEXMBUGA1UEAxMOdGhpcy1p\n" +
            "cy1hLXRlc3QwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDrj8b+p7kZ\n" +
            "TBC9qNsTy/WUz15ZP9r2my4q0h3SqJHcWOMsw+rVn71hktdF0h7qJ01NpYj36h8P\n" +
            "/lJx+5n3ELqRmQmWuoT/pyv2JNpIr85DFHrOhyLnbeTmoPCffxbC13Htc5MsiNkw\n" +
            "zjJKccEIpThswSsv4Sb5rVpMTnI6hax00SbKOuvbLxgMlCk6XYFbLl17bjhs3S76\n" +
            "QHet6fzSjs6pweHpzvXVkSqT7SfBNcUjiKxE6kZdPq/i1H/UxpFmicl1QdKe41ng\n" +
            "CkHC++Exyd9Q6LpOItxwcyaGnjFjTEKhEcFafPESoiz4UhQe9cvezVA0GGkfMLIV\n" +
            "IHU8Oquo/CLfHypD7Zo3lidj7BLkNoJ2wjqYhyTN5bGMF8TjJwIuVCdSrxsy5PO/\n" +
            "1KhQlq8o15wZH87uq2RDmHwaPrUNnUvc+HDzBRK4zQRBgJkNgFMKmAzcg/lMZIjI\n" +
            "LubTYAUUxV+s1zayxX4AKUkOl0qwB408BlPR9AgonscyRgHZXoAC8BkCAwEAAaCC\n" +
            "ATAwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE4MzYzLjIwSgYJKwYBBAGCNxUUMT0w\n" +
            "OwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBv\n" +
            "d2Vyc2hlbGwuZXhlMFwGCSqGSIb3DQEJDjFPME0wDgYDVR0PAQH/BAQDAgeAMBwG\n" +
            "A1UdEQEB/wQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQWBBTGOY+4vRUIPXd/\n" +
            "VKw0lskOiBAsyDBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBgQDEXpI2qKbCcQNk\n" +
            "xFQ7zWIbpIEn1ZPYp4Yh1665KOR0AUXNNgD5DeuwOOv6TBZYhk2GG3NQbghCZRSU\n" +
            "W7ErrHciv4fIZn9lrvSvl8yeRCaZWe5Iq9Y/n8Mi+o30c5MRkpk2TpaXAWz91vbX\n" +
            "WkC6NctcazsbTg4O09pgZFwY1/+sjcwliCUYNfX2eIjrBqSDEzWFHRwXp0Nl8qLu\n" +
            "HDybDu8PJqRalGwjmHnbt5grqGpu7PLnpkGut71Jq5n+MM5k62E5tzDSA+6HEAUd\n" +
            "CL/uKS/fayVp7ZSAo93lXlml1o7CbEz7g7pIfMel+Pnrk3T6hFR/zbq8m+tlar4m\n" +
            "uohOBvnr5I3lDAGC4Yit/JEiZJRvT73ESEQvTZvlDSWyNt0sOOJEzYsGA2ASoINO\n" +
            "3ynSVhJCzeiwhT2p0X+2ghKY8hPhL5aFa6fxjqb/aj5gEk69eIfql3pzC3Bb6vbS\n" +
            "Ym9bWkxH134NkATEaweix9oKAjc/mDhJgE7w7oe4wTkSWIqMFougggcHMIIHAzCC\n" +
            "BOugAwIBAgITcwAIDlrU+8kfM1yNGQACAAgOWjANBgkqhkiG9w0BAQsFADB0MQsw\n" +
            "CQYDVQQGEwJERTEQMA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMw\n" +
            "EQYDVQQKEwpBRENTIExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBM\n" +
            "YWJvciBJc3N1aW5nIENBIDEwHhcNMjIwNTI3MTE0NTA2WhcNMjMwNTI3MTE0NTA2\n" +
            "WjAPMQ0wCwYDVQQDEwRydWRpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
            "AQEArAbgsEjyO5ntIYeXs03gYY7O36VwDTpXl/aZXnfYx/+0BnXc1jhR6ptj0T1J\n" +
            "BHsRk9jN1zjpmYqgPii2z09ngbcY8eiQMNvAgGurm/SW3JPzJyu9k0ymp8FL4AAQ\n" +
            "9WQL1uLDLfkq7AOna94Qw9m3Lj7NsqkH5Fz31Qv7C/ZYx0jUjA/g678pHHBc2lY7\n" +
            "dmL3abUwfweRxltZMkZDXSVnzwdywnUGIz1XsxETHnRnpDGgTKnn0wYix7zBFtNT\n" +
            "4mLczORoAoP8yrCDt64NsnFqGdaeltxTYEnTHZV5I30wI89YAnoH5y+wHL6OiNh7\n" +
            "qBjidq99QSFS0kBQBnvtHTDprQIDAQABo4IC8TCCAu0wOwYJKwYBBAGCNxUHBC4w\n" +
            "LAYkKwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4H8uW2EuYEfAgFlAgF4MB8G\n" +
            "A1UdJQQYMBYGCisGAQQBgjcUAgIGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIGwDAd\n" +
            "BgNVHQ4EFgQUFbhF8pcdgkFNlrTzwk+tHr/x2tQwHwYDVR0jBBgwFoAUPZPjtsSQ\n" +
            "Ro8fyiwzjNtRJPyH/XQwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL3BraS5hZGNz\n" +
            "bGFib3IuZGUvQ2VydERhdGEvQURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIw\n" +
            "MSgxKS5jcmwwggFdBggrBgEFBQcBAQSCAU8wggFLMIHIBggrBgEFBQcwAoaBu2xk\n" +
            "YXA6Ly8vQ049QURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIwMSxDTj1BSUEs\n" +
            "Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln\n" +
            "dXJhdGlvbixEQz1pbnRyYSxEQz1hZGNzbGFib3IsREM9ZGU/Y0FDZXJ0aWZpY2F0\n" +
            "ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwUwYIKwYB\n" +
            "BQUHMAKGR2h0dHA6Ly9wa2kuYWRjc2xhYm9yLmRlL0NlcnREYXRhL0FEQ1MlMjBM\n" +
            "YWJvciUyMElzc3VpbmclMjBDQSUyMDEoMikuY3J0MCkGCCsGAQUFBzABhh1odHRw\n" +
            "Oi8vb2NzcC5hZGNzbGFib3IuZGUvb2NzcDAyBgNVHREEKzApoCcGCisGAQQBgjcU\n" +
            "AgOgGQwXcnVkaUBpbnRyYS5hZGNzbGFib3IuZGUwTgYJKwYBBAGCNxkCBEEwP6A9\n" +
            "BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4Ni0x\n" +
            "MzU5MjgwNzgtMTIyNTANBgkqhkiG9w0BAQsFAAOCAgEAdfez2lwMm1XLRG/K6inn\n" +
            "D38XXZqFN8JPHJk4wpVUIAuFHF7+FPRdJaDD/rfk651bDYrQnzwgXCXa0qqvS2oa\n" +
            "NE5dVU7ZUJxOAkjqLZOZPzgDWPfwtModlABHhviVlY2ydKLzSMJfgiItqDFjYk4n\n" +
            "IZlQyydpXZxf1jirdsATnInDuqS/5BJlMRYYeO7K7p7HqPFqwZ138OIXNmK9EBNo\n" +
            "8qJsgTE9qn29VJOKUnBuwyHhewRSOIgL5oJz7aHqNmQsVQSeUO7uN/LAbAfPNCgS\n" +
            "/V3LL9S4tHytYY0JhxsmRA1eKWtlNkZG7cKmhf2Dsl5XlrOgkqDwNyPjuSC+55Tp\n" +
            "5fUm+XCdxiRkHggl7KDZoQP0UTjBT0mgQyvwINPegfA2F157n2BwnDjaiFLv1u+H\n" +
            "bPPn7Yo1SICtxcPQv+J3cszcZl8T9aD0cXSd/s+9Noazy9ZriD5nrQG0uqJSCHUp\n" +
            "xO1iKP2smz5M4ByMrFI3ljbGpbfuS6blcVwNduxZpgTNLmj/rZk+B+frXfJxFL1k\n" +
            "TYJKA4GLLAUIOybPeydNDTHs+RlFQXT0WUg91TBtW2CnHQJKajw/EScWmVX9Az2f\n" +
            "XIL/KQnR9dBqGSyJ1ttOZ6DH8ybE7IusRjkJUjZdRLiwxsmDhzWd9nQEkedbrRUM\n" +
            "62tj3XcrgHpTt6ugnRxsj8cxggG3MIIBswIBATCBizB0MQswCQYDVQQGEwJERTEQ\n" +
            "MA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENT\n" +
            "IExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBMYWJvciBJc3N1aW5n\n" +
            "IENBIDECE3MACA5a1PvJHzNcjRkAAgAIDlowDQYJYIZIAWUDBAIBBQAwDQYJKoZI\n" +
            "hvcNAQEBBQAEggEAlJVSq7hr7o17x8WavmELZoleLOYcaB3txm1+x27fakz9IlDg\n" +
            "zO3Re8WyXEwd44Ykjc5RtzGXlmBUBup7TrF84TodqZjmXjmY+tuvaboS76L5PhMq\n" +
            "VHbwcjWIdKRy/OMH00aMDLQyd2sC+xsIR4YqWA2fVBPHYZq4uZ4Qnfmg9A2NLDGM\n" +
            "xyAmX6eN2uC/jgMRaAbWrEI63R4nHBlZWBPel/GgwOc5HUc2vSCJzC1QrD/tRvuz\n" +
            "p7wxv0zUScBB8ZrMfTP9miCcnL/k3t6LKscION3KB9aqjlU4DZDZQ2eopQKkFqHJ\n" +
            "ivMQZOGuu4Ri/tn7IY5KGOKQjuXh0aMzklATuQ==\n" +
            "-----END PKCS #7 SIGNED DATA-----";

        private const string CsrCmc =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIGOQYJKoZIhvcNAQcCoIIGKjCCBiYCAQMxCzAJBgUrDgMCGgUAMIIEkwYIKwYB\n" +
            "BQUHDAKgggSFBIIEgTCCBH0wZDBiAgECBgorBgEEAYI3CgoBMVEwTwIBADADAgEB\n" +
            "MUUwQwYJKwYBBAGCNxUUMTYwNAIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3Iu\n" +
            "ZGUMCklOVFJBXHJ1ZGkMB01NQy5FWEUwggQPoIIECwIBATCCBAQwggLsAgEAMBkx\n" +
            "FzAVBgNVBAMMDnRoaXMtaXMtYS10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEA6hJzcbbvMbAnlwkTKtXWy8CfSGAuQraUFpPrFRUVBWjkKHUAIz+Q\n" +
            "T0TLNLQ82civl3ajzy0KaCCKNXNL3h7I4mfRFl4Vz7Yx+cA/GrUfUXRXbwDZV4wA\n" +
            "mkuBMoXep3rFXzrBgv2DMv7P55FKwAYuyQ5wIGrkWyquU+VnDxhHTUDQXm9dQ4cG\n" +
            "ERjlbOkM9kgEjde8s1Ws3YvMtwOGm1bnFTLo80jhaIDiBrvahj3oJoya0bupLJVT\n" +
            "L4fypkk8H0ztT3/5O/n8CqxmavDVNzMmVl9SMnQlUtct2gJzx9+vnXc+eGRrp2hC\n" +
            "0lfznnVfwNDv7+xTxYLUz9rIFRXZDPcasQIDAQABoIIBpDAcBgorBgEEAYI3DQID\n" +
            "MQ4WDDEwLjAuMTgzNjMuMjBDBgkrBgEEAYI3FRQxNjA0AgEFDBpDTElFTlQyLmlu\n" +
            "dHJhLmFkY3NsYWJvci5kZQwKSU5UUkFccnVkaQwHTU1DLkVYRTByBgorBgEEAYI3\n" +
            "DQICMWQwYgIBAR5aAE0AaQBjAHIAbwBzAG8AZgB0ACAAUgBTAEEAIABTAEMAaABh\n" +
            "AG4AbgBlAGwAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBp\n" +
            "AGQAZQByAwEAMIHKBgkqhkiG9w0BCQ4xgbwwgbkwOwYJKwYBBAGCNxUHBC4wLAYk\n" +
            "KwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4b521KEm4hwAgFkAgEQMBMGA1Ud\n" +
            "JQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAbBgkrBgEEAYI3FQoEDjAM\n" +
            "MAoGCCsGAQUFBwMBMBkGA1UdEQQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQW\n" +
            "BBQglePw4hbDLawtDYHqDTdx9rMwAjANBgkqhkiG9w0BAQUFAAOCAQEAtNAv5hgi\n" +
            "zE9Db9u6Wfp4I3l9MC1cwr/IDwvqt72MQ17487DgPLwx8UVTVB2SJDKPOEE8y4BT\n" +
            "T7o/FN8R+lE6SxpGtOufp+r8GKSiUpLJCcdHIqnrPgHO8GBo0u7arCKPyGY7tJ3e\n" +
            "xAAcJlji2mGf/cZe30gRNH4vBvBpuhxzccFWyEAigpF1WhvO1V9nvaZEeZlDPWAJ\n" +
            "NPZvtXsFGQeikrmRnR3uFJ/jtgWBdC9k8Q9huuNv8Bvccj8qYWL/Mtq7DvJQTXSS\n" +
            "2ZnYd5daMmaMwR4PTSMJBL39dcOO13E8V96zNVzk0vyuGV6aj6PYbYG1mcBYhRYo\n" +
            "yGjpsGJCDObrsDAAMAAxggF7MIIBdwIBA4AUIJXj8OIWwy2sLQ2B6g03cfazMAIw\n" +
            "CQYFKw4DAhoFAKA+MBcGCSqGSIb3DQEJAzEKBggrBgEFBQcMAjAjBgkqhkiG9w0B\n" +
            "CQQxFgQUxhKbjHHGqjcaR+dFE/O6k3U0uiMwDQYJKoZIhvcNAQEBBQAEggEA1IqJ\n" +
            "eY7zq0pTPOw2Ejja946kFRgKeRGyFz6tefs8WZs+FVStA0y31o7Lirnz5ipb51hv\n" +
            "vD+J4vWPJzamqlf+XuL3LcqGE2yzmiqPClhdSOnS1YxOup26688NCLPbEXfjYWYL\n" +
            "IKI6SlYKfyl94LSGnZHzK4S7tVxcZ1neXh6b9VgOO4UfyXPWrsPNBfKPJffXkBVb\n" +
            "vTRD/rXcqWn+SM4iTNGbcIMVZdIfMsug1N4twwUrullFrzBcY46FZB2Ht5jFmxHf\n" +
            "b+xocnI5ehrg/rjE9FaCSc63/6vUmwZTg/AhnvYpgWUKjXbfMHa/HtnJnTFRU/Ts\n" +
            "Q2DN9dMpV1FjWqNXdA==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        [TestMethod]
        public void TestAutoDetectPkcs10()
        {
            var result =
                CertificateRequestIntegrityChecks.AutoDetectRequestType(CsrPkcs10, out _);

            Assert.IsTrue(result == CertCli.CR_IN_PKCS10);
        }

        [TestMethod]
        public void TestAutoDetectPkcs7()
        {
            var result =
                CertificateRequestIntegrityChecks.AutoDetectRequestType(CsrPkcs7, out _);

            Assert.IsTrue(result == CertCli.CR_IN_PKCS7);
        }

        [TestMethod]
        public void TestAutoDetectCmc()
        {
            var result =
                CertificateRequestIntegrityChecks.AutoDetectRequestType(CsrCmc, out _);

            Assert.IsTrue(result == CertCli.CR_IN_CMC);
        }
    }
}