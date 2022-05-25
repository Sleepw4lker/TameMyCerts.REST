using System.Collections.Generic;

namespace AdcsToRest.Models
{
    public class AuthorityInformationAccess
    {
        public List<string> Urls { get; set; }

        public List<string> OcspUrls { get; set; }

        public string Certificate { get; set; }
    }
}