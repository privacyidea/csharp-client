using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEA_Client
{
    public class PIEnrollResponse
    {
        public string Raw { get; set; } = "";
        public string? ErrorMessage { get; set; } = "";
        public int? ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;
        public string Serial { get; set; } = "";
        public string TotpUrl { get; set; } = "";
        public string Base64TotpImage { get; set; } = "";

        private PIEnrollResponse() { }

        public static PIEnrollResponse? FromJSON(string json, PrivacyIDEA privacyIDEA)
        {
            if (string.IsNullOrEmpty(json))
            {
                if (privacyIDEA is not null)
                {
                    privacyIDEA.Error("Json to parse is empty!");
                }
                return null;
            }

            PIEnrollResponse ret = new()
            {
                Raw = json
            };

            try
            {
                JObject jobj = JObject.Parse(json);

                if (jobj["result"] is JToken result)
                {
                    ret.Status = (bool)(result["status"] ?? false);

                    JToken? jVal = result["value"];
                    if (jVal is not null)
                    {
                        ret.Value = (bool)jVal;
                    }

                    if (result["error"] is JToken error)
                    {
                        ret.ErrorCode = (int)(error["code"] ?? "");
                        ret.ErrorMessage = (string?)(error["message"] ?? "");
                    }
                }

                if (jobj["detail"] is JToken detail && detail.Type is not JTokenType.Null)
                {
                    
                    // ret.Type = (string)detail["type"];
                    if ((string?)detail["serial"] is string serial)
                    {
                        ret.Serial = serial;
                    }

                    if (detail["googleurl"] is JToken googleTotp && googleTotp.Type is not JTokenType.Null)
                    {
                        if ((string?)googleTotp["value"] is string value)
                        {
                            ret.TotpUrl = value;
                        }
                        if ((string?)googleTotp["img"] is string img)
                        {
                            ret.Base64TotpImage = img;
                        }
                    }
                }
            }
            catch (JsonException je)
            {
                if (privacyIDEA is not null)
                {
                    privacyIDEA.Error(je);
                }
                return null;
            }
            return ret;
        }
    }
}
