using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEA_Client
{
    public class PIResponse
    {
        public string TransactionID { get; set; } = "";
        public string Message { get; set; } = "";
        public string? ErrorMessage { get; set; } = "";
        public string Type { get; set; } = "";
        public string Serial { get; set; } = "";
        public int? ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;

        public string Raw { get; set; } = "";
        public List<PIChallenge> Challenges { get; set; } = new List<PIChallenge>();
        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return Challenges.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            return Challenges.First(challenge => challenge.Type == "push").Message;
        }

        public string MergedSignRequest()
        {
            List<string> webAuthnSignRequests = WebAuthnSignRequests();

            if (webAuthnSignRequests.Count < 1)
            {
                return "";
            }
            else if (webAuthnSignRequests.Count == 1)
            {
                return webAuthnSignRequests[0];
            }
            else
            {
                // Extract allowCredentials from every WebAuthn sign request and store in JArray list.
                List<JArray> extracted = new();
                foreach (string signRequest in webAuthnSignRequests)
                {
                    JObject jobj = JObject.Parse(signRequest);

                    if (jobj["allowCredentials"] is JArray jarray)
                    {
                        extracted.Add(jarray);
                    }
                }
                // Get WebAuthn sign request as JSON object
                JObject webAuthnSignRequest = JObject.Parse(webAuthnSignRequests[0]);

                // Set extracted allowCredentials section from every triggered WebAuthn device into one JSON array.
                JArray allowCredentials = new();

                foreach (var x in extracted)
                {
                    foreach (var item in x)
                    {
                        allowCredentials.Add(item);
                    }
                };

                // Save extracted info in WebAuthn Sign Request
                webAuthnSignRequest.Remove("allowCredentials");
                webAuthnSignRequest.Add("allowCredentials", allowCredentials);

                return webAuthnSignRequest.ToString();
            }
        }

        public List<string> WebAuthnSignRequests()
        {
            List<string> ret = new();
            foreach (PIChallenge challenge in Challenges)
            {
                if (challenge.Type == "webauthn")
                {
                    //        string temp = (challenge as PIWebAuthnSignRequest).WebAuthnSignRequest; todo check if it is good
                    string temp = ((PIWebAuthnSignRequest)challenge).WebAuthnSignRequest;
                    ret.Add(temp);
                }
            }

            return ret;
        }

        public static PIResponse? FromJSON(string json, PrivacyIDEA privacyIDEA)
        {
            if (string.IsNullOrEmpty(json))
            {
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error("Json to parse is empty!");
                }
                return null;
            }

            PIResponse ret = new()
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
                    if (jVal != null)
                    {
                        ret.Value = (bool)jVal;
                    }

                    JToken? error = result["error"];
                    if (error != null)
                    {
                        ret.ErrorCode = (int?)error["code"];
                        ret.ErrorMessage = (string?)error["message"];
                    }
                }

                if (jobj["detail"] is JToken detail && detail.Type != JTokenType.Null)
                {
                    if (detail["transaction_id"] is not null)
                    {
                        ret.TransactionID = (string)detail["transaction_id"]!;
                    }
                    if (detail["message"] is not null)
                    {
                        ret.Message = (string)detail["message"]!;
                    }
                    if (detail["type"] is not null)
                    {
                        ret.Type = (string)detail["type"]!;
                    }
                    if (detail["serial"] is not null)
                    {
                        ret.Serial = (string)detail["serial"]!;
                    }

                    if (detail["multi_challenge"] is JArray multiChallenge)
                    {
                        foreach (JToken element in multiChallenge.Children())
                        {
                            if (element["message"] is not null)
                            {
                                string message = (string)element["message"]!;
                            }
                            if (element["transaction_id"] is not null)
                            {
                                string transactionid = (string)element["transaction_id"]!;
                            }
                            if (element["type"] is not null)
                            {
                                string type = (string)element["type"]!;
                            }
                            if (element["serial"] is not null)
                            {
                                string serial = (string)element["serial"]!;
                            }

                            if (type == "webauthn")
                            {
                                PIWebAuthnSignRequest tmp = new();

                                if (element["attributes"] is JToken attr && attr.Type != JTokenType.Null)
                                {
                                    var signRequest = attr["webAuthnSignRequest"];
                                    if (signRequest != null)
                                    {
                                        tmp.WebAuthnSignRequest = signRequest.ToString(Formatting.None);
                                        tmp.WebAuthnSignRequest.Replace("\n", "");
                                    }
                                }

                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.Challenges.Add(tmp);
                            }
                            else
                            {
                                PIChallenge tmp = new PIChallenge();
                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.Challenges.Add(tmp);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error(ex);
                }
                return null;
            }
            return ret;
        }
    }
}
