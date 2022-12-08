using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEA_Client
{
    public class PrivacyIDEA : IDisposable
    {
        public string Url { get; set; } = "";
        public string Realm { get; set; } = "";
        public Dictionary<string, string> RealmMap { get; set; } = new Dictionary<string, string>();

        private bool _SSLVerify = true;
        public bool SSLVerify
        {
            get
            {
                return _SSLVerify;
            }
            set
            {
                if (SSLVerify != _SSLVerify)
                {
                    _httpClientHandler = new HttpClientHandler();
                    if (SSLVerify is false)
                    {
                        _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                        _httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    }
                    _httpClient = new HttpClient(_httpClientHandler);
                    _httpClient.DefaultRequestHeaders.Add("User-Agent", _userAgent);
                    _sslVerify = SSLVerify;
                }
            }
        }

        private HttpClientHandler _httpClientHandler;
        private HttpClient _httpClient;
        private bool _disposedValue;
        private readonly string _userAgent;
        private string? _serviceUser;
        private string? _servicePass;
        private string? _serviceRealm;
        private readonly bool _logServerResponse = true;
        public IPILog? Logger { get; set; } = null;

        // The webauthn parameters should not be url encoded because they already have the correct format.
        private static readonly List<String> _exludeFromURIEscape = new(new string[]
           { "credentialid", "clientdata", "signaturedata", "authenticatordata", "userhandle", "assertionclientextensions" });

        private static readonly List<String> _logExcludedEndpoints = new(new string[]
           { "/auth", "/validate/polltransaction" });

        public PrivacyIDEA(string url, string useragent, bool sslVerify = true)
        {
            this.Url = url;
            this._userAgent = useragent;

            _httpClientHandler = new HttpClientHandler();
            if (sslVerify is false)
            {
                _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                _httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            _httpClient = new HttpClient(_httpClientHandler);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", useragent);
        }

        /// <summary>
        /// Trigger challenges for the given user using a service account.
        /// </summary>
        /// <param name="username">username to trigger challenges for</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>PIResponse object or null on error</returns>
        public async Task<PIResponse?> TriggerChallenges(string username, string? domain = null, List<KeyValuePair<string, string>>? headers = null, CancellationToken cancellationToken = default)
        {
            if (await GetAuthToken(cancellationToken) is false)
            {
                Error("Unable to trigger challenges without an auth token!");
                return null;
            }
            var parameters = new Dictionary<string, string>
            {
                { "user", username }
            };

            AddRealmForDomain(domain, parameters);

            string response = await SendRequest("/validate/triggerchallenge", parameters, "POST", headers, cancellationToken);
            PIResponse? ret = PIResponse.FromJSON(response, this);

            return ret;
        }

        /// <summary>
        /// Check if the challenge for the given transaction id has been answered yet. This is done using the /validate/polltransaction endpoint.
        /// </summary>
        /// <param name="transactionid"></param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>true if challenge was answered. false if not or error</returns>
        public async Task<bool> PollTransaction(string transactionid, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(transactionid) is false)
            {
                var parameters = new Dictionary<string, string>
                {
                    { "transaction_id", transactionid }
                };

                string response = await SendRequest("/validate/polltransaction", parameters, "GET", new List<KeyValuePair<string, string>>(), cancellationToken);

                if (string.IsNullOrEmpty(response))
                {
                    Error("/validate/polltransaction did not respond!");
                    return false;
                }

                bool ret = false;            
                JObject root = JObject.Parse(response);

                if (root["result"] is JToken result)
                {
                    ret = (bool)(result["value"] ?? false);
                }
                return ret;
            }
            Error("PollTransaction called with empty transaction id!");
            return false;
        }

        /// <summary>
        /// Checks if user has existing token
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>true if token exists. false if not or error</returns>
        public async Task<bool> UserHasToken(string user, string? domain = null, CancellationToken cancellationToken = default)
        {
            if (await GetAuthToken(cancellationToken) is false)
            {
                Error("Unable to lookup tokens without an auth token!");
                return false;
            }
            var parameters = new Dictionary<string, string>
            {
                { "user", user }
            };
            AddRealmForDomain(domain, parameters);

            string response = await SendRequest("/token/", parameters, "GET", new List<KeyValuePair<string, string>>(), cancellationToken);
            if (string.IsNullOrEmpty(response))
            {
                Error("/token/ did not respond!");
                return false;
            }

            bool ret = false;
            JObject root = JObject.Parse(response);

            if (root["result"] is JToken result)
            {
                ret = (bool)(result["value"] ?? false);
            }
            return ret;
        }

        /// <summary>
        /// Enroll TOTP Token for specified user if user does not already have token
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>PIEnrollResponse object or null on error</returns>
        public async Task<PIEnrollResponse?> TokenInit(string user, string? domain = null, CancellationToken cancellationToken = default)
        {
            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "type", "totp" },
                { "genkey", "1" }
            };
            AddRealmForDomain(domain, parameters);

            string response = await SendRequest("/token/init", parameters, "POST", new List<KeyValuePair<string, string>>(), cancellationToken);
            return PIEnrollResponse.FromJSON(response, this);
        }


        /// <summary>
        /// Authenticate using the /validate/check endpoint with the username and OTP value. 
        /// Optionally, a transaction id can be provided if authentication is done using challenge-response.
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="otp">OTP</param>
        /// <param name="transactionid">optional transaction id to refer to a challenge</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>PIResponse object or null on error</returns>
        public async Task<PIResponse?> ValidateCheck(string user, string otp, string? transactionid = null, string? domain = null, List<KeyValuePair<string, string>>? headers = null, CancellationToken cancellationToken = default)
        {
            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "pass", otp }
            };

            if (transactionid is not null)
            {
                parameters.Add("transaction_id", transactionid);
            }

            AddRealmForDomain(domain, parameters);

            string response = await SendRequest("/validate/check", parameters, "POST", headers, cancellationToken);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Authenticate at the /validate/check endpoint using a WebAuthn token instead of the usual OTP value.
        /// This requires the WebAuthnSignResponse and the Origin from the browser.
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="transactionID">transaction id of the webauthn challenge</param>
        /// <param name="webAuthnSignResponse">the WebAuthnSignResponse string in json format as returned from the browser</param>
        /// <param name="origin">origin also returned by the browser</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="cancellationToken">optional</param>
        /// <returns>PIResponse object or null on error</returns>
        public async Task<PIResponse?> ValidateCheckWebAuthn(string user, string transactionID, string webAuthnSignResponse, string origin, string? domain = null, List<KeyValuePair<string, string>>? headers = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(transactionID) || string.IsNullOrEmpty(webAuthnSignResponse) || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckWebAuthn called with missing parameter: user=" + user + ", transactionid=" + transactionID
                    + ", WebAuthnSignResponse=" + webAuthnSignResponse + ", origin=" + origin);
                return null;
            }

            // Parse the WebAuthnSignResponse and add mandatory parameters
            JToken root;
            try
            {
                root = JToken.Parse(webAuthnSignResponse);
            }
            catch (JsonReaderException jex)
            {
                Error("WebAuthnSignRequest does not have the required format! " + jex.Message);
                return null;
            }

            if ((string?)root["credentialid"] is string credentialID && (string?)root["clientdata"] is string clientData
                && (string?)root["signaturedata"] is string signatureData && (string?)root["authenticatordata"] is string authenticatorData)
            {
                var parameters = new Dictionary<string, string>
                {
                    { "user", user },
                    { "pass", "" },
                    { "transaction_id", transactionID },
                    { "credentialid", credentialID },
                    { "clientdata", clientData },
                    { "signaturedata", signatureData },
                    { "authenticatordata", authenticatorData }
                };

                // Optionally add UserHandle and AssertionClientExtensions
                if ((string?)root["userhandle"] is string userHandle)
                {
                    parameters.Add("userhandle", userHandle);
                }
                if ((string?)root["assertionclientextensions"] is string ace)
                {
                    parameters.Add("assertionclientextensions", ace);
                }

                AddRealmForDomain(domain, parameters);

                // The origin has to be set in the header for WebAuthn authentication
                headers ??= new List<KeyValuePair<string, string>>();
                headers.Add(new KeyValuePair<string, string>("Origin", origin));

                string response = SendRequest("/validate/check", parameters, headers);
                return PIResponse.FromJSON(response, this);
            }
            else
            {
                Log("");
                return null;
            }
            
            AddRealmForDomain(domain, parameters);

            // The origin has to be set in the header for WebAuthn authentication
            headers ??= new List<KeyValuePair<string, string>>();
            headers.Add(new KeyValuePair<string, string>("Origin", origin));

            string response = await SendRequest("/validate/check", parameters, "POST", headers, cancellationToken);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Gets an auth token from the privacyIDEA server using the service account.
        /// Afterward, the token is set as the default authentication header for the HttpClient.
        /// </summary>
        /// <param name="cancellationToken">optional</param>
        /// <returns>true if success, false otherwise</returns>
        private async Task<bool> GetAuthToken(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(_serviceUser) || string.IsNullOrEmpty(_servicePass))
            {
                Error("Unable to fetch auth token without service account!");
                return false;
            }
            else
            {
                var map = new Dictionary<string, string>
                    {
                        { "username", _serviceUser },
                        { "password", _servicePass }
                    };

                if (string.IsNullOrEmpty(_serviceRealm) is false)
                {
                    map.Add("realm", _serviceRealm);
                }

            string response = await SendRequest("/auth", parameters, "POST", null, cancellationToken);

                if (string.IsNullOrEmpty(response))
                {
                    Error("/auth did not respond!");
                    return false;
                }

                string token = "";

                JObject root = JObject.Parse(response);
                if (root["result"] is JToken result)
                {
                    if (result["value"] is JToken jVal)
                    {
                        if ((string?)jVal["token"] is string s)
                        {
                            token = s;
                        }
                    }
                }

                if (string.IsNullOrEmpty(token) is false)
                {
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
                    return true;
                }
                return false;
            }
        }

        public void SetServiceAccount(string user, string pass, string realm = "")
        {
            _serviceUser = user;
            _servicePass = pass;
            if (string.IsNullOrEmpty(realm) is false)
            {
                _serviceRealm = realm;
            }
        }
        
        private Task<string> SendRequest(string endpoint, Dictionary<string, string> parameters, string method,
            List<KeyValuePair<string, string>>? headers = null, CancellationToken cancellationToken = default)
        {
            Log("Sending [" + string.Join(" , ", parameters) + "] to [" + Url + endpoint + "] with method [" + method + "]");

            StringContent stringContent = DictToEncodedStringContent(parameters);

            HttpRequestMessage request = new();
            if (method == "POST")
            {
                request.Method = HttpMethod.Post;
                request.RequestUri = new Uri(Url + endpoint);
                request.Content = stringContent;
            }
            else
            {
                string s = stringContent.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
                request.Method = HttpMethod.Get;
                request.RequestUri = new Uri(Url + endpoint + "?" + s);
            }

            if (headers is not null && headers.Count > 0)
            {
                foreach (KeyValuePair<string, string> element in headers)
                {
                    request.Headers.Add(element.Key, element.Value);
                }
            }

            var awaiter = _httpClient.SendAsync(request, cancellationToken).GetAwaiter();

            HttpResponseMessage responseMessage = awaiter.GetResult();

            if (responseMessage.StatusCode != HttpStatusCode.OK)
            {
                Error("The request to " + endpoint + " returned HttpStatusCode " + responseMessage.StatusCode);
                //return "";
            }

            string ret = "";
            try
            {
                ret = responseMessage.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                Error(e.Message);
            }

            if (_logServerResponse && string.IsNullOrEmpty(ret) is false && _logExcludedEndpoints.Contains(endpoint) is false)
            {
                Log(endpoint + " response:\n" + JToken.Parse(ret).ToString(Formatting.Indented));
            }

            return Task.FromResult(ret);
        }

        /// <summary>
        /// Evaluates which realm to use for a given domain and adds it to the parameter dictionary.
        /// The realm mapping takes precedence over the general realm that can be set. If no realm is found, the parameter is omitted.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="parameters"></param>
        private void AddRealmForDomain(string? domain, Dictionary<string, string> parameters)
        {
            if (string.IsNullOrEmpty(domain) is false)
            {
                string r = "";
                string d = domain.ToUpper();
                Log("Searching realm for domain " + d);
                if (RealmMap.ContainsKey(d))
                {
                    r = RealmMap[d];
                    Log("Found realm in mapping: " + r);
                }

                if (string.IsNullOrEmpty(r) && string.IsNullOrEmpty(Realm) is false)
                {
                    r = Realm;
                    Log("Using default realm " + r);
                }

                if (string.IsNullOrEmpty(r) is false)
                {
                    parameters.Add("realm", r);
                }
                else
                {
                    Log("No realm configured for domain " + d);
                }
            }
            else
            {
                if (string.IsNullOrEmpty(Realm) is false)
                {
                    parameters.Add("realm", Realm);
                }
            }            
        }

        internal static StringContent DictToEncodedStringContent(Dictionary<string, string> dict)
        {
            StringBuilder sb = new();

            foreach (var element in dict)
            {
                sb.Append(element.Key).Append('=');
                sb.Append((_exludeFromURIEscape.Contains(element.Key)) ? element.Value : Uri.EscapeDataString(element.Value));
                sb.Append('&');
            }
            // Remove tailing &
            if (sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
            }

            string ret = sb.ToString();
            //Log("Built string: " + ret);
            return new StringContent(ret, Encoding.UTF8, "application/x-www-form-urlencoded"); ;
        }

        internal void Log(string message)
        {
            if (this.Logger is not null)
            {
                this.Logger.Log(message);
            }
        }

        internal void Error(string message)
        {
            if (this.Logger is not null)
            {
                this.Logger.Error(message);
            }
        }

        internal void Error(Exception exception)
        {
            if (this.Logger is not null)
            {
                this.Logger.Error(exception);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposedValue is false)
            {
                if (disposing)
                {
                    // Managed
                    _httpClient.Dispose();
                    _httpClientHandler.Dispose();
                }
                // Unmanaged
                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}