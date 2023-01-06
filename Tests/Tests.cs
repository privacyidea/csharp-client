using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEA_Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests
{
    [TestClass]
    public class Tests
    {
#pragma warning disable CS8618 // [TestInitialize] acts as constructor
        WireMockServer server;
        PrivacyIDEA privacyIDEA;
        private readonly string _AuthToken = "eyJ0eXAiOiJ...KV1QiLC6chGIM";

        [TestInitialize]
        public void Setup()
        {
            server = WireMockServer.Start();
            privacyIDEA = new PrivacyIDEA(server.Urls[0], "test", false);
        }

        [TestCleanup]
        public void Cleanup()
        {
            server.Stop();
        }

        [TestMethod]
        public void SimpleOTP()
        {
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/check")
                    .UsingPost()
                    .WithBody("user=test&pass=test")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody("{\n" +
                        "\"detail\":" +
                        " {\n" +
                            "\"message\": \"matching 1 tokens\",\n" +
                            "\"otplen\": 6,\n" +
                            "\"serial\": \"PISP0001C673\",\n" +
                            "\"threadid\": 140536383567616,\n" +
                            "\"type\": \"totp\"\n" +
                        "},\n" +
                        "\"id\": 1,\n" +
                        "\"jsonrpc\": \"2.0\",\n" +
                        "\"result\": " +
                        "{\n" +
                            "\"status\": true,\n" +
                            "\"value\": true\n" +
                        "},\n" +
                        "\"time\": 1589276995.4397042,\n" +
                        "\"version\": \"privacyIDEA 3.2.1\",\n" +
                        "\"versionnumber\": \"3.2.1\",\n" +
                        "\"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"}"));

            var resp = privacyIDEA.ValidateCheck("test", "test");

            Assert.IsNotNull(resp);
            Assert.IsNotNull(resp.Result);
            Assert.IsTrue(resp.Result.Value);
            Assert.IsTrue(resp.Result.Status);
            Assert.AreEqual("totp", resp.Result.Type);
            Assert.AreEqual("PISP0001C673", resp.Result.Serial);
        }

        [TestMethod]
        public async Task TriggerChallenges()
        {
            string webAuthnSignRequest1 = "{\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";

            string webAuthnSignRequest2 = "{\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwnrijhva23onu230985uc2m08uiowejrtcoml3XCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEqvtw34v43v2335vc25c22IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";

            string mergedSignRequests = "{\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\",\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              },\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwnrijhva23onu230985uc2m08uiowejrtcoml3XCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ]\n" +
                "          }";

            string postAuthBody = "{\n" +
                "    \"id\": 1,\n" +
                "    \"jsonrpc\": \"2.0\",\n" +
                "    \"result\": {\n" +
                "        \"status\": true,\n" +
                "        \"value\": {\n" +
                "            \"log_level\": 20,\n" +
                "            \"menus\": [\n" +
                "                \"components\",\n" +
                "                \"machines\"\n" +
                "            ],\n" +
                "            \"realm\": \"\",\n" +
                "            \"rights\": [\n" +
                "                \"policydelete\",\n" +
                "                \"resync\"\n" +
                "            ],\n" +
                "            \"role\": \"admin\",\n" +
                "            \"token\": \"" + _AuthToken + "\",\n" +
                "            \"username\": \"admin\",\n" +
                "            \"logout_time\": 120,\n" +
                "            \"default_tokentype\": \"hotp\",\n" +
                "            \"user_details\": false,\n" +
                "            \"subscription_status\": 0\n" +
                "        }\n" +
                "    },\n" +
                "    \"time\": 1589446794.8502703,\n" +
                "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                "    \"versionnumber\": \"3.2.1\",\n" +
                "    \"signature\": \"rsa_sha256_pss:\"\n" +
                "}";

            string postValidateTriggerchallenge = "{\n" +
                "  \"detail\": {\n" +
                "    \"attributes\": null,\n" +
                "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
                "    \"messages\": [\n" +
                "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                "      \"Please confirm the authentication on your mobile device!\"\n" +
                "    ],\n" +
                "    \"multi_challenge\": [\n" +
                "      {\n" +
                "        \"attributes\": null,\n" +
                "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                "        \"serial\": \"OATH00020121\",\n" +
                "        \"transaction_id\": \"02659936574063359702\",\n" +
                "        \"type\": \"hotp\"\n" +
                "      },\n" +
                "      {\n" +
                "        \"attributes\": null,\n" +
                "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
                "        \"serial\": \"PIPU0001F75E\",\n" +
                "        \"transaction_id\": \"02659936574063359702\",\n" +
                "        \"type\": \"push\"\n" +
                "      },\n" +
                "      {\n" +
                "        \"attributes\": {\n" +
                "          \"hideResponseInput\": true,\n" +
                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "          \"webAuthnSignRequest\": " + webAuthnSignRequest1 +
                "        },\n" +
                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                "        \"serial\": \"WAN00025CE7\",\n" +
                "        \"transaction_id\": \"16786665691788289392\",\n" +
                "        \"type\": \"webauthn\"\n" +
                "      },\n" +
                "      {\n" +
                "        \"attributes\": {\n" +
                "          \"hideResponseInput\": true,\n" +
                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "          \"webAuthnSignRequest\": " + webAuthnSignRequest2 +
                "        },\n" +
                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 6173234565)\",\n" +
                "        \"serial\": \"WAN0002TER\",\n" +
                "        \"transaction_id\": \"16786665691788289392\",\n" +
                "        \"type\": \"webauthn\"\n" +
                "      }\n" +
                "    ],\n" +
                "    \"serial\": \"PIPU0001F75E\",\n" +
                "    \"threadid\": 140040525666048,\n" +
                "    \"transaction_id\": \"02659936574063359702\",\n" +
                "    \"transaction_ids\": [\n" +
                "      \"02659936574063359702\",\n" +
                "      \"02659936574063359702\"\n" +
                "    ],\n" +
                "    \"type\": \"push\"\n" +
                "  },\n" +
                "  \"id\": 1,\n" +
                "  \"jsonrpc\": \"2.0\",\n" +
                "  \"result\": {\n" +
                "    \"status\": true,\n" +
                "    \"value\": false\n" +
                "  },\n" +
                "  \"time\": 1589360175.594304,\n" +
                "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                "  \"versionnumber\": \"3.2.1\",\n" +
                "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" +
                "}";

            // Auth token response
            server.Given(
                    Request.Create()
                    .WithPath("/auth")
                    .UsingPost()
                    .WithBody("username=admin&password=admin")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(postAuthBody));

            // Trigger challenge response
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=test")
                    .WithHeader("Authorization", _AuthToken)
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(postValidateTriggerchallenge));

            privacyIDEA.SetServiceAccount("admin", "admin");

            var resp = await privacyIDEA.TriggerChallenges("test");

            Assert.IsNotNull(resp);
            Assert.AreEqual(false, resp.Value);
            Assert.AreEqual(true, resp.Status);
            Assert.AreEqual("02659936574063359702", resp.TransactionID);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!", resp.Message);

            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("push"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("hotp"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("webauthn"));

            var c1 = resp.Challenges.Find(item => item.Type == "push");
            Assert.IsNotNull(c1);
            Assert.AreEqual("PIPU0001F75E", c1.Serial);
            Assert.AreEqual("Please confirm the authentication on your mobile device!", c1.Message);
            Assert.AreEqual(c1.Attributes.Count, 0);

            var c2 = resp.Challenges.Find(item => item.Type == "hotp");
            Assert.IsNotNull(c2);
            Assert.AreEqual("OATH00020121", c2.Serial);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: ", c2.Message);
            Assert.AreEqual(c2.Attributes.Count, 0);

            var c3 = resp.Challenges.Find(item => item.Type == "webauthn");
            Assert.IsNotNull(c3);
            Assert.AreEqual("WAN00025CE7", c3.Serial);
            Assert.AreEqual("Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", c3.Message);
            var signRequest = resp.MergedSignRequest();
            Assert.IsFalse(string.IsNullOrEmpty(signRequest));
            Assert.AreEqual(RemoveWhitespace(mergedSignRequests), RemoveWhitespace(signRequest));

            // Test preferred_client_mode: push
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=testpush")
                    .WithHeader("Authorization", _AuthToken)
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TCResponseWithMode("poll")));

            resp = await privacyIDEA.TriggerChallenges("testpush");

            Assert.IsNotNull(resp); //todo rm
            Debug.WriteLine("response push!!! : " + resp.PreferredClientMode);

            // Test preferred_client_mode: otp
            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=testotp")
                .WithHeader("Authorization", _AuthToken)
                .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TCResponseWithMode("interactive")));

            resp = await privacyIDEA.TriggerChallenges("testotp");
            Assert.IsNotNull(resp);
            Assert.AreEqual("otp", resp.PreferredClientMode);

            // Test preferred_client_mode: webauthn
            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=testwebauthn")
                .WithHeader("Authorization", _AuthToken)
                .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TCResponseWithMode("webauthn")));

            resp = await privacyIDEA.TriggerChallenges("testwebauthn");
            Assert.IsNotNull(resp);
            Assert.AreEqual("webauthn", resp.PreferredClientMode);
        }

        private static string TCResponseWithMode(string preferredClientMode)
        {
            return "{\n" +
                   "  \"detail\": {\n" +
                   "    \"attributes\": null,\n" +
                   "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
                   "    \"messages\": [\n" +
                   "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                   "      \"Please confirm the authentication on your mobile device!\"\n" +
                   "    ],\n" +
                   "    \"multi_challenge\": [\n" +
                   "      {\n" +
                   "        \"attributes\": null,\n" +
                   "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                   "        \"serial\": \"OATH00020121\",\n" +
                   "        \"transaction_id\": \"02659936574063359702\",\n" +
                   "        \"type\": \"hotp\"\n" +
                   "      },\n" +
                   "      {\n" +
                   "        \"attributes\": null,\n" +
                   "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
                   "        \"serial\": \"PIPU0001F75E\",\n" +
                   "        \"transaction_id\": \"02659936574063359702\",\n" +
                   "        \"type\": \"push\"\n" +
                   "      }\n" +
                   "    ],\n" +
                   "    \"serial\": \"PIPU0001F75E\",\n" +
                   "    \"preferred_client_mode\": \"" + preferredClientMode + "\",\n" +
                   "    \"threadid\": 140040525666048,\n" +
                   "    \"transaction_id\": \"02659936574063359702\",\n" +
                   "    \"transaction_ids\": [\n" +
                   "      \"02659936574063359702\",\n" +
                   "      \"02659936574063359702\"\n" +
                   "    ],\n" +
                   "    \"type\": \"push\"\n" +
                   "  },\n" +
                   "  \"id\": 1,\n" +
                   "  \"jsonrpc\": \"2.0\",\n" +
                   "  \"result\": {\n" +
                   "    \"status\": true,\n" +
                   "    \"value\": false\n" +
                   "  },\n" +
                   "  \"time\": 1589360175.594304,\n" +
                   "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                   "  \"versionnumber\": \"3.2.1\",\n" +
                   "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" +
                   "}";
        }

        private static string RemoveWhitespace(string str)
        {
            return string.Join("", str.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));
        }
    }
}