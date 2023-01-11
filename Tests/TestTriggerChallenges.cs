using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEA_Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using PrivacyIDEA_TestUtils;

namespace Tests
{
    [TestClass]
    public class TestTriggerChallenges
    {
#pragma warning disable CS8618 // [TestInitialize] acts as constructor
        WireMockServer server;
        PrivacyIDEA privacyIDEA;
#pragma warning restore CS8618 // [TestInitialize] acts as constructor

        [TestInitialize]
        public void Setup()
        {
            server = WireMockServer.Start();
            privacyIDEA = new PrivacyIDEA(server.Urls[0], "test");
        }

        [TestCleanup]
        public void Cleanup()
        {
            server.Stop();
        }

        [TestMethod]
        public async Task TestTCFullResponse()
        {
            server
                .Given(
                    Request.Create()
                    .WithPath("/auth")
                    .UsingPost()
                    .WithBody("username=admin&password=admin")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TestUtils.TCResponsePostAuth()));

            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=test")
                    .WithHeader("Authorization", TestUtils.AuthToken())
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TestUtils.TCFullResponse()));

            privacyIDEA.SetServiceAccount("admin", "admin");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("test");

            Assert.IsNotNull(resp);
            Assert.AreEqual(false, resp.Value);
            Assert.AreEqual(true, resp.Status);
            Assert.AreEqual("02659936574063359702", resp.TransactionID);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!", resp.Message);

            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("push"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("hotp"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("webauthn"));
            Assert.IsTrue(resp.PushMessage().Equals("Please confirm the authentication on your mobile device!", StringComparison.Ordinal));

            PIChallenge? c1 = resp.Challenges.Find(item => item.Type == "push");
            Assert.IsNotNull(c1);
            Assert.AreEqual("PIPU0001F75E", c1.Serial);
            Assert.AreEqual("Please confirm the authentication on your mobile device!", c1.Message);
            Assert.AreEqual(c1.Attributes.Count, 0);

            PIChallenge? c2 = resp.Challenges.Find(item => item.Type == "hotp");
            Assert.IsNotNull(c2);
            Assert.AreEqual("OATH00020121", c2.Serial);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: ", c2.Message);
            Assert.AreEqual(c2.Attributes.Count, 0);

            PIChallenge? c3 = resp.Challenges.Find(item => item.Type == "webauthn");
            Assert.IsNotNull(c3);
            Assert.AreEqual("WAN00025CE7", c3.Serial);
            Assert.AreEqual("Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", c3.Message);
            Assert.AreEqual(c3.Attributes.Count, 0);

            string? signRequest = resp.MergedSignRequest();
            Assert.IsFalse(string.IsNullOrEmpty(signRequest));
            Assert.AreEqual(TestUtils.RemoveWhitespaces(TestUtils.TCMergedSignRequests()), TestUtils.RemoveWhitespaces(signRequest));
        }

        [TestMethod]
        public async Task TestPreferredPush()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=testpush")
                    .WithHeader("Authorization", TestUtils.AuthToken())
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TestUtils.TCResponsePreferredMode("poll")));

            privacyIDEA.SetServiceAccount("admin", "admin");
            privacyIDEA.RealmMap.Add("DOMAIN", "");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("testpush", "domain");
            Assert.IsNotNull(resp);
            Assert.AreEqual("push", resp.PreferredClientMode);
        }

        [TestMethod]
        public async Task TestPreferredOTP()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=testotp&realm=realm")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePreferredMode("interactive")));

            privacyIDEA.SetServiceAccount("admin", "admin");
            privacyIDEA.Realm = "realm";
            privacyIDEA.RealmMap.Add("DOMAIN", "");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("testotp", "domain");
            Assert.IsNotNull(resp);
            Assert.AreEqual("otp", resp.PreferredClientMode);
        }

        [TestMethod]
        public async Task TestPreferredWebauthn()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=preferredClientMode&realm=domainname")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePreferredMode("webauthn")));

            privacyIDEA.SetServiceAccount("admin", "admin");
            privacyIDEA.RealmMap.Add("DOMAIN", "domainname");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("preferredClientMode", "domain");
            Assert.IsNotNull(resp);
            Assert.AreEqual("webauthn", resp.PreferredClientMode);
        }

        [TestMethod]
        public async Task TestSingleWebauthn()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=oneWebauthn")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponseSingleWebauthn()));

            privacyIDEA.SetServiceAccount("admin", "admin");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("oneWebauthn");
            Assert.IsNotNull(resp);
            Assert.AreEqual(TestUtils.RemoveWhitespaces(TestUtils.TCWebAuthnSignRequest1()), resp.MergedSignRequest());
        }

        [TestMethod]
        public async Task TestNoWebauthn()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=noWebauthn")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponseNoWebauthn()));

            privacyIDEA.SetServiceAccount("admin", "admin");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("noWebauthn");
            Assert.IsNotNull(resp);
            Assert.AreEqual("", resp.MergedSignRequest());
        }

        [TestMethod]
        public async Task TestMissingChallengeElement()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=missingElement")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponseMissingChallengeElement()));

            privacyIDEA.SetServiceAccount("admin", "admin");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("missingElement");
            Assert.IsNotNull(resp);
            Assert.IsNull(resp.Challenges.Find(item => item.Type == "hotp"));
        }

        [TestMethod]
        public async Task TestAuthTokenFalse()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/auth")
                .UsingPost()
                .WithBody("username=admin&password=admin")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponsePostAuth()));

            server
            .Given(
                Request.Create()
                .WithPath("/validate/triggerchallenge")
                .UsingPost()
                .WithBody("user=missingElement")
                .WithHeader("Authorization", TestUtils.AuthToken())
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.TCResponseMissingChallengeElement()));

            privacyIDEA.SetServiceAccount("admin", "admin");
            PIResponse? resp = await privacyIDEA.TriggerChallenges("missingElement");
            Assert.IsNotNull(resp);
            Assert.IsNull(resp.Challenges.Find(item => item.Type == "hotp"));
        }

        [TestMethod]
        public async Task TestNoServiceAccount()
        {
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
                    .WithBody(""));
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=test")
                    .WithHeader("Authorization", "")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TestUtils.TCFullResponse()));

            PIResponse? resp = await privacyIDEA.TriggerChallenges("test");

            Assert.IsNull(resp);
        }

        [TestMethod]
        public async Task TestFalseAuthToken()
        {
            privacyIDEA.SetServiceAccount("admin", "admin", "adminRealm");

            PIResponse? resp = await privacyIDEA.TriggerChallenges("test");

            Assert.IsNull(resp);
        }

        [TestMethod]
        public async Task TestNoTokenInResponse()
        {
            server.Given(
                    Request.Create()
                    .WithPath("/auth")
                    .UsingPost()
                    .WithBody("username=admin&password=admin")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(TestUtils.TCResponseNoAuthToken()));

            privacyIDEA.SetServiceAccount("admin", "admin");

            PIResponse? resp = await privacyIDEA.TriggerChallenges("test");

            Assert.IsNull(resp);
        }
    }
}