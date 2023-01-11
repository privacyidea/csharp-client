using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEA_Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using PrivacyIDEA_TestUtils;

namespace Tests
{
    [TestClass]
    public class TestValidateCheck
    {
#pragma warning disable CS8618 // [TestInitialize] acts as constructor
        WireMockServer server;
        PrivacyIDEA privacyIDEA;
#pragma warning restore CS8618 // [TestInitialize] acts as constructor

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
        public async Task TestSuccess()
        {
            server
            .Given(
               Request.Create()
               .WithPath("/validate/check")
               .UsingPost()
               .WithBody("user=testSuccess&pass=test&transaction_id=123446136254")
               .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
               )
    .       RespondWith(
               Response.Create()
               .WithStatusCode(200)
               .WithBody(TestUtils.VCResponseSuccess()));

            PIResponse? resp = await privacyIDEA.ValidateCheck("testSuccess", "test", "123446136254");
            privacyIDEA.SSLVerify = false;

            Assert.IsFalse(privacyIDEA.SSLVerify);
            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.Value);
            Assert.IsTrue(resp.Status);
            Assert.AreEqual("totp", resp.Type);
            Assert.AreEqual("PISP0001C673", resp.Serial); 
        }

        [TestMethod]
        public async Task TestEmptyResponse()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/validate/check")
                .UsingPost()
                .WithBody("user=emptyResponse&pass=test&realm=testrealm")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(""));

            privacyIDEA.Realm = "testrealm";
            var resp = await privacyIDEA.ValidateCheck("emptyResponse", "test");
            privacyIDEA.Dispose();

            Assert.IsNull(resp);
        }

        [TestMethod]
        public async Task TestPIError()
        {
            server
            .Given(
                Request.Create()
                .WithPath("/validate/check")
                .UsingPost()
                .WithBody("user=testError&pass=test")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(TestUtils.VCResponseErrorCode()));

            var resp = await privacyIDEA.ValidateCheck("testError", "test");

            Assert.IsNotNull(resp);
            Assert.AreEqual(904, resp.ErrorCode);
            Assert.AreEqual("ERR904: The user can not be found in any resolver in this realm!", resp.ErrorMessage);
        }
    }
}