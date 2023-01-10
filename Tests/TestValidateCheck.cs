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
            privacyIDEA = new PrivacyIDEA(server.Urls[0], "test");
        }

        [TestCleanup]
        public void Cleanup()
        {
            server.Stop();
        }

        [TestMethod]
        public async Task ValidateCheck()
        {
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/check")
                    .UsingPost()
                    .WithBody("user=testSuccess&pass=test")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody(GetResponseSuccess()));

            PIResponse? resp = await privacyIDEA.ValidateCheck("testSuccess", "test");

            Assert.IsTrue(privacyIDEA.SSLVerify);
            privacyIDEA.SSLVerify = false;
            Assert.IsFalse(privacyIDEA.SSLVerify);

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.Value);
            Assert.IsTrue(resp.Status);
            Assert.AreEqual("totp", resp.Type);
            Assert.AreEqual("PISP0001C673", resp.Serial);

            // Test empty response
            server
            .Given(
                Request.Create()
                .WithPath("/validate/check")
                .UsingPost()
                .WithBody("user=emptyResponse&pass=test")
                .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(""));

            resp = await privacyIDEA.ValidateCheck("emptyResponse", "test");

            Assert.IsNull(resp);

            // Test PI error
            server
            .Given(
                Request.Create()
                .WithPath("/validate/check")
                .UsingPost()
                .WithBody("user=testError&pass=test")
                .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                )
            .RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithBody(GetResponseErrorCode()));

            resp = await privacyIDEA.ValidateCheck("testError", "test");

            Assert.IsNotNull(resp);
            Assert.AreEqual(904, resp.ErrorCode);
            Assert.AreEqual("ERR904: The user can not be found in any resolver in this realm!", resp.ErrorMessage);
        }

        private static string GetResponseSuccess()
        {
            return "{\n" +
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
                "\"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"}";
        }

        private static string GetResponseErrorCode()
        {
            return "{" + "\"detail\":null," + "\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"error\":{" +
                "\"code\":904," + "\"message\":\"ERR904: The user can not be found in any resolver in this realm!\"}," +
                "\"status\":false}," + "\"time\":1649752303.65651," + "\"version\":\"privacyIDEA 3.6.3\"," +
                "\"signature\":\"rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0\"}";
        }
    }
//Debug.WriteLine("write here a message to debug the tests...");
}