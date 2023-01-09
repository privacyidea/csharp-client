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
            privacyIDEA = new PrivacyIDEA(server.Urls[0], "test", false);
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
                    .WithBody(GetVCBody()));

            PIResponse? resp = await privacyIDEA.ValidateCheck("testSuccess", "test");

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
                .WithBody(""));

            resp = await privacyIDEA.ValidateCheck("testError", "test");

            Assert.IsNull(resp);
        }

        private static string GetVCBody()
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
    }
//Debug.WriteLine("write here a message to debug the tests...");
}