namespace PrivacyIDEA_TestUtils
{
    public class TestUtils
    {
        public static string VCResponseSuccess()
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
                    
        public static string VCResponseErrorCode()
        {
            return "{" + "\"detail\":null," + "\"id\":1," + "\"jsonrpc\":\"2.0\"," + "\"result\":{" + "\"error\":{" +
            "\"code\":904," + "\"message\":\"ERR904: The user can not be found in any resolver in this realm!\"}," +
            "\"status\":false}," + "\"time\":1649752303.65651," + "\"version\":\"privacyIDEA 3.6.3\"," +
            "\"signature\":\"rsa_sha256_pss:1c64db29cad0dc127d6...5ec143ee52a7804ea1dc8e23ab2fc90ac0ac147c0\"}";
        }

        public static string TCWebAuthnSignRequest1()
        {
            return "{\n" +
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
        }

        public static string TCWebAuthnSignRequest2()
        {
            return "{\n" +
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
        }

        public static string TCMergedSignRequests()
        {
            return "{\n" +
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
        }

        public static string AuthToken()
        {
            return "eyJ0eXAiOiJ...KV1QiLC6chGIM";
        }

        public static string TCFullResponse()
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
                "      },\n" +
                "      {\n" +
                "        \"attributes\": {\n" +
                "          \"hideResponseInput\": true,\n" +
                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "          \"webAuthnSignRequest\": " + TCWebAuthnSignRequest1() +
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
                "          \"webAuthnSignRequest\": " + TCWebAuthnSignRequest2() +
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
        }

        public static string TCResponsePostAuth()
        {
            return "{\n" +
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
                "            \"token\": \"" + AuthToken() + "\",\n" +
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
        }

        public static string TCResponseNoAuthToken()
        {
            return "{\n" +
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
        }

        public static string TCResponsePreferredMode(string preferredClientMode)
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

        public static string TCResponseSingleWebauthn()
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
                "      },\n" +
                "      {\n" +
                "        \"attributes\": {\n" +
                "          \"hideResponseInput\": true,\n" +
                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                "          \"webAuthnSignRequest\": " + TCWebAuthnSignRequest1() +
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
        }

        public static string TCResponseNoWebauthn()
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

        public static string TCResponseMissingChallengeElement()
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
                "        \"serial\": \"OATH00020121\",\n" +
                "        \"transaction_id\": \"02659936574063359702\",\n" +
                "        \"type\": \"hotp\"\n" +
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
        }

        public static string RemoveWhitespaces(string str)
        {
            return string.Join("", str.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));
        }

        //Debug.WriteLine("write here a message to debug the tests...");
    }
}