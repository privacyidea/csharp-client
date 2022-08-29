using System;

namespace PrivacyIDEA_Client
{
    public interface PILog
    {
        void Log(string message);

        void Error(string message);

        void Error(Exception exception);
    }
}
