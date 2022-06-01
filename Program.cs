using System;
using System.Net;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace WebServerCert3
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpListener listener = new HttpListener();
            // установка адресов прослушки
            listener.Prefixes.Add("http://localhost:5235/");
            listener.Start();
            while (true)
            {
                Console.WriteLine("Ожидание подключений...");
                // метод GetContext блокирует текущий поток, ожидая получение запроса 
                HttpListenerContext context = listener.GetContext();
                HttpListenerRequest request = context.Request;
                // получаем объект ответа
                HttpListenerResponse response = context.Response;

                string webSite = request.Headers.Get("Origin");
                Console.WriteLine($"Веб-сайт {webSite} пытается получить данные сертификатов. Y/N");
                string notyfi = Console.ReadLine();
                string responseStr;
                if (notyfi.ToLower() == "y")
                {
                    responseStr = GetListSert();
                }
                else
                {
                    Console.WriteLine($"Веб-сайт {webSite} не получил ваши сертификаты");
                    responseStr = "Доступ запрещен";
                }

                try
                {
                    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseStr);
                    // получаем поток ответа и пишем в него ответ
                    response.ContentLength64 = buffer.Length;
                    response.AddHeader("Access-Control-Allow-Origin", "*");
                    Stream output = response.OutputStream;
                    output.Write(buffer, 0, buffer.Length);
                    // закрываем поток
                    output.Close();
                    // останавливаем прослушивание подключений
                    Console.WriteLine("Обработка подключений завершена");
                }
                catch (Exception)
                {
                    Console.WriteLine("Подключение потеряно");
                }
            }
        }

        public static string GetListSert()
        {
            string json = "[";
            var certificates = new List<string>();
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                int count = 0;
                foreach (X509Certificate2 x509 in certCollection)
                {
                    string name = x509.IssuerName.Name;
                    string thumbprint = x509.Thumbprint;
                    string has_private_key = x509.HasPrivateKey.ToString().ToLower();
                    string serial_number = x509.SerialNumber;
                    string date_not_after = x509.NotAfter.ToString("R");
                    string date_not_before = x509.NotBefore.ToString("R");
                    string signature_algoruthm = "\"signature_algoruthm\": {\"friendly_name\": \"" + x509.SignatureAlgorithm.FriendlyName + "\", \"value\": \"" + x509.SignatureAlgorithm.Value + "\"}";
                    string subject = "\"subject\": \"" + x509.Subject + "\"";
                    string issuer = "\"issuer\": \"" + x509.Issuer + "\"";
                    string public_key = "\"public_key\": \"" + Convert.ToBase64String(x509.PublicKey.EncodedKeyValue.RawData) + "\"";
                    string private_key = null;
                    if (has_private_key == "true")
                    {
                        //private_key = x509.PrivateKey.ToXmlString(false);
                        var rsa = x509.GetRSAPrivateKey();
                        //byte[] rSAParameters;
                        using (RSA exportRewriter = RSA.Create())
                        {
                            // Only one KDF iteration is being used here since it's immediately being
                            // imported again.  Use more if you're actually exporting encrypted keys.
                            exportRewriter.ImportEncryptedPkcs8PrivateKey(
                                "password",
                                rsa.ExportEncryptedPkcs8PrivateKey(
                                    "password",
                                    new PbeParameters(
                                        PbeEncryptionAlgorithm.Aes128Cbc,
                                        HashAlgorithmName.SHA256,
                                        1)),
                                out _);
                            byte[] byteKey = exportRewriter.ExportPkcs8PrivateKey();
                            private_key = Convert.ToBase64String(byteKey);
                        }
                    }

                    json += "{\"name\": \"" + name + "\"," +
                            " \"thumbprint\": \"" + thumbprint + "\"," +
                            " \"has_private_key\": \"" + has_private_key + "\"," +
                            " \"serial_number\": \"" + serial_number + "\"," +
                            " \"date\": {\"date_not_after\": \"" + date_not_after + "\", \"date_not_before\": \"" + date_not_before + "\"}," +
                            " " + signature_algoruthm + "," +
                            " " + subject + "," +
                            " " + issuer + "," +
                            " " + public_key + "," +
                            " \"private_key\": \"" + private_key + "\"}";

                    certificates.Add(x509.IssuerName.Name);
                    if (count != certCollection.Count - 1)
                    {
                        json += ",";
                    }
                    count++;
                }
                json += "]";
            }
            finally
            {
                store.Close();
            }
            return json;
        }
    }
}
