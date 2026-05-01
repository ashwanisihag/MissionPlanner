using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using log4net;
using MissionPlanner.Utilities;
using Org.BouncyCastle.Ocsp;
using static MissionPlanner.Utilities.LTM;

namespace MissionPlanner.Mavlink
{
    public class MAVAuthKeys
    {
        private static readonly ILog log =
    LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        static string keyfile = Settings.GetUserDataDirectory() + "SihagAuthKey.xml";//Ashwani Sihag

        static Crypto Rij = new Crypto();

        public static AuthKeys Keys = new AuthKeys();

        //https://msdn.microsoft.com/en-us/library/aa347850(v=vs.110).aspx

        [CollectionDataContract(ItemName = "AuthKeys", Namespace = "")]
        public class AuthKeys : Dictionary<string, AuthKey>
        {
        }

        [DataContract(Name = "AuthKey", Namespace = "")]
        public struct AuthKey
        {
            [DataMember()]
            public string Name;
            [DataMember()]
            public byte[] Key;
        }

        static MAVAuthKeys()
        {
            Load();
        }

        public static void AddKey(string name, string seed)
        {
            // sha the user input string
            using (SHA256CryptoServiceProvider signit = new SHA256CryptoServiceProvider())
            {
                var shauser = signit.ComputeHash(Encoding.UTF8.GetBytes(seed));
                Array.Resize(ref shauser, 32);

                Keys[name] = new AuthKey() { Key = shauser, Name = name };
            }
        }

        public static void Save()
        {
            // save config
            DataContractSerializer writer =
                new DataContractSerializer(typeof(AuthKeys),
                    new Type[] { typeof(AuthKey) });

            using (var fs = new FileStream(keyfile, FileMode.Create))
            using (var sw = new CryptoStream(fs, Rij.algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                writer.WriteObject(sw, Keys);
            }
           //UploadFileToFTP(keyfile);
        }

        //private static void UploadFileToFTP(string source)
        //{
        //    try
        //    {
        //        string filename = Path.GetFileName(source);
        //        string ftpfullpath = "ftp://win6044.site4now.net/SihagInnovations";
        //        FtpWebRequest ftp = (FtpWebRequest)FtpWebRequest.Create(ftpfullpath);

        //        ftp.Credentials = new NetworkCredential("ashwanisihag-001", "Becool@1979");
        //        //FtpWebRequest.UsePassive;
        //        ftp.KeepAlive = true;
        //        ftp.UseBinary = true;
        //        ftp.Method = WebRequestMethods.Ftp.UploadFile;

        //        FileStream fs = File.OpenRead(source);
        //        byte[] buffer = new byte[fs.Length];
        //        fs.Read(buffer, 0, buffer.Length);
        //        fs.Close();

        //        Stream ftpstream = ftp.GetRequestStream();
        //        ftpstream.Write(buffer, 0, buffer.Length);
        //        ftpstream.Close();
        //    }
        //    catch (Exception ex)
        //    {
        //        throw ex;
        //    }
        //}


        internal static void Load()
        {
            try
            {
                // Try to refresh from the remote store. Failures must not break UI initialization.
                FtpWebRequest request = (FtpWebRequest)WebRequest.Create("ftp://win6044.site4now.net/SihagInnovations/SihagAuthKey.xml");
                request.Method = WebRequestMethods.Ftp.DownloadFile;
                request.UseBinary = true;
                request.Credentials = new NetworkCredential("ashwanisihag-001", "Becool@1979");

                using (FtpWebResponse response = (FtpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (FileStream fs0 = new FileStream(keyfile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    if (stream != null)
                    {
                        stream.CopyTo(fs0);
                    }
                }
            }
            catch (Exception ex)
            {
                // Expected in environments where FTP credentials are invalid or unreachable.
                log.Warn("Unable to download MAVLink auth keys from FTP. Falling back to local key store.", ex);
            }

            if (!File.Exists(keyfile))
                return;

            try
            {

                DataContractSerializer reader =
                    new DataContractSerializer(typeof(AuthKeys),
                        new Type[] { typeof(AuthKey) });

                using (var fs = new FileStream(keyfile, FileMode.Open))
                using (var sr = new CryptoStream(fs, Rij.algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    Keys = (AuthKeys)reader.ReadObject(sr);
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }

        }
    }
}
