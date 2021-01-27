using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace encryption.rsa
{
    /// <summary>
    /// https://cloud.tencent.com/developer/article/1054441
    /// </summary>
    public class RsaAlgorithm
    {
        public Encoding Encoding { get; set; }
        public string PrivateKey { get;private set; }
        public string PublicKey { get;private set; }

        private  RSACryptoServiceProvider _rsa;
        private int _keySize;
        #region .ctor

        public RsaAlgorithm(int keySize=512)
        {
            _keySize = keySize;
            _rsa = new RSACryptoServiceProvider() { KeySize = _keySize };
            Encoding = Encoding.UTF8;
            PrivateKey = _rsa.ToXmlString(true);
            PublicKey = _rsa.ToXmlString(false);
        }

        #endregion

        #region 创建RSA

        /// <summary>
        /// 创建加密RSA
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public  RSACryptoServiceProvider CreateEncryptRSA(string publicKey)
        {
            try
            {
                _rsa = new RSACryptoServiceProvider() { KeySize = _keySize };
                _rsa.FromXmlString(publicKey);
                PublicKey = publicKey;
                PrivateKey = null;
                return _rsa;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 根据字符串创建解密RSA
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public RSACryptoServiceProvider CreateDecryptRSA(string privateKey)
        {
            try
            {
                _rsa = new RSACryptoServiceProvider() { KeySize = _keySize };
                _rsa.FromXmlString(privateKey);
                PublicKey = null;
                PrivateKey = privateKey;
                return _rsa;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 根据安全证书创建加密RSA
        /// </summary>
        /// <param name="certfile">公钥文件</param>
        /// <returns></returns>
        public RSACryptoServiceProvider X509CertCreateEncryptRSA(string certfile)
        {
            try
            {
                if (File.Exists(certfile)==false)
                {
                    throw new ArgumentNullException(certfile, "加密证书未找到");
                }
                X509Certificate2 x509Cert = new X509Certificate2(certfile);
                _rsa = (RSACryptoServiceProvider)x509Cert.PublicKey.Key;
                return _rsa;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 根据私钥文件创建解密RSA
        /// </summary>
        /// <param name="keyfile">私钥文件</param>
        /// <param name="password">访问含私钥文件的密码</param>
        /// <returns></returns>
        public RSACryptoServiceProvider X509CertCreateDecryptRSA(string keyfile, string password)
        {
            try
            {
                if (File.Exists(keyfile)==false)
                {
                    throw new ArgumentNullException(keyfile, "解密证书未找到");
                }
                X509Certificate2 x509Cert = new X509Certificate2(keyfile, password);
                _rsa = (RSACryptoServiceProvider)x509Cert.PrivateKey;
                return _rsa;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        #endregion


        #region 加密

        /// <summary>
        /// RSA 加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <returns></returns>
        public string Encrypt(string dataToEncrypt)
        {
            byte[] bufferBytes = Encoding.GetBytes(dataToEncrypt);
            return Convert.ToBase64String(this.Encrypt(bufferBytes));
        }

        /// <summary>
        /// RSA 加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] dataToEncrypt)
        {
            byte[] data = null;
            int blockLen = _rsa.KeySize / 8 - 11;
            if (dataToEncrypt.Length <= blockLen)
            {
                return _rsa.Encrypt(dataToEncrypt, false);
            }

            using (var dataStream = new MemoryStream(dataToEncrypt))
            using (var enStream = new MemoryStream())
            {
                Byte[] buffer = new Byte[blockLen];
                int len = dataStream.Read(buffer, 0, blockLen);

                while (len > 0)
                {
                    Byte[] block = new Byte[len];
                    Array.Copy(buffer, 0, block, 0, len);

                    Byte[] enBlock = _rsa.Encrypt(block, false);
                    enStream.Write(enBlock, 0, enBlock.Length);

                    len = dataStream.Read(buffer, 0, blockLen);
                }

                data = enStream.ToArray();
            }

            return data;
        }

        #endregion


        #region 解密

        /// <summary>
        /// RSA 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据<see cref="string"/></param>
        /// <returns></returns>
        public string Decrypt(string encryptedData)
        {
            string str = null;
            byte[] buffer = Convert.FromBase64String(encryptedData);
            return Encoding.GetString(this.Decrypt(buffer));
        }

        /// <summary>
        /// RSA 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据(byte数组)<see cref="byte"/></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] encryptedData)
        {
            byte[] data = null;
            int blockLen = _rsa.KeySize / 8;
            if (encryptedData.Length <= blockLen)
            {
                return _rsa.Decrypt(encryptedData, false);
            }

            using (var dataStream = new MemoryStream(encryptedData))
            using (var deStream = new MemoryStream())
            {
                Byte[] buffer = new Byte[blockLen];
                int len = dataStream.Read(buffer, 0, blockLen);

                while (len > 0)
                {
                    Byte[] block = new Byte[len];
                    Array.Copy(buffer, 0, block, 0, len);

                    Byte[] deBlock = _rsa.Decrypt(block, false);
                    deStream.Write(deBlock, 0, deBlock.Length);

                    len = dataStream.Read(buffer, 0, blockLen);
                }

                data = deStream.ToArray();
            }

            return data;
        }

        #endregion

        #region 签名与验签
        /// <summary>
        ///  RSA 签名
        /// https://docs.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.signdata?view=net-5.0
        /// </summary>
        /// <param name="hash">报文摘要算法</param>
        /// <param name="str">报文数据</param>
        /// <returns></returns>
        public string Sign(string hash, string str)
        {
            byte[] data = Encoding.GetBytes(str);
            byte[] sign = _rsa.SignData(data, hash);
            return Convert.ToBase64String(sign);
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="hash">报文摘要算法</param>
        /// <param name="data">报文数据</param>
        /// <returns></returns>
        public string Sign(string hash, byte[] data)
        {
            byte[] sign = _rsa.SignData(data, hash);
            return Convert.ToBase64String(sign);
        }

        /// <summary>
        /// 验签
        /// </summary>
        /// <param name="data">报文数据</param>
        /// <param name="hash">报文摘要算法</param>
        /// <param name="sign">签名</param>
        /// <returns></returns>
        public bool VerifySign(byte[] data, string hash,string sign)
        {
            byte[] signBytes = Convert.FromBase64String(sign);
            return _rsa.VerifyData(data, hash, signBytes);
        }

        /// <summary>
        /// 验签
        /// </summary>
        /// <param name="data">报文数据</param>
        /// <param name="hash">报文摘要算法</param>
        /// <param name="sign">签名</param>
        /// <returns></returns>
        public bool VerifySign(string data, string hash, string sign)
        {
            return VerifySign(Encoding.GetBytes(data),hash,sign);
        }
        #endregion
    }
}
