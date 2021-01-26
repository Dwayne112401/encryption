using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace encryption.des
{
    /// <summary>
    /// 3DES加密与解密
    /// </summary>
    public class TripleDesAlgorithm
    {
        public Encoding Encoding { get; set; }
        public PaddingMode Padding { get; set; }
        public CipherMode Mode { get; set; }
        public string PassWord { get; private set; }

        private TripleDESCng _des;

        #region .ctor

        public TripleDesAlgorithm()
        {
            _des = new TripleDESCng();
            PassWord = Convert.ToBase64String(_des.Key);
            Encoding = Encoding.UTF8;
            Padding = PaddingMode.PKCS7;
            Mode = CipherMode.CBC;
        }
        #endregion

        /// <summary>
        /// 通过字符串生成新的密钥
        /// </summary>
        /// <param name="password">密码</param>
        /// <returns></returns>
        public TripleDESCng CreateNewkey(string password)
        {
            try
            {
                byte[] key = Encoding.GetBytes(password).Skip(0).Take(24).ToArray();
                byte[] iv = Encoding.GetBytes(password).Skip(0).Take(8).ToArray();
                _des = new TripleDESCng()
                {
                    Key = key,
                    IV = iv,
                };
                PassWord = password;
                return _des;
            }
            catch (Exception e)
            {
                throw new Exception($"The length of password is Wrong:{e.Message}",e);
            }
        }

        /// <summary>
        /// 3DES加密
        /// </summary>
        /// <param name="pToEncrypt">需要加密的字符串<see cref="string"/></param>
        /// <returns></returns>
        public string Encrypt(string pToEncrypt)
        {
            byte[] inputByteArray = Encoding.GetBytes(pToEncrypt);
            return Convert.ToBase64String(this.Encrypt(inputByteArray));
        }

        /// <summary>
        /// 3DES加密
        /// </summary>
        /// <param name="pToEncrypt">需要加密的byte数组<see cref="byte"/></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] pToEncrypt)
        {
            byte[] base64 = null;
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, _des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(pToEncrypt, 0, pToEncrypt.Length);
                    cs.FlushFinalBlock();
                }
                base64 = ms.ToArray();
            }
            return base64;
        }

        /// <summary>
        /// 3DES解密
        /// </summary>
        /// <param name="pToDecrypt">需要解密的字符串<see cref="string"/></param>
        /// <returns></returns>
        public string Decrypt(string pToDecrypt)
        {
            byte[] inputByteArray = Convert.FromBase64String(pToDecrypt);
            return Encoding.GetString(this.Decrypt(inputByteArray));
        }

        /// <summary>
        /// 3DES解密
        /// </summary>
        /// <param name="pToDecrypt">需要解密的byte数组<see cref="byte"/></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] pToDecrypt)
        {
            byte[] data = null;
            using (var ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, _des.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(pToDecrypt, 0, pToDecrypt.Length);
                    cs.FlushFinalBlock();
                }
                data = (ms.ToArray());
            }
            return data;
        }
    }
}
