using System;
using System.Security.Cryptography;
using System.Text;

namespace encryption.md5
{
    public class Md5Util
    {
        public enum MD
        {
            MD5,
            SHA1,
            SHA256,
            SHA512,
        }
        private static HashAlgorithm CreateHashAlgorithm(MD sha)
        {
            switch (sha)
            {
                case MD.MD5:
                    return new MD5CryptoServiceProvider();
                case MD.SHA1:
                    return SHA1.Create();
                case MD.SHA256:
                    return SHA256.Create();
                case MD.SHA512:
                    return SHA512.Create();
            }
            
            throw new Exception($"The type does not exits,type:{sha}");
        }

        /// <summary>
        /// 获取指定byte数组的MD5
        /// </summary>
        /// <param name="source"></param>
        /// <param name="encoding"><see cref="Encoding"/>默认值：UTF8</param>
        /// <returns></returns>
        public static byte[] GetMD5(byte[] source, MD sha=MD.MD5, Encoding encoding = null)
        {
            byte[] output = CreateHashAlgorithm(sha).ComputeHash(source);
            return output;
        }

        /// <summary>
        /// 获取指定字符串的MD5
        /// </summary>
        /// <param name="source"></param>
        /// <param name="encoding"><see cref="Encoding"/>默认值：UTF8</param>
        /// <returns></returns>
        public static byte[] GetMD5(string source, MD sha = MD.MD5, Encoding encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            return GetMD5(encoding.GetBytes(source), sha, encoding);
        }


        /// <summary>
        /// MD5 校验
        /// </summary>
        /// <param name="input">校验二进制</param>
        /// <param name="hash">待比较的MD5 值</param>
        /// <param name="encoding"></param>
        /// <returns>true:相同;false:被纂改</returns>
        public static bool VerifyMD5(byte[] input, byte[] hash, MD sha = MD.MD5, Encoding encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            var buffer = GetMD5(input, sha,encoding);
            if (Convert.ToBase64String(buffer) == Convert.ToBase64String(hash))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// MD5 校验
        /// </summary>
        /// <param name="input">校验字符串</param>
        /// <param name="hash">待比较的MD5 值</param>
        /// <param name="encoding"></param>
        /// <returns>true:相同;false:被纂改</returns>
        public static bool VerifyMD5(string input, byte[] hash, MD sha = MD.MD5, Encoding encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            return VerifyMD5(encoding.GetBytes(input), hash, sha,encoding);
        }
    }
}
