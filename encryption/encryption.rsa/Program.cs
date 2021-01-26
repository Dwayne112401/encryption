using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace encryption.rsa
{
    class Program
    {
        static void Main(string[] args)
        {
            {
                Console.WriteLine("-----------------------------------------------------RSA 字符串加密与解密--------------------------------------------------");
                var input = "公钥密码体制中，目前最著名的是由美国三位科学家Rivest, Shamir 和 Adleman 于1976年提出，并在1978年正式发表的RSA 算法。";
                Console.Write($"加密内容：{input}\r\n");
                var rsa = new RsaAlgorithm();
                Console.WriteLine($"RSA公钥：\r\n{rsa.PublicKey}\r\n");
                Console.WriteLine($"RSA私钥：\r\n{rsa.PrivateKey}\r\n");
                var encrypt = rsa.Encrypt(input);
                Console.WriteLine($"RSA加密后内容：\r\n{encrypt}\r\n");
                Console.WriteLine($"RSA解密后内容：\r\n{rsa.Decrypt(encrypt)}\r\n");
                Console.WriteLine($"RSA签名[SHAI]：\r\n{rsa.Sign("SHA1", input)}\r\n");
            }

            {
                Console.WriteLine("-----------------------------------------------------RSA 文件加密与解密--------------------------------------------------");
                var input = System.IO.File.ReadAllBytes(@"C:\Users\97460\Desktop\1.rar");
                Console.Write($"加密内容：{Convert.ToBase64String(input)}\r\n");
                var rsa = new RsaAlgorithm(1024);
                Console.WriteLine($"RSA公钥：\r\n{rsa.PublicKey}\r\n");
                Console.WriteLine($"RSA私钥：\r\n{rsa.PrivateKey}\r\n");
                var encrypt = rsa.Encrypt(input);
                Console.WriteLine($"RSA加密后内容：\r\n{Convert.ToBase64String(encrypt)}\r\n");
                var decrypt = rsa.Decrypt(encrypt);
                Console.WriteLine($"RSA解密后内容：\r\n{Convert.ToBase64String(decrypt)}\r\n");
                Console.WriteLine($"RSA签名[SHAI]：\r\n{rsa.Sign("SHA1", input)}\r\n");
                System.IO.File.WriteAllBytes("1.rar", decrypt);
            }

            {
                Console.WriteLine("-----------------------------------------------------RSA 使用证书加密与解密字符串--------------------------------------------------");
                var input = "公钥密码体制中，目前最著名的是由美国三位科学家Rivest, Shamir 和 Adleman 于1976年提出，并在1978年正式发表的RSA 算法。";
                Console.Write($"加密内容：{input}\r\n");

                // 证书加密
                var rsaEncrypt = new RsaAlgorithm(1024);
                rsaEncrypt.X509CertCreateEncryptRSA(@"RSAKey.cer");
                Console.WriteLine($"RSA公钥：\r\n{rsaEncrypt.PublicKey}\r\n");
                Console.WriteLine($"RSA私钥：\r\n{rsaEncrypt.PrivateKey}\r\n");
                var encrypt = rsaEncrypt.Encrypt(input);
                Console.WriteLine($"RSA加密后内容：\r\n{encrypt}\r\n");

                // 证书解密
                var rsaDecrypt = new RsaAlgorithm(1024);
                rsaDecrypt.X509CertCreateDecryptRSA(@"RSAKey.pfx", "888888");
                var decrypt = rsaDecrypt.Decrypt(encrypt);
                Console.WriteLine($"RSA解密后内容：\r\n{decrypt}\r\n");
                Console.WriteLine($"RSA签名[SHAI]：\r\n{rsaDecrypt.Sign("SHA1", input)}\r\n");
            }
            Console.ReadKey();
        }
    }
}
