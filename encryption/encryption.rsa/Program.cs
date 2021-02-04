using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using encryption.rsa.github;

namespace encryption.rsa
{
    class Program
    {
        static void Main(string[] args)
        {
            //{
            //    Console.WriteLine("-----------------------------------------------------RSA 字符串加密与解密以及签名与验签--------------------------------------------------");
            //    var input = "公钥密码体制中，目前最著名的是由美国三位科学家Rivest, Shamir 和 Adleman 于1976年提出，并在1978年正式发表的RSA 算法。";
            //    Console.Write($"加密内容：{input}\r\n");
            //    var rsa = new RsaAlgorithm();

            //    Console.WriteLine($"RSA公钥：\r\n{rsa.PublicKey}\r\n");
            //    var encrypt = rsa.Encrypt(input);
            //    Console.WriteLine($"RSA加密后内容：\r\n{encrypt}\r\n");
            //    var sign = rsa.Sign("SHA1", input);
                
            //    Console.WriteLine($"RSA私钥：\r\n{rsa.PrivateKey}\r\n");
            //    var decrypt = rsa.Decrypt(encrypt);
            //    Console.WriteLine($"RSA解密后内容：\r\n{decrypt}\r\n");

            //    Console.WriteLine($"RSA生成数字签名[SHAI]：\r\n{sign}\r\n");
            //    string signResult = rsa.VerifySign(decrypt, "SHA1", sign) ? "验签通过" : "验签未通过";
            //    Console.WriteLine($"RSA进行鉴别数字签名：{signResult}");
            //}

            //{
            //    Console.WriteLine("-----------------------------------------------------RSA 文件加密与解密--------------------------------------------------");
            //    var input = System.IO.File.ReadAllBytes(@"1.rar");
            //    Console.Write($"加密内容：{Convert.ToBase64String(input)}\r\n");
            //    var rsa = new RsaAlgorithm(1024);

            //    Console.WriteLine($"RSA私钥：\r\n{rsa.PrivateKey}\r\n");
            //    var encrypt = rsa.Encrypt(input);
            //    Console.WriteLine($"RSA加密后内容：\r\n{Convert.ToBase64String(encrypt)}\r\n");

            //    Console.WriteLine($"RSA公钥：\r\n{rsa.PublicKey}\r\n");
            //    var decrypt = rsa.Decrypt(encrypt);
            //    Console.WriteLine($"RSA解密后内容：\r\n{Convert.ToBase64String(decrypt)}\r\n");
            //    System.IO.File.WriteAllBytes(".\\copy\\1.rar", decrypt);
            //}


            //{
            //    Console.WriteLine("-----------------------------------------------------通过读取PEM文件 RSA 文件加密与解密--------------------------------------------------");
            //    var input = "公钥密码体制中，目前最著名的是由美国三位科学家Rivest, Shamir 和 Adleman 于1976年提出，并在1978年正式发表的RSA 算法。";
            //    Console.Write($"加密内容：{input}\r\n");
            //    var rsa = new RsaAlgorithm();

            //    rsa.CreateEncryptRSA(System.IO.File.ReadAllText("RSAKey.cer"));
            //    Console.WriteLine($"RSA公钥：\r\n{rsa.PublicKey}\r\n");
            //    var encrypt = rsa.Encrypt(input);
            //    Console.WriteLine($"RSA加密后内容：\r\n{encrypt}\r\n");
                
            //    rsa.CreateDecryptRSA(System.IO.File.ReadAllText("RSAKey.pfx"));
            //    Console.WriteLine($"RSA私钥：\r\n{rsa.PrivateKey}\r\n");
            //    var decrypt = rsa.Decrypt(encrypt);
            //    Console.WriteLine($"RSA解密后内容：\r\n{decrypt}\r\n");

            //    // 私钥签名，公钥验签
            //    var sign = rsa.Sign("SHA1", input);
            //    Console.WriteLine($"RSA生成数字签名[SHAI]：\r\n{sign}\r\n");
            //    string signResult = rsa.VerifySign(decrypt, "SHA1", sign) ? "验签通过" : "验签未通过";
            //    Console.WriteLine($"RSA进行鉴别数字签名：{signResult}");
            //}

            {
                Console.WriteLine("-----------------------------------------------------通过读取PEM文件 RSA 文件加密与解密--------------------------------------------------");
                
                // 公钥加密与签名
                string key = System.IO.File.ReadAllText("pub.txt");
                var rsa = new github.RSA(key,true);
                var encode = rsa.Encode(Encoding.UTF8.GetBytes("123"));
                
                // 私钥解密与验签
                key = System.IO.File.ReadAllText("pri.txt");
                var rsaDecrypt=new github.RSA(key,true);
                var decrypt = rsaDecrypt.DecodeOrNull(encode);
                Console.WriteLine(Encoding.UTF8.GetString(decrypt));

                // 私钥签名与公钥验签
                var sign = rsaDecrypt.Sign("MD5", "123");
                Console.WriteLine($"RSA进行鉴别数字签名：{ rsa.Verify("MD5", sign, "123")}");

            }

            //{
            //    Console.WriteLine("-----------------------------------------------------RSA 使用证书加密与解密字符串--------------------------------------------------");
            //    var input = "公钥密码体制中，目前最著名的是由美国三位科学家Rivest, Shamir 和 Adleman 于1976年提出，并在1978年正式发表的RSA 算法。";
            //    Console.Write($"加密内容：{input}\r\n");

            //    // 证书加密
            //    var rsaEncrypt = new RsaAlgorithm();
            //    rsaEncrypt.X509CertCreateEncryptRSA(@"RSAKey.cer");
            //    Console.WriteLine($"RSA私钥：\r\n{rsaEncrypt.PrivateKey}\r\n");
            //    var encrypt = rsaEncrypt.Encrypt(input);
            //    Console.WriteLine($"RSA加密后内容：\r\n{encrypt}\r\n");

            //    // 证书解密
            //    var rsaDecrypt = new RsaAlgorithm(1024);
            //    rsaDecrypt.X509CertCreateDecryptRSA(@"RSAKey.pfx", "888888");
            //    Console.WriteLine($"RSA公钥：\r\n{rsaEncrypt.PublicKey}\r\n");
            //    var decrypt = rsaDecrypt.Decrypt(encrypt);
            //    Console.WriteLine($"RSA解密后内容：\r\n{decrypt}\r\n");
            //}
            Console.ReadKey();
        }
    }
}
