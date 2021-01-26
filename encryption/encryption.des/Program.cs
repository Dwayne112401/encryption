using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace encryption.des
{
    class Program
    {
        static void Main(string[] args)
        {
            // DES字符串加密与解密
            {
                Console.WriteLine("-----------------------------------------------------DES字符串加密与解密--------------------------------------------------");
                var input = "数据加密标准（ Data Encryption Standard， DES）是对称密钥密码的典型代表，由IBM公司研制，于1977年被美国定为联邦信息标准 。";
                Console.Write($"加密内容：\r\n{input}\r\n");
                var des = new DesAlgorithm();
                // TEST:可使用该方法通过字符串生成新的密钥
                //des.CreateNewkey("https://www.cnblogs.com/dongweian");
                Console.WriteLine($"DES密钥：\r\n{des.PassWord}\r\n");
                var encrypt = des.Encrypt(input);
                Console.WriteLine($"DES加密后内容：\r\n{encrypt}\r\n");
                var decrypt = des.Decrypt(encrypt);
                Console.WriteLine($"DES解密后内容：\r\n{decrypt}\r\n");
            }

            // DES文件加密与解密
            {
                Console.WriteLine("---------------------------------------------------DES文件加密与解密--------------------------------------------------");
                var input = System.IO.File.ReadAllBytes(@"C:\Users\97460\Desktop\1.rar");
                Console.Write($"加密内容：\r\n{Convert.ToBase64String(input)}\r\n");
                var des = new DesAlgorithm();
                // TEST:可使用该方法通过字符串生成新的密钥
                //des.CreateNewkey("https://www.cnblogs.com/dongweian");
                Console.WriteLine($"DES密钥：\r\n{des.PassWord}\r\n");
                var encrypt = des.Encrypt(input);
                Console.WriteLine($"DES加密后内容：\r\n{Convert.ToBase64String(encrypt)}\r\n");
                var decrypt = des.Decrypt(encrypt);
                Console.WriteLine($"DES解密后内容：\r\n{Convert.ToBase64String(decrypt)}\r\n");
                System.IO.File.WriteAllBytes("1.rar", decrypt);
            }



            // 3DES字符串加密与解密
            {
                Console.WriteLine("---------------------------------------------------3DES字符串加密与解密--------------------------------------------------");
                var input = "数据加密标准（ Data Encryption Standard， DES）是对称密钥密码的典型代表，由IBM公司研制，于1977年被美国定为联邦信息标准 。";
                Console.Write($"加密内容：\r\n{input}\r\n");
                var des = new TripleDesAlgorithm();
                // TEST:可使用该方法通过字符串生成新的密钥
                //des.CreateNewkey("https://www.cnblogs.com/dongweian");
                Console.WriteLine($"3DES密钥：\r\n{des.PassWord}\r\n");
                var encrypt = des.Encrypt(input);
                Console.WriteLine($"3DES加密后内容：\r\n{encrypt}\r\n");
                var decrypt = des.Decrypt(encrypt);
                Console.WriteLine($"DES解密后内容：\r\n{decrypt}\r\n");
            }

            // 3DES文件加密与解密
            {
                Console.WriteLine("---------------------------------------------------3DES文件加密与解密--------------------------------------------------");
                var input = System.IO.File.ReadAllBytes(@"C:\Users\97460\Desktop\1.rar");
                Console.Write($"加密内容：\r\n{Convert.ToBase64String(input)}\r\n");
                var des = new TripleDesAlgorithm();
                // TEST:可使用该方法通过字符串生成新的密钥
                //des.CreateNewkey("https://www.cnblogs.com/dongweian");
                Console.WriteLine($"3DES密钥：\r\n{des.PassWord}\r\n");
                var encrypt = des.Encrypt(input);
                Console.WriteLine($"3DES加密后内容：\r\n{Convert.ToBase64String(encrypt)}\r\n");
                var decrypt = des.Decrypt(encrypt);
                Console.WriteLine($"3DES解密后内容：\r\n{Convert.ToBase64String(decrypt)}\r\n");
                System.IO.File.WriteAllBytes("1.rar", decrypt);
            }
            Console.ReadKey();
        }
    }
}
