using System;
using System.Security.Cryptography;
using System.Text;
using encryption.md5;

public class Program
{  
    static void Main()
    {
        {
            Console.WriteLine("-----------------------------------------------------生成MD5--------------------------------------------------");
            var input = "目前广泛应用的报文摘要算法有MD5[RFC1321]和安全散列算法1（SecureHashAlgorithm,SHA-1）。";
            Console.WriteLine($"内容：{input}");
            byte[] md5 = Md5Util.GetMD5(input);
            Console.WriteLine($"MD5：{Convert.ToBase64String(md5)}");
        }

        {
            Console.WriteLine("-----------------------------------------------------MD5防篡改校验--------------------------------------------------");
            var input = "https://docs.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.md5?view=net-5.0";
            Console.WriteLine($"内容：{input}");
            byte[] md5 = Md5Util.GetMD5(input+"不一致");
            Console.WriteLine($"MD5校验：{Md5Util.VerifyMD5(input, md5)}");
        }

        {
            Console.WriteLine("-----------------------------------------------------生成SHA512--------------------------------------------------");
            var input = "目前广泛应用的报文摘要算法有MD5[RFC1321]和安全散列算法1（SecureHashAlgorithm,SHA-1）。";
            Console.WriteLine($"内容：{input}");
            byte[] md5 = Md5Util.GetMD5(input,Md5Util.MD.SHA512);
            Console.WriteLine($"SHA512：{Convert.ToBase64String(md5)}");
        }

        {
            Console.WriteLine("-----------------------------------------------------SHA512防篡改校验--------------------------------------------------");
            var input = "https://docs.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.md5?view=net-5.0";
            Console.WriteLine($"内容：{input}");
            byte[] md5 = Md5Util.GetMD5(input, Md5Util.MD.SHA512);
            Console.WriteLine($"SHA512校验：{Md5Util.VerifyMD5(input, md5, Md5Util.MD.SHA512)}");
        }

        Console.ReadKey();
    }
}
    