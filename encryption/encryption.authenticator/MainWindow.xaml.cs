using Google.Authenticator;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace encryption.authenticator
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

        }

        // 密钥
        private string key = "123456";

        // 生成新的二维码
        private void ButtonBase_OnClick1(object sender, RoutedEventArgs e)
        {
            // 发行人
            string issuer = TextBoxIssuer.Text;

            //登陆账号名称
            string user = TextBoxUser.Text;

            // 生成 SetupCode
            var code  = new GoogleAuthenticator().GenerateSetupCode(issuer, user, key, 5);

            // 转换成位图
            var img = GoogleAuthenticator.GetQRCodeImage(code.QrCodeSetupImageUrl);

            // 展示位图
            {
                Bitmap bitmap = img as Bitmap;
                IntPtr myImagePtr = bitmap.GetHbitmap();
                ImageSource imgsource = System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(myImagePtr, IntPtr.Zero, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());  //创建imgSource
                ImageQRCode.Source = imgsource;
            }
        }

        // 验证校验
        private void ButtonBase_OnClick(object sender, RoutedEventArgs e)
        {
            string token = TextBoxToken.Text;
            if (string.IsNullOrEmpty(token) == false)
            {
                GoogleAuthenticator gat = new GoogleAuthenticator();
                var result = gat.ValidateTwoFactorPIN(key, token.ToString());
                if (result)
                {
                    MessageBox.Show("动态码校验通过！", "提示信息", MessageBoxButton.OK, MessageBoxImage.Question);
                }
                else
                {
                    MessageBox.Show("动态码校验未通过！", "提示信息", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }
    }

   
}
