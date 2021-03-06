/*
 * MIT License
 * 
 * Copyright (c) 2022 Patrick Borger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using AdysTech.CredentialManager;
using Microsoft.Win32;
using OtpNet;

namespace XIVLauncher_AutoOTP
{
    class Program
    {
        public static string Username;

        public static string OTP
        {
            private get
            {
                ICredential icredential;
                try
                {
                    icredential = CredentialManager.GetICredential($"FINAL FANTASY XIV-{Username.ToLower()}-OTP");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"No credentials for the username {Username} found.");
                    throw;
                }

                if (icredential != null)
                {
                    Encrypted = bool.Parse(icredential.Comment.Substring(0, icredential.Comment.IndexOf("-", StringComparison.Ordinal)));
                    Steam     = bool.Parse(icredential.Comment.Substring(icredential.Comment.IndexOf("-", StringComparison.Ordinal) + 1));
                    return icredential.ToNetworkCredential().Password;

                }

                return string.Empty;
            }
            set
            {
                try
                {
                    CredentialManager.RemoveCredentials($"FINAL FANTASY XIV-{Username.ToLower()}-OTP");
                }
                catch (Exception ex)
                {
                    // ignore
                }

                var credential = (new NetworkCredential { UserName = Username, Password = value }).ToICredential();
                credential.TargetName  = $"FINAL FANTASY XIV-{Username.ToLower()}-OTP";
                credential.Comment     = $"{Encrypted.ToString()}-{Steam.ToString()}";
                credential.Persistance = Persistance.Enterprise;
                credential.SaveCredential();
            }
        }

        public static bool Encrypted;

        public static bool Steam;

        public static bool PortInUse(int port)
        {
            bool inUse = false;

            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[]       ipEndPoints  = ipProperties.GetActiveTcpListeners();


            foreach (IPEndPoint endPoint in ipEndPoints)
            {
                if (endPoint.Port == port)
                {
                    inUse = true;
                    break;
                }
            }

            return inUse;
        }

        public static string checkInstalled(string p_name)
        {
            string      displayName;
            RegistryKey key;

            key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            foreach (String keyName in key.GetSubKeyNames())
            {
                RegistryKey subkey = key.OpenSubKey(keyName);
                displayName = subkey.GetValue("DisplayName") as string;
                if (p_name.Equals(displayName, StringComparison.OrdinalIgnoreCase) == true)
                {
                    return subkey.GetValue("InstallLocation") as string;
                }
            }

            return null;
        }

        static void Login()
        {
            var launcherPath = checkInstalled("XIVLauncher");
            if (string.IsNullOrEmpty(launcherPath))
            {
                Console.WriteLine("XIVLauncher not found!");
                return;
            }

            launcherPath = launcherPath + "\\XIVLauncher.exe";

            string  launcherConfig = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\XIVLauncher\\launcherConfigV3.json";
            string  json           = File.ReadAllText(launcherConfig);
            dynamic jsonObj        = Newtonsoft.Json.JsonConvert.DeserializeObject(json);
            jsonObj["AutologinEnabled"] = "true";
            string output = Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText(launcherConfig, output);

            var secretKey = OTP;
            Totp totp;

            if (Encrypted)
            {
                var base32Bytes = Base32Encoding.ToBytes(DPAPI.Unprotect(secretKey, DataProtectionScope.CurrentUser, AsteriskCredentials(false)));
                totp = new Totp(base32Bytes);
            }
            else
            {
                var base32Bytes = Base32Encoding.ToBytes(secretKey);
                totp = new Totp(base32Bytes);
            }

            var otp = totp.ComputeTotp();

            Console.WriteLine();
            Console.WriteLine($"OTP: {otp}");

            System.Diagnostics.Process.Start(launcherPath, $"--account={Username.ToLower()}-True-{Steam.ToString()}");
            while (!PortInUse(4646))
            {
                System.Threading.Thread.Sleep(1000);
            }

            _ = new HttpClient().GetAsync($"http://localhost:4646/ffxivlauncher/{otp}").Result;
        }

        static string AsteriskCredentials(bool otp)
        {
            Console.WriteLine("Please enter your " + (otp ? "OTP secret key to encrypt:" : "passphrase for encryption:"));
            var        pass = string.Empty;
            ConsoleKey key;

            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;
                
                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            return pass;
        }

        static void AddCredentials()
        {
            Console.WriteLine("Are you using Steam? (Y/N)");
            switch (Console.ReadLine()?.ToUpper())
            {
                case "Y":
                    Steam = true;
                    break;
                case "N":
                    Steam = false;
                    break;
                default:
                    return;
            }

            Console.WriteLine("(RECOMMENDED) Do you want to encrypt your key? (Y/N)");
            switch (Console.ReadLine()?.ToUpper())
            {
                case "Y":
                    Encrypted = true;
                    Console.WriteLine("Do you want your key/passphrase to be shown while typing? (Y/N)");
                    string otpSecretKey;
                    string passphrase;
                    switch (Console.ReadLine()?.ToUpper())
                    {
                        case "Y":
                            Console.WriteLine("Please enter your OTP secret key:");
                            otpSecretKey = Console.ReadLine();
                            Console.WriteLine("Please enter your passphrase for encryption:");
                            passphrase = Console.ReadLine();
                            if (!string.IsNullOrEmpty(otpSecretKey) && !string.IsNullOrEmpty(passphrase))
                            {
                                OTP = DPAPI.Protect(otpSecretKey, DataProtectionScope.CurrentUser, passphrase);
                                return;
                            }

                            Console.WriteLine("You haven't entered either a secret key or passphrase!");
                            return;
                        case "N":
                            otpSecretKey = AsteriskCredentials(true);
                            passphrase   = AsteriskCredentials(false);
                            if (!string.IsNullOrEmpty(otpSecretKey) && !string.IsNullOrEmpty(passphrase))
                            {
                                OTP = DPAPI.Protect(otpSecretKey, DataProtectionScope.CurrentUser, passphrase);
                                return;
                            }

                            Console.WriteLine("You haven't entered either a secret key or passphrase!");
                            return;
                        default:
                            return;
                    }
                case "N":
                    Console.WriteLine("Do you want your OTP secret key to be shown while typing? (Y/N)");
                    Encrypted = false;
                    string secretKey;
                    switch (Console.ReadLine()?.ToUpper())
                    {
                        case "Y":
                            Console.WriteLine("Please enter your OTP secret key:");
                            secretKey = Console.ReadLine();
                            if (!string.IsNullOrEmpty(secretKey))
                            {
                                OTP = secretKey;
                            }
                            else
                            {
                                Console.WriteLine("You haven't entered a secret key!");
                            }

                            return;
                        case "N":
                            secretKey = AsteriskCredentials(true);
                            if (!string.IsNullOrEmpty(secretKey))
                            {
                                OTP = secretKey;
                            }
                            else
                            {
                                Console.WriteLine("You haven't entered a secret key!");
                            }

                            return;
                        default:
                            return;
                    }
            }
        }

        public class DPAPI
        {
            public static string Protect(string stringToEncrypt, DataProtectionScope scope, string optionalEntropy = null)
            {
                return Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(stringToEncrypt), optionalEntropy != null ? Encoding.UTF8.GetBytes(optionalEntropy) : null, scope));
            }

            public static string Unprotect(string encryptedString, DataProtectionScope scope, string optionalEntropy = null)
            {
                return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encryptedString), optionalEntropy != null ? Encoding.UTF8.GetBytes(optionalEntropy) : null, scope));
            }
        }

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                foreach (string arg in args)
                {
                    if (arg.StartsWith("--Username="))
                    {
                        Username = arg.Substring(arg.IndexOf("=") + 1);
                        Console.WriteLine("Logging in as: " + Username);
                    }
                }

                Login();
            }
            else
            {

                bool optionChosen = false;
                Console.WriteLine("1) Add new user credentials");
                Console.WriteLine("2) Login with user");
                Console.WriteLine("5) Delete credential");
                Console.WriteLine("0) Exit");
                while (!optionChosen)
                {
                    switch (Console.ReadLine())
                    {
                        case "1":
                            Console.Clear();
                            Console.WriteLine("-- Add new user credentials --");
                            Console.WriteLine("Please enter your account name:");
                            Username = Console.ReadLine();
                            AddCredentials();
                            optionChosen = true;
                            return;
                        case "2":
                            Console.Clear();
                            Console.WriteLine("-- Login with user --");
                            Console.WriteLine("Please enter your account name:");
                            Username = Console.ReadLine();
                            Login();
                            optionChosen = true;
                            return;
                        case "5":
                            Console.Clear();
                            Console.WriteLine("-- Delete Credentials --");
                            Console.WriteLine("Please enter your credentials account name you want to delete:");
                            Username = Console.ReadLine();
                            if (!string.IsNullOrEmpty(Username))
                            {
                                try
                                {
                                    CredentialManager.RemoveCredentials($"FINAL FANTASY XIV-{Username.ToLower()}-OTP");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine("Credentials not found!");
                                    throw;
                                }
                            }
                            return;
                        case "0":
                            optionChosen = true;
                            return;
                        default:
                            optionChosen = false;
                            break;
                    }

                }
            }
        }
    }
}



