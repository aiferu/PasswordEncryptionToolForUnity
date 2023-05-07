using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using UnityEngine.UI;


/// <summary>
/// 加密算法
/// </summary>
public class Ep : MonoBehaviour
{
    public static Ep ep;
    public InputField inText;
    public InputField outText;
    public InputField keyText;

    private void Awake()
    {
        ep = this;
        WebGLInput.captureAllKeyboardInput = false;
    }

    public static void Encryption()
    {
        string key = "";
        if (ep.keyText.text.Length < 250)
        {
            key = GetIv(256);
            ep.keyText.text = key;
        }
        else
        {
            key = ep.keyText.text;
        }

        ep.outText.text = AESEncrypt(ep.inText.text, key);
        Debug.Log(key);
    }

    public static void Decryption()
    {
        string key = ep.keyText.text;
        Debug.Log(key);
        ep.outText.text = AESDecrypt(ep.inText.text, key);
    }

    public static void Clear()
    {
        ep.inText.text = "";
        ep.keyText.text = "";
        ep.outText.text = "";
    }

    //定义默认密钥
    private static byte[] _aesKeyByte = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
    private static string _aesKeyStr = Encoding.UTF8.GetString(_aesKeyByte);

    /// <summary>
    /// 随机生成密钥，默认密钥长度为32，不足在加密时自动填充空格
    /// </summary>
    /// <param name="n">密钥长度</param>
    /// <returns></returns>
    public static string GetIv(int n)
    {
        string s = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char[] arrChar = new char[s.Length];
        for (int i = 0; i < s.Length; i++)
        {
            arrChar[i] = Convert.ToChar(s.Substring(i, 1));
        }
        StringBuilder num = new StringBuilder();
        System.Random rnd = new System.Random(DateTime.Now.Millisecond);
        for (int i = 0; i < n; i++)
        {
            num.Append(arrChar[rnd.Next(0, arrChar.Length)].ToString());
        }
        _aesKeyByte = Encoding.UTF8.GetBytes(num.ToString());
        return _aesKeyStr = Encoding.UTF8.GetString(_aesKeyByte);
    }


    /// <summary>  
    /// AES加密(无向量)  
    /// </summary>  
    /// <param name="plainBytes">被加密的明文</param>  
    /// <param name="key">密钥</param>  
    /// <returns>密文</returns>  
    public static string AESEncrypt(String Data, String Key)
    {
        MemoryStream mStream = new MemoryStream();
        RijndaelManaged aes = new RijndaelManaged();

        byte[] plainBytes = Encoding.UTF8.GetBytes(Data);
        Byte[] bKey = new Byte[32];
        Array.Copy(Encoding.UTF8.GetBytes(Key.PadRight(bKey.Length)), bKey, bKey.Length);

        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        aes.KeySize = 128;
        //aes.Key = _key;  
        aes.Key = bKey;
        //aes.IV = _iV;  
        CryptoStream cryptoStream = new CryptoStream(mStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        try
        {
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
            cryptoStream.FlushFinalBlock();
            return Convert.ToBase64String(mStream.ToArray());
        }
        finally
        {
            cryptoStream.Close();
            mStream.Close();
            aes.Clear();
        }
    }


    /// <summary>  
    /// AES解密(无向量)  
    /// </summary>  
    /// <param name="encryptedBytes">被加密的明文</param>  
    /// <param name="key">密钥</param>  
    /// <returns>明文</returns>  
    public static string AESDecrypt(String Data, String Key)
    {
        Byte[] encryptedBytes = Convert.FromBase64String(Data);
        Byte[] bKey = new Byte[32];
        Array.Copy(Encoding.UTF8.GetBytes(Key.PadRight(bKey.Length)), bKey, bKey.Length);

        MemoryStream mStream = new MemoryStream(encryptedBytes);
        //mStream.Write( encryptedBytes, 0, encryptedBytes.Length );  
        //mStream.Seek( 0, SeekOrigin.Begin );  
        RijndaelManaged aes = new RijndaelManaged();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        aes.KeySize = 128;
        aes.Key = bKey;
        //aes.IV = _iV;  
        CryptoStream cryptoStream = new CryptoStream(mStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
        try
        {
            byte[] tmp = new byte[encryptedBytes.Length + 32];
            int len = cryptoStream.Read(tmp, 0, encryptedBytes.Length + 32);
            byte[] ret = new byte[len];
            Array.Copy(tmp, 0, ret, 0, len);
            return Encoding.UTF8.GetString(ret);
        }
        finally
        {
            cryptoStream.Close();
            mStream.Close();
            aes.Clear();
        }
    }

}




