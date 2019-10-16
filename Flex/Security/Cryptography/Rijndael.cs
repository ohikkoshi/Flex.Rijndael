using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Flex.Security.Cryptography
{
	public class Rijndael
	{
		readonly ICryptoTransform encoder;
		readonly ICryptoTransform decoder;


		private Rijndael()
		{
		}

		public Rijndael(string password, int bit = 128)
		{
			Debug.Assert(!string.IsNullOrEmpty(password));

			var crypt = new RijndaelManaged();
			crypt.KeySize = bit;
			crypt.BlockSize = bit;

			byte[] utf8 = Encoding.UTF8.GetBytes(password);
			byte[] key = ToArray(ref utf8, crypt.Key.Length);
			byte[] iv = ToArray(ref utf8, crypt.IV.Length);

			encoder = crypt.CreateEncryptor(key, iv);
			decoder = crypt.CreateDecryptor(key, iv);
		}

		byte[] ToArray(ref byte[] array, int size)
		{
			var buff = new byte[size];

			foreach (int i in Enumerable.Range(0, array.Length)) {
				buff[i % size] ^= array[i];
			}

			return buff;
		}

		public string Encode(string str)
		{
			byte[] utf8 = Encoding.UTF8.GetBytes(str);

			using (var ms = new MemoryStream())
			using (var cs = new CryptoStream(ms, encoder, CryptoStreamMode.Write))
			{
				cs.Write(utf8, 0, utf8.Length);
				cs.FlushFinalBlock();

				return Convert.ToBase64String(ms.ToArray());
			}
		}

		public string Decode(string str)
		{
			byte[] base64 = Convert.FromBase64String(str);

			using (var ms = new MemoryStream(base64))
			using (var cs = new CryptoStream(ms, decoder, CryptoStreamMode.Read))
			using (var stream = new StreamReader(cs, Encoding.UTF8))
			{
				return stream.ReadToEnd();
			}
		}
	}
}