using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Flex.Security.Cryptography
{
	public sealed class Rijndael
	{
		readonly ICryptoTransform encoder;
		readonly ICryptoTransform decoder;


		/// <summary>
		/// 
		/// </summary>
		/// <value></value>
		Rijndael() { }

		/// <summary>
		/// 
		/// </summary>
		/// <param name="password"></param>
		/// <param name="bit"></param>
		public Rijndael(string password, int bit = 128)
		{
			var crypt = new RijndaelManaged();
			crypt.KeySize = bit;
			crypt.BlockSize = bit;

			var utf8 = Encoding.UTF8.GetBytes(password);
			var key = ToArray(ref utf8, crypt.Key.Length);
			var iv = ToArray(ref utf8, crypt.IV.Length);
			encoder = crypt.CreateEncryptor(key, iv);
			decoder = crypt.CreateDecryptor(key, iv);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="array"></param>
		/// <param name="size"></param>
		/// <returns></returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		byte[] ToArray(ref byte[] array, int size)
		{
			var buff = new byte[size];

			foreach (int i in Enumerable.Range(0, array.Length)) {
				buff[i % size] ^= array[i];
			}

			return buff;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="str"></param>
		/// <returns></returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public string Encode(string str)
		{
			var utf8 = Encoding.UTF8.GetBytes(str);

			using (var ms = new MemoryStream())
			using (var cs = new CryptoStream(ms, encoder, CryptoStreamMode.Write)) {
				cs.Write(utf8, 0, utf8.Length);
				cs.FlushFinalBlock();

				return System.Convert.ToBase64String(ms.ToArray());
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="str"></param>
		/// <returns></returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public string Decode(string str)
		{
			var base64 = System.Convert.FromBase64String(str);

			using (var ms = new MemoryStream(base64))
			using (var cs = new CryptoStream(ms, decoder, CryptoStreamMode.Read))
			using (var stream = new StreamReader(cs, Encoding.UTF8)) {
				return stream.ReadToEnd();
			}
		}
	}
}
