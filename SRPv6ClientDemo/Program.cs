using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace SRPv6ClientDemo
{
	class Program
	{
		/// <summary>
		/// Системная константа N, указанная в документации к УПШ.
		/// </summary>
		private const string N = "0115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";

		/// <summary>
		/// Системная константа g, указанная в документации к УПШ.
		/// </summary>
		private const string G = "02";
		
		/// <summary>
		/// Перегрузка SRP-клиента с реализацией методов расчёта в соответствии с документацией к УПШ.
		/// </summary>
		private static readonly SberSrp6Client _sberSrp6Client;

		/// <summary>
		/// Алгоритм шифрования SHA1.
		/// </summary>
		private static readonly SHA1 _sha1;

		/// <summary>
		/// Инициализация данных.
		/// </summary>
		static Program()
		{
			_sha1 = SHA1.Create();
			_sberSrp6Client = new SberSrp6Client();
			_sberSrp6Client.Init(
				new BigInteger(N, 16),
				new BigInteger(G, 16),
				new Sha1Digest(),
				new SecureRandom());
		}

		/// <summary>
		/// Основной блок.
		/// </summary>
		static void Main()
		{
			// arrange
			InputData input;
			using (var fileStream = new FileStream("Data.xml", FileMode.Open))
			{
				var serializer = new XmlSerializer(typeof(InputData));
				input = (InputData)serializer.Deserialize(fileStream);
			}

			// act
			var result = ComputeSrpClientValues(input);

			// assert
			var key = BitConverter.ToString(result[0]);
			var a = BitConverter.ToString(result[1]);

			a = a.Replace("-", string.Empty);
			key = key.Replace("-", string.Empty);

			Console.WriteLine($"Calculated key is\n{key}");
			Console.WriteLine($"Calculated A is\n{a}");

			Console.ReadLine();
		}

		/// <summary>
		/// Вычисление клиентских значений SRP.
		/// </summary>
		/// <param name="input">Входные параметры.</param>
		/// <returns>Полученные значения.</returns>
		private static byte[][] ComputeSrpClientValues(InputData input)
		{
			var i = Encoding.UTF8.GetBytes(input.Login);
			var p = Encoding.UTF8.GetBytes(input.Password);
			var a = _sberSrp6Client.GenerateClientCredentials(input.Salt, i, p).ToByteArray();
			var s = _sberSrp6Client.CalculateSecret(new BigInteger(input.B));
			var unhashedBytes = CutEmptyBytes(s.ToByteArray());
			var key = _sha1.ComputeHash(unhashedBytes);

			return new[]
			{
				key,
				CutEmptyBytes(a),
			};
		}

		/// <summary>
		/// Удаление нулевых байт в начале вектора.
		/// </summary>
		/// <param name="source">Исходный вектор.</param>
		/// <returns>Вектор без нулевых байт в начале.</returns>
		private static byte[] CutEmptyBytes(byte[] source)
		{
			var index = 0;
			while (source[index] == 0x00)
			{
				index++;
			}

			if (index == 0)
			{
				return source;
			}

			var lenght = source.Length - index;
			var result = new byte[lenght];
			Array.Copy(source, index, result, 0, lenght);

			return result;
		}
	}
}
