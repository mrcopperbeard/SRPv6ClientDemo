using System;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Math;

namespace SRPv6ClientDemo
{
	/// <summary>
	/// Переопределение методов для подсчёта SRPv6 ключей для клиента.
	/// </summary>
	public class SberSrp6Client : Srp6Client
	{
		/// <summary>
		/// Переопределение расчёта секретного ключа.
		/// </summary>
		/// <param name="serverB">Серверное значение B.</param>
		/// <returns>Секретный ключ.</returns>
		public override BigInteger CalculateSecret(BigInteger serverB)
		{
			B = Srp6Utilities.ValidatePublicValue(N, serverB);
			u = Srp6Utilities.CalculateU(digest, N, pubA, B);
			S = CalculateS();

			return S;
		}

		/// <summary>
		/// Переопределение расчёта ключа S.
		/// </summary>
		/// <returns>Значение S.</returns>
		private BigInteger CalculateS()
		{
			var k = Srp6Utilities.CalculateK(digest, N, g);
			var baseValue = B.Subtract(g.ModPow(x, N).Multiply(k));
			if (baseValue.SignValue >= 0)
			{
				baseValue = k.Multiply(N).Add(baseValue);
			}

			return baseValue.ModPow(u.Multiply(x).Add(privA), N);
		}
	}
}
