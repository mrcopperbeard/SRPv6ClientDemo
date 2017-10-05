using System;
using System.Xml.Serialization;

namespace SRPv6ClientDemo
{
	/// <summary>
	/// Модель с входными данными.
	/// </summary>
	public class InputData
	{
		/// <summary>
		/// Логин пользователя.
		/// </summary>
		[XmlElement]
		public string Login { get; set; }

		/// <summary>
		/// Пароль пользователя.
		/// </summary>
		[XmlElement]
		public string Password { get; set; }

		/// <summary>
		/// Соль, получаемая с сервера.
		/// </summary>
		[XmlElement]
		public byte[] Salt { get; set; }

		/// <summary>
		/// Параметр В, получаемый с сервера.
		/// </summary>
		[XmlElement]
		public byte[] B { get; set; }
	}
}
