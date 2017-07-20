using HtmlAgilityPack;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using Windows.Web.Http;

namespace AuthenticationComponent
{
	public sealed class NAMResponse
	{
		public Uri ActionUri { get; set; }
		public string SAMLRequest { get; set; }

		public string SAMLResponse { get; set; }

		public string RelayState { get; set; }

		public string Cookies { get; set; }

		public NAMResponse()
		{
			// empty constructor, used when authenticating directly with the NAM.
		}

		public NAMResponse(HttpResponseMessage responseMessage)
		{
			// extract the form POST URL, SAMLRequest (or SAMLResponse) and RelayState
			try
			{
				string cookieHeader;
				responseMessage.Headers.TryGetValue("Set-Cookie", out cookieHeader);

				this.Cookies = cookieHeader;

			} catch (Exception ex)
			{
				Debug.WriteLine("Error getting cookies from request: " + ex.Message);
			}

			var contentTask = responseMessage.Content.ReadAsInputStreamAsync().AsTask();
			contentTask.Wait();

			var htmlDocument = new HtmlDocument();
			htmlDocument.Load(contentTask.Result.AsStreamForRead());

			var formAction = from form in htmlDocument.DocumentNode.Descendants("form")
							 select form.ChildAttributes("action").FirstOrDefault();
			var actionUri = new Uri(formAction.FirstOrDefault().Value);

			var hiddenInputs = from input in htmlDocument.DocumentNode.Descendants("input")
							   select input;

			this.ActionUri = actionUri;

			foreach (var input in hiddenInputs)
			{
				if (input.GetAttributeValue("name", "").Equals("SAMLRequest"))
				{
					this.SAMLRequest = WebUtility.HtmlDecode(input.GetAttributeValue("value", ""));
				}
				else if (input.GetAttributeValue("name", "").Equals("SAMLResponse"))
				{
					this.SAMLResponse = WebUtility.HtmlDecode(input.GetAttributeValue("value", ""));
				}
				else if (input.GetAttributeValue("name", "").Equals("RelayState"))
				{
					this.RelayState = WebUtility.HtmlDecode(input.GetAttributeValue("value", ""));
				}
			}
		}
	}
}
