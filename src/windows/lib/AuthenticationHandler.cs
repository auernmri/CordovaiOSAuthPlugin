using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.Web;
using Windows.Web.Http;
using Windows.Web.Http.Filters;

namespace AuthenticationComponent
{
	public sealed class AuthenticationHandler
	{
		static string SESSION_TIMESTAMP_KEY = "SessionTimeStamp";

		/// <summary>
		/// Tries to perform a SAML authentication with the NAM gateway.
		/// </summary>
		/// <param name="samlRequest">The base64-encoded SAML request that gets passed through to the NAM</param>
		/// <param name="idpUrlString">The URL of the identity provider (receives the SAML request)</param>
		/// <returns>A base64-encoded SAML response, as received from the NAM</returns>
		public static NAMResponse Authenticate(string samlRequest, string idpUrlString)
		{
			var handler = new AuthenticationHandler();

			if ((samlRequest != null && idpUrlString != null)
				&& (samlRequest != "null" && idpUrlString != "null"))
			{
				var loginUri = new Uri(idpUrlString, UriKind.Absolute);
				return handler.LoginWithCertificateAndSAMLRequest(loginUri, samlRequest);
			}
			else
			{
				return handler.LoginDirectlyWithCertificateOnly();
			}
		}

		public static bool ValidateSession(string sessionCookieName, int sessionTime)
		{
			// compare the stored session timestamp with the current time
			var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
			var currentTime = DateTime.Now;

			if (!localSettings.Values.Keys.Contains(SESSION_TIMESTAMP_KEY))
			{
				// session not started yet, create the timestamp
				localSettings.Values[SESSION_TIMESTAMP_KEY] = currentTime.ToString();
				return false;
			}

			var storedSessionTimestamp = Convert.ToDateTime(localSettings.Values[SESSION_TIMESTAMP_KEY]);

			if (storedSessionTimestamp.AddMinutes(sessionTime).CompareTo(currentTime) < 0)
			{
				// session timed out, update timestamp
				localSettings.Values[SESSION_TIMESTAMP_KEY] = currentTime.ToString();
				return false;
			}
			else
			{
				// session still valid
				return true;
			}
		}

		public static bool ResetSessionTimestamp(int graceTime)
		{
			// compare the stored session timestamp with the current time
			var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
			var currentTime = DateTime.Now.AddMinutes(-graceTime);

			// set the new timestamp, adjusted by the gracetime
			localSettings.Values[SESSION_TIMESTAMP_KEY] = currentTime.ToString();

			return true;
		}

		private NAMResponse LoginWithCertificateAndSAMLRequest(Uri loginUri, string samlRequest)
		{
			var certificate = GetDeviceCertificate();

			Debug.WriteLine("Certificate found, verifying access to private key...");
			var verifyResult = VerifyCertificateKeyAccess(certificate);

			if (verifyResult)
			{
				Debug.WriteLine("Access granted, creating HttpClient...");
				HttpBaseProtocolFilter httpFilter = new HttpBaseProtocolFilter();
				httpFilter.ClientCertificate = certificate;

				// try login
				HttpClient httpClient = new HttpClient(httpFilter);

				try
				{
					Debug.WriteLine("Sending SAML request to NAM...");
					var uriBuilder = new UriBuilder(loginUri);
					if (samlRequest != null)
					{
						uriBuilder.Query = "SAMLRequest=" + WebUtility.UrlEncode(samlRequest);
					}

					var ssoResponseTask = httpClient.GetAsync(uriBuilder.Uri).AsTask();
					ssoResponseTask.Wait();
					var ssoResponse = ssoResponseTask.Result;
					ssoResponse.EnsureSuccessStatusCode();

					// follow the Javascript redirect
					Debug.WriteLine("Received response, trying to extract redirect URI from javascript");
					var redirectUri = ExtractJavaScriptRedirectUri(ssoResponse, loginUri);
					Debug.WriteLine("Requesting SAML response from: " + redirectUri.ToString());
					var redirectResponseTask = httpClient.GetAsync(redirectUri).AsTask();
					redirectResponseTask.Wait();
					var redirectResponse = redirectResponseTask.Result;
					redirectResponse.EnsureSuccessStatusCode();

					// read the SAMLResponse
					Debug.WriteLine("Received response from NAM, extracting SAMLResponse...");
					NAMResponse namResponse = new NAMResponse(redirectResponse);

					Debug.WriteLine("Returning SAML Response: " + namResponse.SAMLResponse);

					string cookieHeader;
					ssoResponse.Headers.TryGetValue("Set-Cookie", out cookieHeader);
					namResponse.Cookies = cookieHeader;

					Debug.WriteLine("And Cookies: " + namResponse.Cookies);

					// update the session timestamp
					var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
					localSettings.Values[SESSION_TIMESTAMP_KEY] = DateTime.Now.ToString();

					return namResponse;
				}
				catch (FormatException formatException)
				{
					Debug.WriteLine("Uri extraction error: " + formatException.Message);

					return null;
				}
				catch (Exception ex)
				{
					Debug.WriteLine("Connection error...");
					Debug.WriteLine("Exception during NAM communication: " + ex.Message);

					var exceptionDetail = WebError.GetStatus(ex.GetBaseException().HResult);
					Debug.WriteLine("Exception Detail: " + exceptionDetail);

					return null;
				}
			}

			return null;
		}

		private NAMResponse LoginDirectlyWithCertificateOnly()
		{
			var certificate = GetDeviceCertificate();

			Debug.WriteLine("Certificate found, verifying access to private key...");
			var verifyResult = VerifyCertificateKeyAccess(certificate);

			if (verifyResult)
			{
				Debug.WriteLine("Access granted, creating HttpClient...");
				HttpBaseProtocolFilter httpFilter = new HttpBaseProtocolFilter();
				httpFilter.ClientCertificate = certificate;

				// try login
				HttpClient httpClient = new HttpClient(httpFilter);

				try
				{
					Debug.WriteLine("Authenticating directly with NAM...");
					var loginUri = new Uri("https://login.schaeffler.com/nidp/app/login?id=Smartcard");

					var ssoResponseTask = httpClient.GetAsync(loginUri).AsTask();
					ssoResponseTask.Wait();
					var ssoResponse = ssoResponseTask.Result;
					ssoResponse.EnsureSuccessStatusCode();

					// follow the Javascript redirect
					Debug.WriteLine("Received response, trying to extract redirect URI from javascript");
					var redirectUri = ExtractJavaScriptRedirectUri(ssoResponse, loginUri);
					Debug.WriteLine("Requesting SAML response from: " + redirectUri.ToString());
					var redirectResponseTask = httpClient.GetAsync(redirectUri).AsTask();
					redirectResponseTask.Wait();
					var redirectResponse = redirectResponseTask.Result;
					redirectResponse.EnsureSuccessStatusCode();

					// create an empty Response object, since the NAM won't send a SAMLResponse when authenticating directly
					NAMResponse namResponse = new NAMResponse();
					namResponse.SAMLResponse = "";
					string cookieHeader;
					ssoResponse.Headers.TryGetValue("Set-Cookie", out cookieHeader);
					namResponse.Cookies = cookieHeader;

					Debug.WriteLine("Cookies: " + namResponse.Cookies);

					// update the session timestamp
					var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
					localSettings.Values[SESSION_TIMESTAMP_KEY] = DateTime.Now.ToString();

					return namResponse;
				}
				catch (FormatException formatException)
				{
					Debug.WriteLine("Uri extraction error: " + formatException.Message);

					return null;
				}
				catch (Exception ex)
				{
					Debug.WriteLine("Connection error...");
					Debug.WriteLine("Exception during NAM communication: " + ex.Message);

					var exceptionDetail = WebError.GetStatus(ex.GetBaseException().HResult);
					Debug.WriteLine("Exception Detail: " + exceptionDetail);

					return null;
				}
			}

			return null;
		}

		private Uri ExtractJavaScriptRedirectUri(HttpResponseMessage responseMessage, Uri baseUri)
		{
			var contentTask = responseMessage.Content.ReadAsStringAsync().AsTask();
			contentTask.Wait();
			var content = contentTask.Result;
			var redirectRegex = new Regex("href='(.*)'");
			var redirectValue = redirectRegex.Match(content).Groups[1].Value;

			if (redirectValue.StartsWith("http"))
			{
				// treat it as an absolute URI
				return new Uri(redirectValue, UriKind.Absolute);
			}
			else
			{
				// relative uri
				return new Uri(baseUri, redirectValue);
			}
		}

		/// <summary>
		/// Queries the device certificates and tries to retrieve one suitable for authenticating with the NAM.
		/// 
		/// Will look for issuer "Schaeffler Group Sub CA01" (for newer devices) or just "Schaeffler*" (for older devices)
		/// </summary>
		/// <returns>A certificate suitable for NAM authentication.</returns>
		private Certificate GetDeviceCertificate()
		{
			// get certificate by issuer name
			Debug.WriteLine("Finding certificates...");
			var certificateTask = CertificateStores.FindAllAsync().AsTask();
			certificateTask.Wait();

			// get certificates (with private keys) issued by Schaeffler, prefer newer ones
			var possibleCertificates = from cert in certificateTask.Result
									   where cert.HasPrivateKey && (cert.Issuer == "Schaeffler Group Sub CA01" || cert.Issuer.StartsWith("Schaeffler"))
									   orderby cert.ValidFrom
									   select cert;

			var certificate = possibleCertificates.FirstOrDefault();
			return certificate;
		}

		/// <summary>
		/// Tries to sign and verify a bit of test data using the given certificate.
		/// This will cause the security subsystem to grant the calling app access 
		/// to the certificate's private key for the current session.
		/// 
		/// </summary>
		/// <param name="selectedCertificate">The X.509 Certificate for which access is required</param>
		/// <returns>True on successful signing and verification, false otherwise.</returns>
		private static bool VerifyCertificateKeyAccess(Certificate selectedCertificate)
		{
			bool VerifyResult = false;  // default to access failure
			var keyPairTask = PersistedKeyProvider.OpenKeyPairFromCertificateAsync(
												selectedCertificate, HashAlgorithmNames.Sha1,
												CryptographicPadding.RsaPkcs1V15).AsTask();
			keyPairTask.Wait();
			CryptographicKey keyPair = keyPairTask.Result;
			String buffer = "Data to sign";
			IBuffer Data = CryptographicBuffer.ConvertStringToBinary(buffer, BinaryStringEncoding.Utf16BE);

			try
			{
				// sign the data by using the key
				var signedDataTask = CryptographicEngine.SignAsync(keyPair, Data).AsTask();
				signedDataTask.Wait();
				IBuffer Signed = signedDataTask.Result;
				VerifyResult = CryptographicEngine.VerifySignature(keyPair, Data, Signed);
			}
			catch (Exception exp)
			{
				Debug.WriteLine("Verification Failed. Exception Occurred : {0}", exp.Message);
				// default result is false so drop through to exit.
			}

			return VerifyResult;
		}
	}
}
