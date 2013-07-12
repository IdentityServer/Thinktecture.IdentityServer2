namespace SimpleHttpClient
{
    using Microsoft.ServiceBus;
    //-----------------------------------------------------------------------------
    // Copyright (c) Microsoft Corporation.  All rights reserved.
    //-----------------------------------------------------------------------------

    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.Threading;
    using System.Web;


    sealed public class StaticSimpleWebTokenProvider : TokenProvider
    {
        readonly string rawToken;
        readonly DateTime expiresIn;

        public StaticSimpleWebTokenProvider(string rawToken)
            : base(false, true)
        {
            this.rawToken = rawToken;
            this.expiresIn = ExtractExpiresIn(rawToken);
        }

        protected override IAsyncResult OnBeginGetToken(string appliesTo, string action, TimeSpan timeout, AsyncCallback callback, object state)
        {
            SimpleWebSecurityToken token = new SimpleWebSecurityToken(this.rawToken, this.expiresIn);
            return new CompletedAsyncResult<SimpleWebSecurityToken>(token, callback, state);
        }

        protected override IAsyncResult OnBeginGetWebToken(string appliesTo, string action, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return OnBeginGetToken(appliesTo, action, timeout, callback, state);
        }

        protected override SecurityToken OnEndGetToken(IAsyncResult ar, out DateTime cacheUntil)
        {
            SimpleWebSecurityToken token = CompletedAsyncResult<SimpleWebSecurityToken>.End(ar);
            cacheUntil = token.ValidTo;
            return token;
        }

        protected override string OnEndGetWebToken(IAsyncResult ar, out DateTime cacheUntil)
        {
            SimpleWebSecurityToken token = CompletedAsyncResult<SimpleWebSecurityToken>.End(ar);
            cacheUntil = token.ValidTo;
            return string.Format(CultureInfo.InvariantCulture, "{0} {1}=\"{2}\"", TokenConstants.WrapAuthenticationType, TokenConstants.WrapAuthorizationHeaderKey, token.Token);
        }

        class CompletedAsyncResult<T> : IAsyncResult
        {
            WaitHandle asyncWaitHandle;
            AsyncCallback callback;
            object state;
            T result;

            public CompletedAsyncResult(T result, AsyncCallback callback, object state)
            {
                asyncWaitHandle = new ManualResetEvent(true);
                this.callback = callback;
                this.state = state;
                this.result = result;

                if (this.callback != null)
                {
                    this.callback(this);
                }
            }

            public object AsyncState { get { return this.state; } }

            public WaitHandle AsyncWaitHandle { get { return this.asyncWaitHandle; } }

            public bool CompletedSynchronously { get { return true; } }

            public bool IsCompleted { get { return true; } }

            public static T End(IAsyncResult ar)
            {
                return ((CompletedAsyncResult<T>)ar).result;
            }
        }

        static DateTime ExtractExpiresIn(string simpleWebToken)
        {
            DateTime expiration = DateTime.MinValue;

            if (string.IsNullOrWhiteSpace(simpleWebToken))
            {
                throw new ArgumentException("Null, empty, or whitespace", "simpleWebToken");
            }

            IDictionary<string, string> decodedToken = Decode(simpleWebToken);
            string expiresOn = decodedToken[TokenConstants.TokenExpiresOn];

            if (string.IsNullOrEmpty(expiresOn))
            {
                throw new ArgumentException("Token is missing expiration");
            }

            expiration = TokenConstants.WrapBaseTime + TimeSpan.FromSeconds(double.Parse(HttpUtility.UrlDecode(expiresOn.Trim()), CultureInfo.InvariantCulture));

            return expiration;
        }

        static IDictionary<string, string> Decode(string encodedString)
        {
            IDictionary<string, string> dictionary = new Dictionary<string, string>();
            if (!string.IsNullOrWhiteSpace(encodedString))
            {
                IEnumerable<string> valueEncodedPairs = encodedString.Split(new char[] { TokenConstants.UrlParameterSeparator }, StringSplitOptions.None);
                foreach (string valueEncodedPair in valueEncodedPairs)
                {
                    string[] pair = valueEncodedPair.Split(new char[] { TokenConstants.KeyValueSeparator }, StringSplitOptions.None);
                    if (pair.Length != 2)
                    {
                        throw new FormatException("Invalid encoding");
                    }

                    dictionary.Add(HttpUtility.UrlDecode(pair[0]), HttpUtility.UrlDecode(pair[1]));
                }
            }

            return dictionary;
        }
    }
}