package com.example.openid;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class NimbusdsOpenId {

	private static final Logger LOG = LoggerFactory.getLogger(NimbusdsOpenId.class);

	private static final int CONNECT_TIMEOUT_MILLIS = 5000;
	private static final int READ_TIMEOUT_MILLIS = 5000;
	private static final String CALLBACK = "/security_check";
	private static final String SESSION_ATTR_CLAIMSET = "claimset";

	private final String issuerUri;
	private final String clientId;
	private final String clientSecret;

	// TODO replace with signed JWTs with short expire times.
	private final Set<String> states = new HashSet<>();
	private final Map<String, URI> callbackUris = new HashMap<>();  // TODO not need this - put in state?

	private OIDCProviderMetadata opMetadata;

	public NimbusdsOpenId(final String issuerUri, final String clientId, final String clientSecret) {
		this.issuerUri = issuerUri;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		if (this.issuerUri == null || this.clientId == null || this.clientSecret == null) {
			throw new IllegalArgumentException("ERROR: OIDC_ISSUER_URI, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET environment variables must be set.");
		}
	}

	public void addToHandler(final ServletContextHandler handler) {
		handler.addServlet(new ServletHolder(new CallbackServlet()), CALLBACK);
	}

	private static URI makeCallbackUri(final HttpServletRequest req) throws ServletException {
		final String path = joinPaths(req.getServletPath(), req.getContextPath(), CALLBACK);
		try {
			return new URI(req.getScheme(), null, req.getServerName(), req.getServerPort(), path, null, null);
		}
		catch (final URISyntaxException e) {
			throw new ServletException(e);
		}
	}

	private static String joinPaths(final String... parts) {
		String ret = "";
		for (final String p : parts) {
			if (p.length() < 1 || p.equals("/")) continue;
			if (!p.startsWith("/")) ret += "/";
			if (p.endsWith("/")) {
				ret += p.substring(0, p.length() - 1);
			}
			else {
				ret += p;
			}
		}
		return ret;
	}

	public void startAuthFlow(final HttpServletRequest req, final HttpServletResponse resp) throws IOException, ServletException, GeneralException {
		final Issuer issuer = new Issuer(this.issuerUri);
		this.opMetadata = OIDCProviderMetadata.resolve(issuer, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS);

		final URI callbackUri = makeCallbackUri(req);
		System.out.println(callbackUri);
		final State state = new State();
		final Nonce nonce = new Nonce();

		this.states.add(state.getValue());
		this.callbackUris.put(state.getValue(), callbackUri);

		final AuthenticationRequest request = new AuthenticationRequest.Builder(
				ResponseType.CODE,
				Scope.parse("openid email profile"),
				new ClientID(this.clientId),
				callbackUri)
						.state(state)
						.nonce(nonce)
						.endpointURI(this.opMetadata.getAuthorizationEndpointURI())
						.build();

		final URI authRequestURI = request.toURI();
		LOG.info("redirecting to: {}", authRequestURI);
		resp.sendRedirect(authRequestURI.toString());
	}

	@SuppressWarnings("serial")
	public class CallbackServlet extends HttpServlet {
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			final ClientID clientID = new ClientID(NimbusdsOpenId.this.clientId);

			final URI requestURI = URI.create(req.getRequestURL().toString() + "?" + req.getQueryString());
			final AuthenticationResponse authResp;
			try {
				authResp = AuthenticationResponseParser.parse(requestURI);
			}
			catch (final ParseException e) {
				throw new ServletException(e);
			}

			final State state = authResp.getState();
			if (!NimbusdsOpenId.this.states.contains(state.getValue())) {
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state.");
				return;
			}

			if (!authResp.indicatesSuccess()) {
				final AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authResp;
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication error: " + errorResponse.getErrorObject().toJSONObject());
				return;
			}

			final URI callbackUri = NimbusdsOpenId.this.callbackUris.get(state.getValue());

			final AuthenticationSuccessResponse success = (AuthenticationSuccessResponse) authResp;
			final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, new Secret(NimbusdsOpenId.this.clientSecret));
			final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(success.getAuthorizationCode(), callbackUri);
			final TokenRequest request = new TokenRequest.Builder(NimbusdsOpenId.this.opMetadata.getTokenEndpointURI(), clientAuth, codeGrant).build();

			final TokenResponse tokenResponse;
			try {
				tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
			}
			catch (final ParseException e) {
				throw new ServletException(e);
			}

			if (!tokenResponse.indicatesSuccess()) {
				final TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Token error: " + errorResponse.getErrorObject().toJSONObject());
				return;
			}

			final OIDCTokenResponse tokenSuccessResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
			LOG.info("tokenSuccessResponse: {}", tokenSuccessResponse.toJSONObject());

			final JWT idToken = tokenSuccessResponse.getOIDCTokens().getIDToken();
			LOG.info("idToken: {}", idToken);

			LOG.info("JWKSetURI: {}", NimbusdsOpenId.this.opMetadata.getJWKSetURI());
			final ResourceRetriever retriever = new DefaultResourceRetriever(
					CONNECT_TIMEOUT_MILLIS,
					READ_TIMEOUT_MILLIS,
					1024 * 1024 // size limit in bytes
			);
			final JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
					.create(NimbusdsOpenId.this.opMetadata.getJWKSetURI().toURL(), retriever)
					.cache(true)
					.retrying(true)
					.build();

			final List<JWSAlgorithm> algs = NimbusdsOpenId.this.opMetadata.getIDTokenJWSAlgs();
			final JWSAlgorithm jwsAlgorithm = algs.contains(JWSAlgorithm.RS256) ? JWSAlgorithm.RS256 : algs.get(0);
			final JWSKeySelector<SecurityContext> jwsSelector = new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);

			final IDTokenValidator validator = new IDTokenValidator(NimbusdsOpenId.this.opMetadata.getIssuer(), clientID, jwsSelector, null);
			final IDTokenClaimsSet claimsSet;
			try {
				claimsSet = validator.validate(idToken, null);
			}
			catch (BadJOSEException | JOSEException e) {
				throw new ServletException(e);
			}
			LOG.info("idTokenClaimsSet: {}", claimsSet.toJSONString());

			final AccessToken accessToken = tokenSuccessResponse.getOIDCTokens().getAccessToken();
			LOG.info("accessToken: {}", accessToken);

			final RefreshToken refreshToken = tokenSuccessResponse.getOIDCTokens().getRefreshToken();
			LOG.info("refreshToken: {}", refreshToken);

			final HttpSession session = req.getSession(true);
			session.setAttribute(SESSION_ATTR_CLAIMSET, claimsSet);

			// userinfo on needed if required info was not included in the JWT claims above.
			final UserInfo userInfo = fetchUserInfo(accessToken, resp);
			if (userInfo == null) return;
			LOG.info("userInfo: {}", userInfo);

			resp.sendRedirect("/");
		}
	}

	private UserInfo fetchUserInfo(final AccessToken accessToken, final HttpServletResponse resp) throws IOException, ServletException {
		final HTTPResponse httpResponse = new UserInfoRequest(this.opMetadata.getUserInfoEndpointURI(), accessToken)
				.toHTTPRequest()
				.send();
		UserInfoResponse userInfoResponse;
		try {
			userInfoResponse = UserInfoResponse.parse(httpResponse);
		}
		catch (final ParseException e) {
			throw new ServletException(e);
		}
		if (!userInfoResponse.indicatesSuccess()) {
			final UserInfoErrorResponse errorResponse = userInfoResponse.toErrorResponse();
			resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Userinfo error: " + errorResponse.getErrorObject().toJSONObject());
			return null;
		}
		return userInfoResponse.toSuccessResponse().getUserInfo();
	}

	public IDTokenClaimsSet getClaimSet(final HttpServletRequest req) {
		final HttpSession session = req.getSession(false);
		if (session == null) return null;
		return (IDTokenClaimsSet) session.getAttribute(SESSION_ATTR_CLAIMSET);
	}

}
