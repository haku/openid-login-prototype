// src/main/java/com/example/jetty/EmbeddedJettyOidcApp.java

package com.example.openid;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
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

public class Main {

	private static final String HOST = "awoo";
	private static final int PORT = 8080;
	private static final String CALLBACK = "/security_check";

	private static final int CONNECT_TIMEOUT_MILLIS = 5000;
	private static final int READ_TIMEOUT_MILLIS = 5000;

	private static final Logger LOG = LoggerFactory.getLogger(Main.class);

	public static void main(final String[] args) throws Exception {
		new Main().run();
	}

	private final String issuerUri;
	private final String clientId;
	private final String clientSecret;
	private final URI callbackUri = URI.create("http://" + HOST + ":" + PORT + CALLBACK);

	public Main() {
		this.issuerUri = System.getenv("OIDC_ISSUER_URI");
		this.clientId = System.getenv("OIDC_CLIENT_ID");
		this.clientSecret = System.getenv("OIDC_CLIENT_SECRET");

		if (this.issuerUri == null || this.clientId == null || this.clientSecret == null) {
			System.err.println("ERROR: OIDC_ISSUER_URI, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET environment variables must be set.");
			System.exit(1);
		}
	}

	@SuppressWarnings("resource")
	private void run() throws Exception {
		final Server server = new Server();

		final ServerConnector connector = new ServerConnector(server);
		connector.setPort(PORT);
		connector.setHost(HOST);
		server.addConnector(connector);

		final ServletContextHandler servletHandler = new ServletContextHandler();
		servletHandler.setContextPath("/");
		servletHandler.addServlet(new ServletHolder(new HelloServlet()), "/");
		servletHandler.addServlet(new ServletHolder(new CallbackServlet()), CALLBACK);

		server.setHandler(servletHandler);
		RequestLoggingFilter.addTo(servletHandler);

		server.start();
		server.join();
	}

	// TODO replace with signed JWTs with short expire times.
	private final Set<String> states = new HashSet<>();

	private OIDCProviderMetadata opMetadata;

	public void startAuthFlow(final HttpServletRequest req, final HttpServletResponse resp) throws IOException, ServletException, GeneralException {
		final Issuer issuer = new Issuer(this.issuerUri);
		this.opMetadata = OIDCProviderMetadata.resolve(issuer, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS);

		final State state = new State();
		final Nonce nonce = new Nonce();

		this.states.add(state.getValue());

		final AuthenticationRequest request = new AuthenticationRequest.Builder(
				ResponseType.CODE,
				Scope.parse("openid email profile"),
				new ClientID(this.clientId),
				this.callbackUri)
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
			final ClientID clientID = new ClientID(Main.this.clientId);

			final URI requestURI = URI.create(req.getRequestURL().toString() + "?" + req.getQueryString());
			final AuthenticationResponse authResp;
			try {
				authResp = AuthenticationResponseParser.parse(requestURI);
			}
			catch (final ParseException e) {
				throw new ServletException(e);
			}

			final State state = authResp.getState();
			if (!Main.this.states.contains(state.getValue())) {
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state.");
				return;
			}

			if (!authResp.indicatesSuccess()) {
				final AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authResp;
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication error: " + errorResponse.getErrorObject().toJSONObject());
				return;
			}

			final AuthenticationSuccessResponse success = (AuthenticationSuccessResponse) authResp;
			final ClientAuthentication clientAuth = new ClientSecretBasic(clientID, new Secret(Main.this.clientSecret));
			final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(success.getAuthorizationCode(), Main.this.callbackUri);
			final TokenRequest request = new TokenRequest.Builder(Main.this.opMetadata.getTokenEndpointURI(), clientAuth, codeGrant).build();

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

			LOG.info("JWKSetURI: {}", Main.this.opMetadata.getJWKSetURI());
			final ResourceRetriever retriever = new DefaultResourceRetriever(
					CONNECT_TIMEOUT_MILLIS,
					READ_TIMEOUT_MILLIS,
					1024 * 1024 // size limit in bytes
			);
			final JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
					.create(Main.this.opMetadata.getJWKSetURI().toURL(), retriever)
					.cache(true)
					.retrying(true)
					.build();

			final List<JWSAlgorithm> algs = Main.this.opMetadata.getIDTokenJWSAlgs();
			final JWSAlgorithm jwsAlgorithm = algs.contains(JWSAlgorithm.RS256) ? JWSAlgorithm.RS256 : algs.get(0);
			final JWSKeySelector<SecurityContext> jwsSelector = new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);

			final IDTokenValidator validator = new IDTokenValidator(Main.this.opMetadata.getIssuer(), clientID, jwsSelector, null);
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

			// TODO now do your own session management lol.  or use the jetty one?

			// userinfo on needed if required info was not included in the JWT claims above.
			final HTTPResponse httpResponse = new UserInfoRequest(Main.this.opMetadata.getUserInfoEndpointURI(), accessToken)
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
				return;
			}
			final UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
			LOG.info("userInfo: {}", userInfo);
		}
	}

	@SuppressWarnings("serial")
	public class HelloServlet extends HttpServlet {
		@SuppressWarnings({ "resource" })
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			if ("login".equals(req.getParameter("action"))) {
				try {
					startAuthFlow(req, resp);
				}
				catch (final GeneralException e) {
					throw new ServletException(e);
				}
				return;
			}

			resp.setContentType("text/html");
			final PrintWriter w = resp.getWriter();
			w.println("<h1>Root</h1>");

			final Principal userPrincipal = req.getUserPrincipal();
			final String username = userPrincipal != null ? userPrincipal.getName() : null;
			w.println("<p>username: " + username + "</p>");

			if (username == null) {
				w.println("<p><a href=\"?action=login\">Login</a></p>");
			}
			else {
				w.println("<p><a href=\"/logout\">Logout " + username + "</a></p>");
			}
		}
	}

}
