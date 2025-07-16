// src/main/java/com/example/jetty/EmbeddedJettyOidcApp.java

package com.example.jetty;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.SessionTrackingMode;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.HttpCookie.SameSite;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.openid.OpenIdAuthenticator;
import org.eclipse.jetty.security.openid.OpenIdConfiguration;
import org.eclipse.jetty.security.openid.OpenIdLoginService;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

// https://github.com/jetty/jetty.project/blob/62f6d02253eb937550da88934a633f692dc57c87/documentation/jetty/modules/code/examples/src/main/java/org/eclipse/jetty/docs/programming/security/OpenIdDocs.java

public class EmbeddedJettyOidcApp {

	@SuppressWarnings("resource")
	public static void main(final String[] args) throws Exception {
		final int port = 8080;
		final Server server = new Server();
		final ServerConnector connector = new ServerConnector(server);
		connector.setPort(port);
		connector.setHost("127.0.0.1");
		server.addConnector(connector);

		final String issuerUri = System.getenv("OIDC_ISSUER_URI");
		final String clientId = System.getenv("OIDC_CLIENT_ID");
		final String clientSecret = System.getenv("OIDC_CLIENT_SECRET");

		if (issuerUri == null || clientId == null || clientSecret == null) {
			System.err.println("ERROR: OIDC_ISSUER_URI, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET environment variables must be set.");
			System.exit(1);
		}

		final OpenIdConfiguration openIdConfig = new OpenIdConfiguration(issuerUri, clientId, clientSecret);
		openIdConfig.addScopes("email", "profile");
		openIdConfig.setLogoutWhenIdTokenIsExpired(true);
		openIdConfig.setAuthenticateNewUsers(false);

		final OpenIdLoginService loginService = new OpenIdLoginService(openIdConfig);
		loginService.setIdentityService(new DefaultIdentityService());

		final OpenIdAuthenticator authenticator = new OpenIdAuthenticator(openIdConfig); // TODO configure /j_security_check

		final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
		securityHandler.setLoginService(loginService);
		securityHandler.setAuthenticator(authenticator);
		securityHandler.setRealmName(issuerUri);

		final SessionHandler sessionHandler = new SessionHandler();
		sessionHandler.setSessionTrackingModes(EnumSet.of(SessionTrackingMode.COOKIE));
		sessionHandler.getSessionCookieConfig().setName("MY_AUTH_COOKIE");
		sessionHandler.getSessionCookieConfig().setHttpOnly(true);
		sessionHandler.getSessionCookieConfig().setComment(HttpCookie.getCommentWithAttributes("", true, SameSite.LAX, false));
		sessionHandler.setRefreshCookieAge((int) TimeUnit.HOURS.toSeconds(1));
		sessionHandler.getSessionCookieConfig().setMaxAge((int) TimeUnit.HOURS.toSeconds(2));
		sessionHandler.setMaxInactiveInterval((int) TimeUnit.HOURS.toSeconds(2));
		sessionHandler.setHandler(securityHandler);

		final ServletContextHandler servletHandler = new ServletContextHandler();
		servletHandler.setContextPath("/");
		servletHandler.setSessionHandler(sessionHandler);
		servletHandler.setSecurityHandler(securityHandler);
		servletHandler.addServlet(new ServletHolder(new HelloServlet()), "/");
		servletHandler.addServlet(new ServletHolder(new LogoutServlet()), "/logout");
		servletHandler.addServlet(new ServletHolder(new InfoServlet()), "/info");

		server.setHandler(servletHandler);
		RequestLoggingFilter.addTo(servletHandler);

		server.start();
		server.join();
	}

	/**
	 * This is to work around an issue where org.eclipse.jetty.server.Request.authenticate()
	 * always throws ServletException even when everything is working fine,
	 * because it does not know about org.eclipse.jetty.server.Authentication.Challenge.
	 */
	public static void startAuthFlow(final HttpServletRequest req, final HttpServletResponse resp) throws IOException, ServletException {
		final Request jreq = (Request) req;
		final Authentication auth = jreq.getAuthentication();
		if (auth == null) throw new IllegalStateException("auth system is not configured.");
		if (!(auth instanceof Authentication.Deferred)) throw new IllegalStateException("auth was not correct class: " + auth.getClass());
		final Authentication newAuth = ((Authentication.Deferred) auth).authenticate(req, resp);
		jreq.setAuthentication(newAuth);

		if (!(newAuth instanceof Authentication.Challenge)) {
			// If got this far but did not return a challenge, then something is broken in the openid config.
			resp.sendError(HttpStatus.INTERNAL_SERVER_ERROR_500);
			return;
		}
	}

	@SuppressWarnings("serial")
	public static class HelloServlet extends HttpServlet {
		@SuppressWarnings({ "resource" })
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			if ("login".equals(req.getParameter("action"))) {
				startAuthFlow(req, resp);
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

	@SuppressWarnings("serial")
	public static class LogoutServlet extends HttpServlet {
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			req.logout();
		}
	}

	@SuppressWarnings("serial")
	public static class InfoServlet extends HttpServlet {
		@SuppressWarnings({ "resource", "unchecked" })
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			resp.setContentType("text/html");
			final PrintWriter w = resp.getWriter();

			final Principal userPrincipal = req.getUserPrincipal();
			if (userPrincipal != null) {
				w.println("<p>Authenticated User: " + userPrincipal.getName() + "</p>");

				final HttpSession session = req.getSession(false);
				if (session != null) {
					final Map<String, ?> claims = (Map<String, ?>) session.getAttribute(OpenIdAuthenticator.CLAIMS);
					for (final Entry<String, ?> i : claims.entrySet()) {
						Object value = i.getValue();
						if (value instanceof Object[]) value = Arrays.toString((Object[]) value);
						w.println("<p>" + i.getKey() + " = " + value + "</p>");
					}

					final Iterator<String> names = session.getAttributeNames().asIterator();
					while (names.hasNext()) {
						final String name = names.next();
						w.println("<p>Attr: " + name + " = " + session.getAttribute(name) + "</p>");
					}
				}

			}
			else {
				w.println("<p>User is not authenticated.</p>");
			}
		}
	}
}
