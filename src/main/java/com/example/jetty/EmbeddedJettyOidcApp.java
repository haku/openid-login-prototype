// src/main/java/com/example/jetty/EmbeddedJettyOidcApp.java

package com.example.jetty;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.openid.OpenIdAuthenticator;
import org.eclipse.jetty.security.openid.OpenIdConfiguration;
import org.eclipse.jetty.security.openid.OpenIdLoginService;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;

// https://github.com/jetty/jetty.project/blob/62f6d02253eb937550da88934a633f692dc57c87/documentation/jetty/modules/code/examples/src/main/java/org/eclipse/jetty/docs/programming/security/OpenIdDocs.java

public class EmbeddedJettyOidcApp {

	@SuppressWarnings("resource")
	public static void main(final String[] args) throws Exception {
		final int port = 8080;
		final Server server = new Server();
		final ServerConnector connector = new ServerConnector(server);
		connector.setPort(port);
		connector.setHost("100.115.92.201");
		server.addConnector(connector);

		final String issuerUri = System.getenv("OIDC_ISSUER_URI"); // e.g., "https://accounts.google.com" or
																	// "https://dev-xxxxxx.okta.com/oauth2/default"
		final String clientId = System.getenv("OIDC_CLIENT_ID"); // Your client ID
		final String clientSecret = System.getenv("OIDC_CLIENT_SECRET"); // Your client secret

		if (issuerUri == null || clientId == null || clientSecret == null) {
			System.err.println("ERROR: OIDC_ISSUER_URI, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET environment variables must be set.");
			System.err.println("Example for Google: OIDC_ISSUER_URI=https://accounts.google.com");
			System.err.println("Make sure your OIDC provider's redirect URI is configured to: http://" + connector.getHost() + ":" + port
					+ "/j_security_check");
			System.exit(1);
		}

		final OpenIdConfiguration openIdConfig = new OpenIdConfiguration(issuerUri, clientId, clientSecret);
		openIdConfig.addScopes("email", "profile");
		openIdConfig.setAuthenticateNewUsers(false);
		// openIdConfig.setErrorPage("/error");
		// openIdConfig.setLogoutRedirectPage("/logout-success");

		final OpenIdLoginService loginService = new OpenIdLoginService(openIdConfig);
		loginService.setIdentityService(new DefaultIdentityService());

		final OpenIdAuthenticator authenticator = new OpenIdAuthenticator(openIdConfig); // TODO configure /j_security_check

		final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
		securityHandler.setLoginService(loginService);
		securityHandler.setAuthenticator(authenticator);
		securityHandler.setRealmName(issuerUri);

		final Constraint constraint = new Constraint();
		constraint.setName("auth");
		constraint.setAuthenticate(true);
		constraint.setRoles(new String[] { "**" }); // Any authenticated user (any role)

		final ConstraintMapping mapping = new ConstraintMapping();
		mapping.setPathSpec("/protected/*");
		mapping.setConstraint(constraint);
		securityHandler.addConstraintMapping(mapping);

		final SessionHandler sessionHandler = new SessionHandler();
		sessionHandler.setHandler(securityHandler);

		final ServletContextHandler servletHandler = new ServletContextHandler(sessionHandler, "/", ServletContextHandler.SESSIONS);
		servletHandler.setContextPath("/");
		servletHandler.setSecurityHandler(securityHandler);
		servletHandler.addServlet(new ServletHolder(new HelloServlet()), "/hello");
		servletHandler.addServlet(new ServletHolder(new ProtectedServlet()), "/protected/hello");

		server.insertHandler(securityHandler);
		server.setHandler(servletHandler);
		server.start();
		server.join();
	}

	@SuppressWarnings("serial")
	public static class HelloServlet extends HttpServlet {
		@SuppressWarnings("resource")
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			resp.setContentType("text/html");
			resp.getWriter().println("<h1>Hello from Public Servlet!</h1>");
			resp.getWriter().println("<p><a href=\"/protected/hello\">Go to Protected Page</a></p>");
		}
	}

	@SuppressWarnings("serial")
	public static class ProtectedServlet extends HttpServlet {
		@SuppressWarnings({ "resource", "unchecked" })
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			resp.setContentType("text/html");
			final PrintWriter w = resp.getWriter();
			w.println("<h1>Hello from Protected Servlet!</h1>");

			final Principal userPrincipal = req.getUserPrincipal();
			if (userPrincipal != null) {
				w.println("<p>Authenticated User: " + userPrincipal.getName() + "</p>");

				final HttpSession session = req.getSession(false);
				if (session != null) {
					final Map<String, ?> claims = (Map<String, ?>) session.getAttribute(OpenIdAuthenticator.CLAIMS);
					for (Entry<String, ?> i : claims.entrySet()) {
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
				w.println("<p>User is not authenticated (this should not happen if accessed via /protected/)</p>");
			}
			w.println("<p><a href=\"/\">Go to Public Page</a></p>");
			// Note: Jetty's OIDC module handles logout via /j_security_check?action=logout
			w.println("<p><a href=\"/j_security_check?action=logout\">Logout</a></p>");
		}
	}
}
