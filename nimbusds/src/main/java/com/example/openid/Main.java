// src/main/java/com/example/jetty/EmbeddedJettyOidcApp.java

package com.example.openid;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.SessionTrackingMode;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.http.HttpCookie.SameSite;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

public class Main {

	private static final int PORT = 8080;

	private NimbusdsOpenId openId;

	public static void main(final String[] args) throws Exception {
		new Main().run();
	}

	@SuppressWarnings("resource")
	private void run() throws Exception {
		this.openId = new NimbusdsOpenId(
				System.getenv("OIDC_ISSUER_URI"),
				System.getenv("OIDC_CLIENT_ID"),
				System.getenv("OIDC_CLIENT_SECRET"));

		final Server server = new Server();

		final ServerConnector connector = new ServerConnector(server);
		connector.setPort(PORT);
		server.addConnector(connector);

		final SessionHandler sessionHandler = new SessionHandler();
		sessionHandler.setSessionTrackingModes(EnumSet.of(SessionTrackingMode.COOKIE));
		sessionHandler.getSessionCookieConfig().setName("MY_AUTH_COOKIE");
		sessionHandler.getSessionCookieConfig().setHttpOnly(true);
		sessionHandler.getSessionCookieConfig().setComment(HttpCookie.getCommentWithAttributes("", true, SameSite.LAX, false));
		sessionHandler.setRefreshCookieAge((int) TimeUnit.HOURS.toSeconds(1));
		sessionHandler.getSessionCookieConfig().setMaxAge((int) TimeUnit.HOURS.toSeconds(2));
		sessionHandler.setMaxInactiveInterval((int) TimeUnit.HOURS.toSeconds(2));

		final ServletContextHandler servletHandler = new ServletContextHandler();
		servletHandler.setContextPath("/");
		servletHandler.setSessionHandler(sessionHandler);
		this.openId.addToHandler(servletHandler);
		servletHandler.addServlet(new ServletHolder(new HelloServlet()), "/");

		server.setHandler(servletHandler);
		RequestLoggingFilter.addTo(servletHandler);

		server.start();
		server.join();
	}



	@SuppressWarnings("serial")
	public class HelloServlet extends HttpServlet {
		@SuppressWarnings({ "resource" })
		@Override
		protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
			if ("login".equals(req.getParameter("action"))) {
				try {
					Main.this.openId.startAuthFlow(req, resp);
				}
				catch (final GeneralException e) {
					throw new ServletException(e);
				}
				return;
			}

			resp.setContentType("text/html");
			final PrintWriter w = resp.getWriter();
			w.println("<h1>Root</h1>");

			final IDTokenClaimsSet claimset = Main.this.openId.getClaimSet(req);

			// TODO move this.
			final HttpSession sesson = req.getSession(false);
			final String sessionId = sesson != null ? sesson.getId() : null;
			final Subject subject = claimset != null ? claimset.getSubject() : null;
			final String username = subject != null ? subject.getValue() : null;

			w.println("<p>session: " + sessionId + "</p>");
			w.println("<p>username: " + username + "</p>");
			w.println("<p>claimset: " + claimset + "</p>");

			if (username == null) {
				w.println("<p><a href=\"?action=login\">Login</a></p>");
			}
			else {
				w.println("<p><a href=\"/logout\">Logout " + username + "</a></p>");
			}
		}
	}

}
