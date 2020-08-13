package org.bonitasoft.securitycar.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.bonitasoft.console.common.server.login.HttpServletRequestAccessor;
import org.bonitasoft.engine.api.ApiAccessType;
import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.api.LoginAPI;
import org.bonitasoft.engine.api.TenantAPIAccessor;
import org.bonitasoft.engine.connector.ConnectorAPIAccessorImpl;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.engine.util.APITypeManager;
import org.bonitasoft.log.event.BEvent;
import org.bonitasoft.securitycar.engine.TowerControl;

/**
 * <!-- security car --> <filter> <filter-name>SecurityCarFilter</filter-name>
 * <filter-class>org.bonitasoft.securitycar.filter.SecurityCarFilterConnect</filter-class>
 * <init-param> <param-name>usernamereport</param-name>
 * <param-value>jan.fisher</param-value> </init-param> <init-param>
 * <param-name>userpasswordreport</param-name> <param-value>bpm</param-value>
 * </init-param> </filter>
 * 
 * <filter-mapping> <filter-name>SecurityCarFilter</filter-name>
 * <url-pattern>/loginservice</url-pattern> </filter-mapping>
 *
 * 
 */
public class SecurityCarFilter implements Filter {

	public Logger logger = Logger.getLogger(SecurityCarFilter.class.getName());
	public String logHeader = "--------------------- filter SecurityCar ";

	public String userNameReport = "";
	public String userPasswortReport = "";

	public void init(final FilterConfig filterConfig) throws ServletException {
		userNameReport = filterConfig.getInitParameter("usernamereport");
		userPasswortReport = filterConfig.getInitParameter("userpasswordreport");

	}

	/**
	 * Filter, then study if we are connected. If not, that's a false
	 * connection. Yes, reset the number of tentative to 0.
	 */
	public void doFilter(final ServletRequest request, final ServletResponse servletResponse, final FilterChain chain) throws IOException, ServletException {
		// final HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
		final HttpServletRequest httpRequest = (HttpServletRequest) request;

		Butler butler = Butler.getInstance();
		
		if ( ! butler.watchDog(this, httpRequest))
		    return;
		
		logger.info(logHeader + "Before URL=[" + httpRequest.getRequestURI() + "]");
		long timeBefore = System.currentTimeMillis();
		chain.doFilter(httpRequest, servletResponse);
	    long timeAfter = System.currentTimeMillis();

	    butler.registerOneHttpCall(timeAfter - timeBefore, httpRequest);
	    
		// is this is a login URL ? 
		if (! httpRequest.getRequestURI().startsWith("/bonita/loginservice"))
		    return;
		
		logger.info(logHeader + "After URL=[" + httpRequest.getRequestURI() + "]");
		int tenantId;
		try
		{
			tenantId = Integer.parseInt( httpRequest.getParameter("tenant"));
		}
		catch( Exception e)
		{
			tenantId=1;
		}
		
		
		final HttpServletRequestAccessor requestAccessor = new HttpServletRequestAccessor(httpRequest);
		if (requestAccessor != null) {
			final APISession apiSession = requestAccessor.getApiSession();
			if (apiSession != null) {
				logger.info(logHeader + "Connected");
				try {
					final IdentityAPI identityAPI = TenantAPIAccessor.getIdentityAPI(apiSession);

					User user = identityAPI.getUser(apiSession.getUserId());
					butler.addOneTentative(tenantId, user.getUserName(), httpRequest, true, identityAPI);
				} catch (Exception e) {
					logger.severe(logHeader + "user from id[" + apiSession.getUserId() + "] not found");
				}
				return;
			}

		}
		String userName = request.getParameter("username");

		logger.info(logHeader + "Connection refused username[" + userName + "]");

		// two possibility : wrong password or user does not exist.
		// So, we need to connect to check the userId. Use the technical user
		// given in parameters to check that

		final Map<String, String> map = new HashMap<>();
		APITypeManager.setAPITypeAndParams(ApiAccessType.LOCAL, map);

		try {
            ConnectorAPIAccessorImpl apiAccessor = new ConnectorAPIAccessorImpl(tenantId);
            final IdentityAPI identityAPI = apiAccessor.getIdentityAPI();

			// final LoginAPI loginAPI = TenantAPIAccessor.getLoginAPI();

			// log in to the tenant to create a session
			// final APISession apiSession = loginAPI.login(userNameReport, userPasswortReport);
			// set the session in the TomcatSession
            // final IdentityAPI identityAPI = TenantAPIAccessor.getIdentityAPI(apiSession);
			butler.addOneTentative(tenantId, userName, httpRequest, false, identityAPI);
			

		} catch (Exception e) {
			logger.info(logHeader + "Error during reporting[" + e.toString() + "]");

		}

		return;
	}

	public void destroy() {

	}

}
