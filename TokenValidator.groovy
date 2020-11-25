import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenValidator {

    private static final String API_TOKEN_SESSION_ATTR = "api_token";
    private static final String CSRF_TOKEN_HEADER = "X-Bonita-API-Token";

    /**
     * Logger
     */
    private static final def LOGGER = Logger.getLogger(TokenValidator.class.getName());

    public static boolean checkCSRFToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        //Get CSRF token from request in 'X-Bonita-API-Token' header
        def headerFromRequest = httpRequest.getHeader(CSRF_TOKEN_HEADER);
        def apiToken = httpRequest.getSession().getAttribute(API_TOKEN_SESSION_ATTR);
    		if (apiToken != null) {
            if (headerFromRequest == null || !headerFromRequest.equals(apiToken)) {
                if (LOGGER.isLoggable(Level.FINE)) {
                    LOGGER.log(Level.FINE, "Token Validation failed, expected: " + apiToken + ", received: " + headerFromRequest);
                }
                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return false;
    	      } else {
                if (LOGGER.isLoggable(Level.FINE)) {
                    LOGGER.log(Level.FINE, "Token Validation succeeded");
                }
            }
        } else {
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.log(Level.FINE, "Token Validation is not active. No CSRF token in session.");
            }
        }
        return true;
    }
}
