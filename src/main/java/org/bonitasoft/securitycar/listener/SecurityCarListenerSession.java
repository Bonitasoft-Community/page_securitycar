package org.bonitasoft.securitycar.listener;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.bonitasoft.console.common.server.utils.SessionUtil;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.engine.session.Session;
import org.bonitasoft.securitycar.SecurityCarAPI;
import org.bonitasoft.securitycar.TowerControl;

/**
 * Add the session listener in the web?xml <!-- security car --> <listener>
 * <listener-class>org.bonitasoft.securitycar.listener.SecurityCarListenerSession</listener-class>
 * </listener>
 *
 * 
 */
public class SecurityCarListenerSession implements HttpSessionListener {
	private static Logger logger = Logger.getLogger(SecurityCarListenerSession.class.getName());
	public String logHeader = "--------------------- Listener SecurityCar ";

	public Map<String, HttpSession> mListSession = new HashMap<String, HttpSession>();

	public SecurityCarListenerSession() {
		TowerControl towerControl = TowerControl.getInstance();
		towerControl.registerListener(this);
	}

	/**
	 * implement the interface
	 */
	public void sessionDestroyed(HttpSessionEvent se) {
		logger.info(logHeader + "Session Destroy [" + se.getSession().getId() + "]");
		mListSession.remove(se.getSession().getId());

	}

	public void sessionCreated(HttpSessionEvent se) {
		logger.info(logHeader + "Session Created [" + se.getSession().getId() + "]");
		mListSession.put(se.getSession().getId(), se.getSession());

	}

	/**
	 * return the list of session currently monitoring
	 * 
	 * @return
	 */
	public Map<String, HttpSession> getListSession() {
		return mListSession;
	}

}
