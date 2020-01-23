package org.bonitasoft.securitycar;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpSession;

import org.bonitasoft.console.common.server.utils.SessionUtil;
import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.identity.UserUpdater;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.log.event.BEvent;
import org.bonitasoft.log.event.BEvent.Level;
import org.bonitasoft.log.event.BEventFactory;
import org.bonitasoft.properties.BonitaProperties;
import org.bonitasoft.securitycar.SecurityCarAPI.SecurityParameter;
import org.bonitasoft.securitycar.SecurityCarAPI.SecurityStatus;
import org.bonitasoft.securitycar.UsersCustomInfo.TentativeStatus;
import org.bonitasoft.securitycar.listener.SecurityCarListenerSession;

/**
 * Tower Control is used to keep track of all needed information. It is the
 * basis of the Filter and Listener. In order to let the page run as maximum as
 * possible, the tower keep only information relative to the theft and
 * connection.
 * 
 *
 */
public class TowerControl {

	private static Logger logger = Logger.getLogger(SecurityCarListenerSession.class.getName());
	public String logHeader = "--------------------- TowerControl SecurityCar ";

	SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

	private static TowerControl towerControl = new TowerControl();

	private static BEvent EventNotDeployed = new BEvent(TowerControl.class.getName(), 1, Level.ERROR, "Listener not deployed", "The listener is not deployed, not possible to disconnect the user", "user will not be disconnected", "Install the listener");
	// private static BEvent EventException = new BEvent(TowerControl.class.getName(), 2, Level.APPLICATIONERROR, "Exception during execution", "The execution failed", "No result", "Check the exception");
	private static BEvent EventUserDisconnected = new BEvent(TowerControl.class.getName(), 3, Level.SUCCESS, "User Disconnected", "The user is disconnected");
	private static BEvent EventUserNotDisconnected = new BEvent(TowerControl.class.getName(), 4, Level.APPLICATIONERROR, "User not Disconnected", "The user is not disconnected, because no user connection is found", "", "Refresh the screen");
	private static BEvent EventCantDisableUser = new BEvent(TowerControl.class.getName(), 5, Level.APPLICATIONERROR, "Can't disable user", "The user has too many tentative, and should be disable. An error arrive", "User is not disabled", "Check the error");
	private static BEvent EventParametersSaved = new BEvent(TowerControl.class.getName(), 6, Level.SUCCESS, "Parameters saved", "Parameters saved");

	/**
	 * theftTimeLine. Key is the time line 10mn per 10 mn , example 201802031600
	 * / 201802031610 / 201802031620 / ...
	 */
	private LinkedHashMap<String, Map<String, Object>> theftTimeLine = new LinkedHashMap<String, Map<String, Object>>();
	private int limitTimeLine = 6 * 48; // 48 H
	/**
	 * kept the log of the theft. Key is the ipaddress+username. We use the
	 * linked in order to kept max 50 entry in the list
	 */
	private LinkedHashMap<String, Map<String, Object>> theftLog = new LinkedHashMap<String, Map<String, Object>>();
	private int limitTheftLog = 50;

	/**
	 * keep track of the listener : we will ask it who is connected
	 */
	private SecurityCarListenerSession mSecurityCarListenerSession;

	private TowerControl() {

	}

	public static TowerControl getInstance() {
		return towerControl;
	}

	/**
	 * register the listener
	 * 
	 * @param listener
	 */
	public void registerListener(SecurityCarListenerSession listener) {
		mSecurityCarListenerSession = listener;
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* getInformation */
	/*                                                                      */
	/*	                                                                    */
	/* ******************************************************************** */

	/**
	 * return the list of users connected
	 * 
	 * @param identityAPI
	 * @return
	 */
	public List<Long> getListCurrentUserConnected(int startIndex, int maxResults, IdentityAPI identityAPI) {

		logger.info(logHeader + ".getListCurrentUserConnected : startIndex[" + startIndex + "] maxResult[" + maxResults + "]");

		if (mSecurityCarListenerSession == null) {
			logger.info(logHeader + ".getListCurrentUserConnected : listener not deployed");
			return null;
		}
		List<Long> listUsersConnected = new ArrayList<Long>();

		for (HttpSession httpSession : mSecurityCarListenerSession.getListSession().values()) {
			APISession apiSession = (APISession) httpSession.getAttribute(SessionUtil.API_SESSION_PARAM_KEY);
			if (apiSession != null) {
				listUsersConnected.add(apiSession.getUserId());

			}
		}
		return listUsersConnected;

	}

	/**
	 * disconnect a user
	 * @param userId
	 * @param identityAPI
	 * @return
	 */
	public List<BEvent> disconnect(long userId, IdentityAPI identityAPI) {
		List<BEvent> listEvents = new ArrayList<BEvent>();
		if (mSecurityCarListenerSession == null) {
			logger.info(logHeader + ".getListCurrentUserConnected : listener not deployed");
			listEvents.add(EventNotDeployed);
			return listEvents;
		}

		for (HttpSession httpSession : mSecurityCarListenerSession.getListSession().values()) {
			APISession apiSession = (APISession) httpSession.getAttribute(SessionUtil.API_SESSION_PARAM_KEY);
			if (apiSession != null && apiSession.getUserId() == userId) {
				{
					// disconnect : just remove the API Session
					httpSession.setAttribute(SessionUtil.API_SESSION_PARAM_KEY, null);
					listEvents.add(EventUserDisconnected);
					return listEvents;
				}
			}
		}

		listEvents.add(EventUserNotDisconnected);
		return listEvents;

	}

	/**
	 * register a logging tentative.
	 * 
	 * @param userName
	 * @param sourceIpAddress
	 * @param correct
	 * @param identityAPI
	 * @return
	 */
	public List<BEvent> addOneTentative(long tenantId, String userName, String sourceIpAddress, boolean correct, IdentityAPI identityAPI) {
		List<BEvent> listEvents = new ArrayList<BEvent>();
		
		UsersCustomInfo userCustomInfo = UsersCustomInfo.getInstance();
		TentativeStatus tentativeStatus = userCustomInfo.addOneTentative(userName, sourceIpAddress, correct, identityAPI);

		// if the tentative is not correct, then keep it in memory. In order to
		// be small, we kept two kind of information:
		// * in a timeLine, the number of tentative
		// * in the teft log, the sourceIpAddress + userName + number of
		// tentative
		if (!correct) {
			synchronized (this) {
				// record in the time slot
				Map<String, Object> timeSlot = getTimeSlot(theftTimeLine);
				timeSlot.put("n", timeSlot.get("n") == null ? 1 : ((Integer) timeSlot.get("n")) + 1);
				log(theftTimeLine);

				// register in the theftLog
				String keyLog = sourceIpAddress + "#" + userName;
				Map<String, Object> logItem = theftLog.get(keyLog);
				if (logItem == null) {
					logItem = new HashMap<String, Object>();
					theftLog.put(keyLog, logItem);
					limitSize(theftLog, limitTheftLog);
				}
				logItem.put("t", System.currentTimeMillis());
				logItem.put("n", logItem.get("n") == null ? 1 : ((Integer) logItem.get("n")) + 1);
				logItem.put("ip", sourceIpAddress);
				logItem.put("u", userName);
			}
			
			// do we have to block the user ? 
			if (paramDaysPasswordActif==null || System.currentTimeMillis() - paramLastTimeLoad > 1000*60*5)
			{
				listEvents.addAll( loadParameters( tenantId ));
			}
			if (! BEventFactory.isError(listEvents))
			{
				if (tentativeStatus.userId!=null && tentativeStatus.nbTentative >= paramMaxOfTentatives)
				{
					logger.info(logHeader+" Too Many tentatives("+tentativeStatus.nbTentative+") when max=" +paramMaxOfTentatives+" for["+userName+"] userId["+tentativeStatus.userId+"]");
					
					// invalidate the user
					UserUpdater userUpdater = new UserUpdater();
					userUpdater.setEnabled( false );
					try {
						identityAPI.updateUser(tentativeStatus.userId, userUpdater);
					}
					catch( Exception e)
					{
						logger.severe(logHeader+" Can't disable the user["+userName+"] userId["+tentativeStatus.userId+"] error:"+e.toString());
						listEvents.add(new BEvent( EventCantDisableUser, e, "User["+userName+"] userId["+tentativeStatus.userId+"]"));
					}
				}
			}
			log(theftLog);

		}

		return listEvents;

	}

	/* ******************************************************************** */
	/*                                                                      */
	/* getTheftInformation */
	/*                                                                      */
	/*	                                                                    */
	/* ******************************************************************** */

	public Map<String, Map<String, Object>> getTheftTimeLine() {
		return theftTimeLine;
	}

	public Map<String, Map<String, Object>> getTheftLog() {
		return theftLog;
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* parameters */
	/*                                                                      */
	/* ******************************************************************** */
	private static String ParamDaysPasswordActif = "DaysPasswordActif";
	private static String ParamMaxOfTentatives = "maxOfTentatives";

	public Integer paramDaysPasswordActif = 0;
	public Integer paramMaxOfTentatives = 3;
	/**
	 * in order to not reload at each call the param, we kept the last time the load was done, and we reload only after X minutes
	 */
	public long paramLastTimeLoad;
 
	/**
	 * loadParameters
	 * 
	 * @param tenantId
	 * @param securityStatus
	 */
	public List<BEvent> loadParameters(long tenantId) {
		List<BEvent> listEvents = new ArrayList<BEvent>();
		BonitaProperties bonitaProperties = new BonitaProperties(UsersCustomInfo.PROPERTIESNAME, tenantId);

		listEvents.addAll(bonitaProperties.load());

		String dayPasswordActifSt = bonitaProperties.getProperty(ParamDaysPasswordActif, "0");
		paramDaysPasswordActif = dayPasswordActifSt == null ? 0 : Integer.valueOf(dayPasswordActifSt);

		String maxOfTentativesSt = bonitaProperties.getProperty(ParamMaxOfTentatives, "3");
		paramMaxOfTentatives = maxOfTentativesSt == null ? 6 : Integer.valueOf(maxOfTentativesSt);
		paramLastTimeLoad= System.currentTimeMillis();
		
		return listEvents;
	}

	/**
	 * 
	 * @param tenantId
	 * @param securityParameter
	 * @param securityStatus
	 */
	public SecurityStatus saveParameters(SecurityParameter securityParameter) {
		SecurityStatus securityStatus = new SecurityStatus();
		BonitaProperties bonitaProperties = new BonitaProperties(UsersCustomInfo.PROPERTIESNAME, securityParameter.tenantId);

		securityStatus.listEvents.addAll(bonitaProperties.load());

		logger.info( logHeader+",Save passwordActif["+securityParameter.paramDaysPasswordActif+"] nbTentatives["+securityParameter.paramMaxOfTentatives+"]" );
		bonitaProperties.setProperty(ParamDaysPasswordActif, String.valueOf(securityParameter.paramDaysPasswordActif));
		bonitaProperties.setProperty(ParamMaxOfTentatives, String.valueOf(securityParameter.paramMaxOfTentatives));

		securityStatus.listEvents.addAll(bonitaProperties.store());
		 if (! BEventFactory.isError(securityStatus.listEvents) )
		 {
			 securityStatus.listEvents.add(EventParametersSaved);
		 }
		return securityStatus;
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* private information */
	/*                                                                      */
	/*	                                                                    */
	/* ******************************************************************** */

	/**
	 * get a time slot
	 * 
	 * @param timeLine
	 * @return
	 */
	private Map<String, Object> getTimeSlot(Map<String, Map<String, Object>> timeLine) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHH");
		String key = sdf.format(new Date());
		int mn = (int) ((System.currentTimeMillis() / (1000 * 60)) % 60);
		mn = (mn / 10); // now it's 0,1,2,3,4,5
		key += mn + "0";
		Map<String, Object> timeSlot = timeLine.get(key);
		if (timeSlot != null)
			return timeSlot;
		timeSlot = new HashMap<String, Object>();
		timeLine.put(key, timeSlot);
		limitSize(timeLine, limitTimeLine);
		return timeSlot;
	}

	/**
	 * remove the first element of the map
	 * 
	 * @param mapToLimit
	 * @param limit
	 */
	private void limitSize(Map<String, Map<String, Object>> mapToLimit, int limit) {
		// if the size is more than limit, purge the first record
		while (mapToLimit.size() > limit) {
			String firstRecord = mapToLimit.keySet().iterator().next();
			mapToLimit.remove(firstRecord);
		}
	}

	/**
	 * log the map which are supposed ordered
	 * 
	 * @param mapToLog
	 */
	private void log(Map<String, Map<String, Object>> mapToLog) {
		logger.info(logHeader + " ---------------- ");

		for (String key : mapToLog.keySet()) {
			logger.info(logHeader + " " + key + " - " + mapToLog.toString());
		}
		logger.info(logHeader + " ---------------- ");
	}
}
