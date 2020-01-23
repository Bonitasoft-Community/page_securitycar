package org.bonitasoft.securitycar;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.lang3.RandomStringUtils;
import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.exception.UpdateException;
import org.bonitasoft.engine.identity.CustomUserInfoValue;
import org.bonitasoft.engine.identity.CustomUserInfoValueSearchDescriptor;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserNotFoundException;
import org.bonitasoft.engine.identity.UserSearchDescriptor;
import org.bonitasoft.engine.identity.UserUpdater;
import org.bonitasoft.engine.search.Order;
import org.bonitasoft.engine.search.SearchOptionsBuilder;
import org.bonitasoft.engine.search.SearchResult;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.googlegraph.GraphGenerator;
import org.bonitasoft.googlegraph.GraphGenerator.GraphRange;
import org.bonitasoft.log.event.BEvent;
import org.bonitasoft.log.event.BEvent.Level;
import org.bonitasoft.log.event.BEventFactory;
import org.bonitasoft.securitycar.UsersCustomInfo.TentativeStatus;
import org.json.simple.JSONValue;

public class SecurityCarAPI {

	private static Logger logger = Logger.getLogger(SecurityCarAPI.class.getName());
	public String logHeader = "--------------------- SecurityCarAPI ";

	// private static BEvent EventNotDeployed = new BEvent(SecurityCarAPI.class.getName(), 1, Level.ERROR, "Command not deployed", "The command is not deployed");
	private static BEvent EventUserNotFound = new BEvent(SecurityCarAPI.class.getName(), 2, Level.APPLICATIONERROR, "User not found", "The user is not found", "The operation can't be done", "Check the user (maybe it was deleted in the meantime ? )");
	private static BEvent EventOperationDone = new BEvent(SecurityCarAPI.class.getName(), 3, Level.SUCCESS, "Operation Success", "The operation is done");
	private static BEvent EventOperationError = new BEvent(SecurityCarAPI.class.getName(), 4, Level.APPLICATIONERROR, "Operation failed", "The operation failed", "The operation can't be done", "Check the exception");
	private static BEvent EventListenerNotDeployed = new BEvent(SecurityCarAPI.class.getName(), 5, Level.APPLICATIONERROR, "Listener not deployed", "To keep information of connected user, a listener must be deployed", "User connected can't be track", "Deploy the listener");
	private static BEvent EventException = new BEvent(SecurityCarAPI.class.getName(), 6, Level.APPLICATIONERROR, "Exception during execution", "The execution failed", "No result", "Check the exception");
	private static BEvent EventResetSuccess = new BEvent(SecurityCarAPI.class.getName(), 7, Level.SUCCESS, "Reset with success", "The number of tentative is set to 0 with success");
	private static BEvent EventCantUpdatePassword = new BEvent(SecurityCarAPI.class.getName(), 8, Level.APPLICATIONERROR, "Can't upate the password", "The password can't be updated", "Password does not change", "Check exception");

	/**
	 * SecurityParameter
	 *
	 */
	public static class SecurityParameter {
		public int connectedStartIndex = 0;
		public int connectedMaxResults = 0;
		public String userOperationsFilterUser = "";
		public int userOperationsStartIndex = 0;
		public int userOperationsMaxResults = 0;

		public int theftStartIndex = 0;
		public int theftMaxResults = 0;

		public int paramDaysPasswordActif = 0;
		public int paramMaxOfTentatives = 0;

		public long tenantId;

		public Long userId;
		public String userName;

		public static SecurityParameter getInstanceFromJsonSt(APISession apiSession, String jsonSt) {
			SecurityParameter securityParameter = new SecurityParameter();
			if (jsonSt == null)
				return securityParameter;

			securityParameter.tenantId = apiSession.getTenantId();
			@SuppressWarnings("unchecked")
            final HashMap<String, Object> jsonHash = (HashMap<String, Object>) JSONValue.parse(jsonSt);
			securityParameter.connectedStartIndex = SecurityToolbox.getInteger(jsonHash, "connectedStartIndex", 0);
			securityParameter.connectedMaxResults = SecurityToolbox.getInteger(jsonHash, "connectedMaxResults", 100);
			securityParameter.userOperationsFilterUser = SecurityToolbox.getString(jsonHash, "useroperationFilteruser", "");

			securityParameter.userOperationsStartIndex = SecurityToolbox.getInteger(jsonHash, "useroperationStartIndex", 0);
			securityParameter.userOperationsMaxResults = SecurityToolbox.getInteger(jsonHash, "useroperationMaxResults", 100);

			securityParameter.theftStartIndex = SecurityToolbox.getInteger(jsonHash, "theftStartIndex", 0);
			securityParameter.theftMaxResults = SecurityToolbox.getInteger(jsonHash, "theftMaxResults", 100);

			securityParameter.paramDaysPasswordActif = SecurityToolbox.getInteger(jsonHash, "nbdayspasswordactif", 0);
			securityParameter.paramMaxOfTentatives = SecurityToolbox.getInteger(jsonHash, "nbtentatives", 0);

			securityParameter.userId = SecurityToolbox.getLong(jsonHash.get("userid"), null);
			securityParameter.userName = SecurityToolbox.getString(jsonHash, "username", "");

			securityParameter.tenantId = 1;
			return securityParameter;
		}

	}

	/**
	 * SecurityStatus
	 *
	 */
	public static class SecurityStatus {
		public Information listUsersTheft = null;

		public Information listUsersConnected = null;

		public Information listUsersOperations = null;

		
		public Map<String, Map<String, Object>> theftTimeLine;
		public Map<String, Map<String, Object>> theftLog;
			
			
		// in case of operation on one user, return information
		public boolean userIsEnabled;
		public String passwordGenerated;

		public int paramDaysPasswordActif = 0;
		public int paramMaxOfTentatives = 3;

		public List<BEvent> listEvents = new ArrayList<BEvent>();

		public Map<String, Object> toMap() {
			Map<String, Object> map = new HashMap<String, Object>();

			map.put("theft", listUsersTheft != null ? listUsersTheft.getJson() : null);
			map.put("connected", listUsersConnected != null ? listUsersConnected.getJson() : null);
			map.put("operations", listUsersOperations != null ? listUsersOperations.getJson() : null);

			map.put("theftTimeLine",theftTimeLine);
			map.put("theftLog",theftLog);
		
			// create the graph one 2 days
			Calendar c = Calendar.getInstance();
			c.add( Calendar.DAY_OF_YEAR, -1);
			c.set(Calendar.HOUR_OF_DAY,0);
			c.set(Calendar.MINUTE, 0);
			c.set(Calendar.SECOND, 0);
			GraphGenerator graphGenerator = new GraphGenerator();
			
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHH");
			List<GraphRange> listRange = new ArrayList<GraphGenerator.GraphRange>();
			for (int i=0;i<2*24*6;i++)
			{
				String key=sdf.format( c.getTime());
				String title= i % 6 ==0 ? key  : "";
				if (theftTimeLine.containsKey(key))
					listRange=graphGenerator.addGraphRange(listRange, title, (Integer) theftTimeLine.get(key).get("n"));
				else
					listRange=graphGenerator.addGraphRange(listRange, title, 0L);
				c.add(Calendar.MINUTE, 10);
			}
			map.put("theftGraph", GraphGenerator.getGraphRange("Theft", listRange));
			
			Map<String, Object> parameter = new HashMap<String, Object>();

			map.put("parameter", parameter);
			parameter.put("nbdayspasswordactif", paramDaysPasswordActif);
			parameter.put("nbtentatives", paramMaxOfTentatives);

			map.put("passwordGenerated", passwordGenerated);

			map.put("listevents", BEventFactory.getHtml(listEvents));
			// in Javascript, easy to manipulate the status to know if the
			// operation is a success
			map.put("listeventssuccess", ! BEventFactory.isError(listEvents));
			return map;
		}

	}

	public UsersCustomInfo mUserInfo = null;

	public SecurityCarAPI() {
		mUserInfo = new UsersCustomInfo();
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* get general information */
	/*                                                                      */
	/* ********************************************************************* */

	/**
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	public SecurityStatus getStatus(SecurityParameter securityParameter, IdentityAPI identityAPI) {
		SecurityStatus securityStatus = new SecurityStatus();
		TowerControl towerControl = TowerControl.getInstance();

		towerControl.loadParameters(securityParameter.tenantId);
		securityStatus.paramDaysPasswordActif = towerControl.paramDaysPasswordActif;
		securityStatus.paramMaxOfTentatives = towerControl.paramMaxOfTentatives;

		securityStatus.listUsersTheft = getUserTheft(securityParameter, securityStatus, identityAPI);
		securityStatus.listUsersConnected = getListCurrentUserConnected(securityParameter, identityAPI);


		securityStatus.theftTimeLine = towerControl.getTheftTimeLine();
		securityStatus.theftLog = towerControl.getTheftLog();
		
			
			
		return securityStatus;
	}

	/**
	 * get the user operation
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	public SecurityStatus getUsersOperations(SecurityParameter securityParameter, IdentityAPI identityAPI) {
		SecurityStatus securityStatus = new SecurityStatus();
		TowerControl towerControl = TowerControl.getInstance();
		towerControl.loadParameters(securityParameter.tenantId);
		securityStatus.paramDaysPasswordActif = towerControl.paramDaysPasswordActif;
		securityStatus.paramMaxOfTentatives = towerControl.paramMaxOfTentatives;

		securityStatus.listUsersOperations = searchUsers(securityStatus.paramMaxOfTentatives, securityParameter.userOperationsFilterUser, securityParameter.userOperationsStartIndex, securityParameter.userOperationsMaxResults, identityAPI);

		return securityStatus;
	}

	
		
	/* ******************************************************************** */
	/*                                                                      */
	/* get status on connection */
	/*                                                                      */
	/* ********************************************************************* */
	private static String UserStatusTheft = "THEFT";
	private static String UserStatusDisable = "DISABLE";
	private static String UserStatusActif = "ACTIF";

	public static class Information {
		public List<BEvent> listEvents = new ArrayList<BEvent>();
		public int startIndex;
		public int maxResults;
		public long totalResult;
		public List<Map<String, Object>> mResult = new ArrayList<Map<String, Object>>();

		/**
		 * add a result and return the map
		 * 
		 * @return
		 */
		public Map<String, Object> addOneResult() {
			Map<String, Object> oneResult = new HashMap<String, Object>();
			mResult.add(oneResult);
			return oneResult;
		}

		// sort based on the username
		public void sort(final String nameAttribut) {
			Collections.sort(mResult, new Comparator<Map<String, Object>>() {
				public int compare(Map<String, Object> s1, Map<String, Object> s2) {
					String o1 = (String) s1.get(nameAttribut);
					String o2 = (String) s2.get(nameAttribut);
					if (o1 != null)
						return o1.compareTo(o2);
					return 0;
				}
			});
		}

		public Map<String, Object> getJson() {
			Map<String, Object> jsonMap = new HashMap<String, Object>();
			jsonMap.put("list", mResult.subList(startIndex, startIndex + maxResults > mResult.size() ? mResult.size() : startIndex + maxResults));

			jsonMap.put("nbconnected", totalResult);
			jsonMap.put("listevents", BEventFactory.getHtml(listEvents));

			return jsonMap;
		}

	}

	/**
	 * calculate the list of user connected
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	private Information getListCurrentUserConnected(SecurityParameter securityParameter, IdentityAPI identityAPI) {
		Information information = new Information();
		information.startIndex = securityParameter.connectedStartIndex;
		information.maxResults = securityParameter.connectedMaxResults;
		TowerControl towerControl = TowerControl.getInstance();
		List<Long> listUsersConnected = towerControl.getListCurrentUserConnected(information.startIndex, information.maxResults, identityAPI);
		if (listUsersConnected == null) {
			information.listEvents.add(EventListenerNotDeployed);
			return information;
		}

		for (Long userId : listUsersConnected)
			try {
				User user = identityAPI.getUser(userId);
				Map<String, Object> userMap = information.addOneResult();
				fillMapWithUser(userMap, user);
			} catch (UserNotFoundException e) {
				logger.severe(logHeader + ".getListCurrentUserConnected : " + e.toString());
			}

		// sort the list
		information.sort("username");

		return information;
	}

	/**
	 * user theft
	 * 
	 * @param securityParameter
	 * @param securityStatus
	 * @param identityAPI
	 */
	public Information getUserTheft(SecurityParameter securityParameter, SecurityStatus securityStatus, IdentityAPI identityAPI) {

		Information information = new Information();
		information.startIndex = securityParameter.theftStartIndex;
		information.maxResults = securityParameter.theftMaxResults;

		mUserInfo.checkUserCustom(identityAPI);

		SearchOptionsBuilder optionsBuilder = new SearchOptionsBuilder(securityParameter.theftStartIndex, securityParameter.theftMaxResults);
		optionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mUserInfo.mDefinitionTentative);
		optionsBuilder.greaterThan(CustomUserInfoValueSearchDescriptor.VALUE, Long.valueOf(0));
		optionsBuilder.sort(CustomUserInfoValueSearchDescriptor.USER_ID, Order.ASC);

		SearchResult<CustomUserInfoValue> search = identityAPI.searchCustomUserInfoValues(optionsBuilder.done());
		information.totalResult = search.getCount();
		for (CustomUserInfoValue userInfoValue : search.getResult()) {
			Map<String, Object> userMap = information.addOneResult();

			userMap.put("nbtentative", SecurityToolbox.getInteger(userInfoValue.getValue(), 0));
			User user;
			try {
				user = identityAPI.getUser(userInfoValue.getUserId());
				fillMapWithUser(userMap, user);
			} catch (UserNotFoundException e) {
			}
		}
		return information;
	}

	/**
	 * searchInformation on the users, ordered by the username ASC
	 * 
	 * @param maxTentatives
	 *            after this number of tentative, the user is considered as in
	 *            progress to be stolen
	 * @param filterUser
	 * @param startIndex
	 * @param maxResults
	 * @param identityAPI
	 * @return
	 */
	public Information searchUsers(int maxTentatives, String filterUser, int startIndex, int maxResults, IdentityAPI identityAPI) {
		Information information = new Information();
		information.startIndex = startIndex;
		information.maxResults = maxResults;

		logger.info(logHeader + ".searchUsers : filterUser[" + filterUser + "] startIndex[" + startIndex + "] maxResult[" + maxResults + "]");

		try {

			SearchOptionsBuilder optionsBuilder = new SearchOptionsBuilder(startIndex, maxResults);
			if (filterUser != null && filterUser.trim().length() > 0)
				optionsBuilder.filter(UserSearchDescriptor.USER_NAME, filterUser);

			optionsBuilder.sort(UserSearchDescriptor.USER_NAME, Order.ASC);

			SearchResult<User> search = identityAPI.searchUsers(optionsBuilder.done());
			information.totalResult = search.getCount();
			Map<Long, Map<String, Object>> directAccess = new HashMap<Long, Map<String, Object>>();
			for (User user : search.getResult()) {
				logger.info(logHeader + ".searchUsers : found user[" + user.getUserName() + "] id[" + user.getId() + "]");
				Map<String, Object> userMap = information.addOneResult();
				fillMapWithUser(userMap, user);

				userMap.put("nbtentatives", 0);

				if (!user.isEnabled())
					userMap.put("status", UserStatusDisable);
				else
					userMap.put("status", UserStatusActif);
				directAccess.put(user.getId(), userMap);
			}

			// now search the additionnal information from this list of user
			UsersCustomInfo userCustomInfo = new UsersCustomInfo();

			userCustomInfo.checkUserCustom(identityAPI);

			// the list may be very large : ask per page of 10
			int count = 0;
			int nbPerPage = 10;
			while (count < information.mResult.size()) {
				List<Long> listPageUserId = new ArrayList<Long>();
				for (int i = 0; i < nbPerPage; i++) {
					if (count + i < information.mResult.size()) {
						listPageUserId.add((Long) information.mResult.get(count + i).get("userid"));
						logger.info(logHeader + ".searchUsers : search additionnal inform for user[" + (Long) information.mResult.get(count + i).get("userid") + "]");

					}
				}
				SearchResult<CustomUserInfoValue> searchResult = userCustomInfo.getUsersInformation(listPageUserId, identityAPI);
				// explode
				for (CustomUserInfoValue customerUserInfo : searchResult.getResult()) {
					Map<String, Object> mapUserInfo = directAccess.get(customerUserInfo.getUserId());
					if (mapUserInfo == null) {
						logger.severe(logHeader + "Cant find the map for userid[" + customerUserInfo.getUserId() + "]");
						continue;
					}
					logger.info(logHeader + ".searchUsers : found additionnal inform for user[" + customerUserInfo.getUserId() + "] defId[" + customerUserInfo.getDefinitionId() + "] value[" + customerUserInfo.getValue() + "]");

					if (customerUserInfo.getDefinitionId() == userCustomInfo.mDefinitionTentative)
						mapUserInfo.put("nbtentatives", customerUserInfo.getValue());
					if (customerUserInfo.getDefinitionId() == userCustomInfo.mDefinitionLastChangePassword) {
						Long lastChangePasswordLong = SecurityToolbox.getLong(customerUserInfo.getValue(), null);
						if (lastChangePasswordLong != null)
							mapUserInfo.put("lastChangePassword", sdf.format(new Date(lastChangePasswordLong)));
					}
				}
				count += nbPerPage;
			}

			// ok, reprocess to set the status
			for (int i = 0; i < information.mResult.size(); i++) {
				int nbTentative = SecurityToolbox.getInteger(information.mResult.get(i).get("nbtentatives"), 0);
				if (nbTentative > maxTentatives)
					information.mResult.get(i).put("status", UserStatusTheft);
			}
		} catch (Exception e) {
			logger.severe(logHeader + "Error " + e.toString());
			information.listEvents.add(new BEvent(EventException, e, ""));
		}
		return information;
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* Theft */
	/*                                                                      */
	/* ********************************************************************* */

	/* ******************************************************************** */
	/*                                                                      */
	/* UserOperation */
	/*                                                                      */
	/* ********************************************************************* */
	SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

	public SecurityStatus setUserEnable(SecurityParameter securityParameter, boolean enableUser, IdentityAPI identityAPI) {
		SecurityStatus securityStatus = new SecurityStatus();
		logger.info(logHeader + ".setUserEnable : username[" + securityParameter.userName + "] userId[" + securityParameter.userId + "] enable ? " + enableUser);

		UserUpdater userUpdater = new UserUpdater();
		userUpdater.setEnabled(enableUser);
		try {
			identityAPI.updateUser(securityParameter.userId, userUpdater);
			securityStatus.listEvents.add(new BEvent(EventOperationDone, "User updated"));
			securityStatus.userIsEnabled = enableUser;
			if (!enableUser) {
				// disconnect it
				TowerControl towerControl = TowerControl.getInstance();
				securityStatus.listEvents = towerControl.disconnect(securityParameter.userId, identityAPI);

			}
		} catch (UserNotFoundException e) {
			securityStatus.listEvents.add(new BEvent(EventUserNotFound, securityParameter.userName));
		} catch (UpdateException e) {
			securityStatus.listEvents.add(new BEvent(EventOperationError, e, "Update user [" + securityParameter.userName + "] userId[" + securityParameter.userId + "]"));
		}

		return securityStatus;
	}

	/**
	 * disconnect the user
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	public SecurityStatus disconnect(SecurityParameter securityParameter, IdentityAPI identityAPI) {
		SecurityStatus securityStatus = new SecurityStatus();
		logger.info(logHeader + ".disconnect : username[" + securityParameter.userName + "] userId[" + securityParameter.userId + "] ");
		TowerControl towerControl = TowerControl.getInstance();

		securityStatus.listEvents = towerControl.disconnect(securityParameter.userId, identityAPI);

		return securityStatus;
	}

	/**
	 * disconnect the user
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	public SecurityStatus resetTentative(SecurityParameter securityParameter, IdentityAPI identityAPI) {
		SecurityStatus securityStatus = new SecurityStatus();
		logger.info(logHeader + ".resetTentative : username[" + securityParameter.userName + "] userId[" + securityParameter.userId + "] ");
		UsersCustomInfo userCustomInfo = new UsersCustomInfo();
		TentativeStatus tentativeStatus = userCustomInfo.updateAttributes(Integer.valueOf(0), null, securityParameter.userId, identityAPI);

		securityStatus.listEvents = tentativeStatus.listEvents;
		if (!BEventFactory.isError(securityStatus.listEvents)) {
			securityStatus.listEvents.add(EventResetSuccess);
		}
		return securityStatus;
	}

	/**
	 * reset the password
	 * 
	 * @param securityParameter
	 * @param identityAPI
	 * @return
	 */
	public SecurityStatus resetPassword(SecurityParameter securityParameter, IdentityAPI identityAPI) {

		SecurityStatus securityStatus = new SecurityStatus();

		// generate a new password
		char[] possibleCharacters = (new String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$&*_")).toCharArray();
		String randomStr = RandomStringUtils.random(10, 0, possibleCharacters.length - 1, false, false, possibleCharacters, new SecureRandom());
		// set it
		UserUpdater userUpdater = new UserUpdater();
		userUpdater.setPassword(randomStr);
		try {
			identityAPI.updateUser(securityParameter.userId, userUpdater);
			securityStatus.passwordGenerated = randomStr;
			// set the date
			UsersCustomInfo userCustomInfo = new UsersCustomInfo();
			TentativeStatus tentativeStatus = userCustomInfo.updateAttributes(null, new Date(), securityParameter.userId, identityAPI);
			securityStatus.listEvents.addAll(tentativeStatus.listEvents);
		} catch (Exception e) {
			logger.severe(logHeader + " Can't update password[" + randomStr + "] userId[" + securityParameter.userId + "] error:" + e.toString());
			securityStatus.listEvents.add(new BEvent(EventCantUpdatePassword, e, "Password[" + randomStr + "] userId[" + securityParameter.userId + "]"));
		}
		return securityStatus;
	}

	/* ******************************************************************** */
	/*                                                                      */
	/* private method */
	/*                                                                      */
	/* ********************************************************************* */

	/**
	 * fill the map from the user
	 * 
	 * @param userMap
	 * @param user
	 */
	private void fillMapWithUser(Map<String, Object> userMap, User user) {
		userMap.put("userid", user.getId());
		userMap.put("username", user.getUserName());
		userMap.put("firstname", user.getFirstName());
		userMap.put("lastname", user.getLastName());
		userMap.put("isenabled", user.isEnabled());
		userMap.put("lastconnection", user.getLastConnection() == null ? null : sdf.format(user.getLastConnection()));
	}

}
