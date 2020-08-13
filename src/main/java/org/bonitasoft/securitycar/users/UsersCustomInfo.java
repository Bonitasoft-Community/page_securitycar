package org.bonitasoft.securitycar.users;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.exception.AlreadyExistsException;
import org.bonitasoft.engine.exception.CreationException;
import org.bonitasoft.engine.exception.UpdateException;
import org.bonitasoft.engine.identity.CustomUserInfoDefinition;
import org.bonitasoft.engine.identity.CustomUserInfoDefinitionCreator;
import org.bonitasoft.engine.identity.CustomUserInfoValue;
import org.bonitasoft.engine.identity.CustomUserInfoValueSearchDescriptor;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserNotFoundException;
import org.bonitasoft.engine.search.SearchOptionsBuilder;
import org.bonitasoft.engine.search.SearchResult;
import org.bonitasoft.log.event.BEvent;
import org.bonitasoft.log.event.BEvent.Level;
import org.bonitasoft.securitycar.server.SecurityCarListenerSession;

public class UsersCustomInfo {
	private static Logger logger = Logger.getLogger(SecurityCarListenerSession.class.getName());
	public String logHeader = "--------------------- SecurityCar.UsersCustomInfo";

	private static BEvent EventCantRegisterTentative = new BEvent(UsersCustomInfo.class.getName(), 1, Level.APPLICATIONERROR, "Can't register the tentative", "The user custom info is not created, the tentative can't be register");
	private static BEvent EventUserNotExist = new BEvent(UsersCustomInfo.class.getName(), 2, Level.APPLICATIONERROR, "User not found", "A tentative is done on a unknow user (may be an attack)", "Check the number of occurence, you may are under attack", "Check who do the tentative");
	private static BEvent EventCantCreateUserCustomAttribut = new BEvent(UsersCustomInfo.class.getName(), 3, Level.ERROR, "Can't create User Custom attribut", "The creation of a custom attribut is not possible", "Tentative can't be registered", "Check error");
	private static BEvent EventCantResetTentative = new BEvent(UsersCustomInfo.class.getName(), 4, Level.ERROR, "Can't reset the number of tentative", "The reset is not possible, user still have the same number of tentative", "User has to connect with the correct password to reset it to zero", "Check exception"); 
	private static BEvent EventCantSetLastDateChangePassword = new BEvent(UsersCustomInfo.class.getName(), 5, Level.ERROR, "Can't set the change password date", "The set is not possible", "The last date when the password change is not updated", "Check exception"); 
	
	
	public Long mDefinitionTentative = null;
	public Long mDefinitionLastChangePassword = null;

	public final static String USERTENTATIVE = "USERTENTATIVECONNECTION";
	public final static String USERLASTCHANGEPASSWORD = "USERLASTCHANGEPASSWORD";
	public final static String PROPERTIESNAME = "securitycarproperties";

	public static UsersCustomInfo getInstance() {
		return new UsersCustomInfo();
	}

	/*
	 * check and create the custom information if needed
	 */
	public List<BEvent> checkUserCustom(IdentityAPI identityAPI) {
		List<BEvent> listEvents = new ArrayList<BEvent>();
		if (mDefinitionTentative != null && mDefinitionLastChangePassword != null)
			return listEvents;

		List<CustomUserInfoDefinition> listInfo = identityAPI.getCustomUserInfoDefinitions(0, 10000);
		for (CustomUserInfoDefinition info : listInfo) {
			if (info.getName().equals(USERTENTATIVE))
				mDefinitionTentative = info.getId();
			if (info.getName().equals(USERLASTCHANGEPASSWORD))
				mDefinitionLastChangePassword = info.getId();
		}

		if (mDefinitionTentative == null) {
			CustomUserInfoDefinitionCreator creator = new CustomUserInfoDefinitionCreator(USERTENTATIVE);
			;
			CustomUserInfoDefinition infoDefinition;
			try {
				infoDefinition = identityAPI.createCustomUserInfoDefinition(creator);
				mDefinitionTentative = infoDefinition.getId();
			} catch (AlreadyExistsException e) {
			} catch (CreationException e) {
				listEvents.add(new BEvent(EventCantCreateUserCustomAttribut, e, "Attribute[" + USERTENTATIVE + "]"));
			}

		}
		if (mDefinitionLastChangePassword == null) {
			CustomUserInfoDefinitionCreator creator = new CustomUserInfoDefinitionCreator(USERLASTCHANGEPASSWORD);
			;
			CustomUserInfoDefinition infoDefinition;
			try {
				infoDefinition = identityAPI.createCustomUserInfoDefinition(creator);
				mDefinitionLastChangePassword = infoDefinition.getId();
			} catch (AlreadyExistsException e) {
			} catch (CreationException e) {
				listEvents.add(new BEvent(EventCantCreateUserCustomAttribut, e, "Attribute[" + USERLASTCHANGEPASSWORD + "]"));
			}
		}
		return listEvents;
	}

	public static class TentativeStatus
	{
		public List<BEvent> listEvents;
		public int nbTentative=0;
		public Long userId=null;
	}
	/**
	 * add one tentative, which can failed (or not)
	 * 
	 * @param userName
	 * @param sourceIpAddress
	 * @param correct
	 * @param identityAPI
	 * @return
	 */
	public TentativeStatus addOneTentative(String userName, String sourceIpAddress, boolean correct, IdentityAPI identityAPI) {
		TentativeStatus tentativeStatus = new TentativeStatus();
		tentativeStatus.listEvents = checkUserCustom(identityAPI);
		if (mDefinitionTentative == null) {
			logger.severe(logHeader + "No custom UserTentative created, can't register the tentative");
			tentativeStatus.listEvents.add(EventCantRegisterTentative);
			return tentativeStatus;
		}
		// search the user
		User user;
		try {
			user = identityAPI.getUserByUserName(userName);
			tentativeStatus.userId = user.getId();
			SearchOptionsBuilder searchOptionsBuilder = new SearchOptionsBuilder(0, 10);
			searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mDefinitionTentative);
			searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.USER_ID, user.getId());
			
			SearchResult<CustomUserInfoValue> searchResult = identityAPI.searchCustomUserInfoValues(searchOptionsBuilder.done());
			if (searchResult.getCount() > 0) {
				tentativeStatus.nbTentative = SecurityToolbox.getInteger(searchResult.getResult().get(0).getValue(), 0);
			}
			if (correct)
				tentativeStatus.nbTentative = 0;
			else
				tentativeStatus.nbTentative++;
			// set the value now
			identityAPI.setCustomUserInfoValue(mDefinitionTentative, user.getId(), String.valueOf(tentativeStatus.nbTentative));
		} catch (UserNotFoundException e) {
			tentativeStatus.listEvents.add(new BEvent(EventUserNotExist, "User [" + userName + "] Ip[" + sourceIpAddress + "]"));

		} catch (UpdateException e) {
			tentativeStatus.listEvents.add(new BEvent(EventCantRegisterTentative, "User [" + userName + "] error " + e.toString()));
		}
		return tentativeStatus;
	}

	/**
	 * add one tentative, which can failed (or not)
	 * 
	 * @param userName
	 * @param sourceIpAddress
	 * @param correct
	 * @param identityAPI
	 * @return
	 */
	public TentativeStatus updateAttributes(Integer nbTentatives, Date userLastChangePassword, Long userId, IdentityAPI identityAPI) {
		TentativeStatus tentativeStatus = new TentativeStatus();
		tentativeStatus.listEvents = checkUserCustom(identityAPI);
		// search the user
		User user;
		BEvent eventInCaseOfError=null;
		try {
			tentativeStatus.userId = userId;
			if (nbTentatives!=null)
			{
				eventInCaseOfError = EventCantResetTentative;
				if (mDefinitionTentative == null) {
					logger.severe(logHeader + "No custom attribut["+USERTENTATIVE+"] created, can't reset the number");
					tentativeStatus.listEvents.add(EventCantResetTentative);
				}				
				else
					identityAPI.setCustomUserInfoValue(mDefinitionTentative, userId, String.valueOf(tentativeStatus.nbTentative));
			}

			if (userLastChangePassword!=null)
			{
				
				eventInCaseOfError = EventCantSetLastDateChangePassword;
				if (mDefinitionLastChangePassword == null) {
					logger.severe(logHeader + "No custom attribut["+USERLASTCHANGEPASSWORD+"] created, can't save the last date");
					tentativeStatus.listEvents.add(EventCantSetLastDateChangePassword);
				}				
				else
					identityAPI.setCustomUserInfoValue(mDefinitionLastChangePassword, userId, String.valueOf(userLastChangePassword.getTime()));
			}
		} catch (UpdateException e) {
			tentativeStatus.listEvents.add(new BEvent(eventInCaseOfError, "UserId[" + userId + "] error " + e.toString()));
		}
		return tentativeStatus;
	}

	/**
	 * return the number of tentative for a list of user, start a startIndex for
	 * maxResults values
	 * 
	 * @param startIndex
	 * @param maxResults
	 * @param identityAPI
	 * @return
	 */
	public SearchResult<CustomUserInfoValue> getUsersTentatives(int startIndex, int maxResults, IdentityAPI identityAPI) {
		SearchOptionsBuilder searchOptionsBuilder = new SearchOptionsBuilder(startIndex, maxResults);
		searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mDefinitionTentative);

		SearchResult<CustomUserInfoValue> searchResult = identityAPI.searchCustomUserInfoValues(searchOptionsBuilder.done());
		return searchResult;
	}
	
	/**
	 * get all userinformations relative to the list of users.
	 * Attention : the result contains potentialy 2 records per user (one for the tentative, one for the last change password)
	 * @param listUserId
	 * @param identityAPI
	 * @return
	 */
	public SearchResult<CustomUserInfoValue> getUsersInformation(List<Long> listUserId, IdentityAPI identityAPI) {
		
		if (listUserId.size()==0)
			return null;
		SearchOptionsBuilder searchOptionsBuilder = new SearchOptionsBuilder(0, listUserId.size() * 2);
		searchOptionsBuilder.leftParenthesis();
		searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mDefinitionTentative);
		searchOptionsBuilder.or();
		searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mDefinitionLastChangePassword);
		searchOptionsBuilder.rightParenthesis();
		searchOptionsBuilder.and();
		searchOptionsBuilder.leftParenthesis();
		for (int i=0;i<listUserId.size();i++)
		{
			if (i>0)
				searchOptionsBuilder.or();
			searchOptionsBuilder.filter(CustomUserInfoValueSearchDescriptor.USER_ID, listUserId.get( i ));
		}
		searchOptionsBuilder.rightParenthesis();

		SearchResult<CustomUserInfoValue> searchResult = identityAPI.searchCustomUserInfoValues(searchOptionsBuilder.done());
		return searchResult;
	}
}
