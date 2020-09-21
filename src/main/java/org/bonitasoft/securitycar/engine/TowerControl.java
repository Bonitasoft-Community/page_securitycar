package org.bonitasoft.securitycar.engine;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpSession;

import org.bonitasoft.console.common.server.utils.SessionUtil;
import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.exception.SearchException;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserSearchDescriptor;
import org.bonitasoft.engine.search.SearchOptionsBuilder;
import org.bonitasoft.engine.search.SearchResult;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.log.event.BEvent;
import org.bonitasoft.log.event.BEvent.Level;
import org.bonitasoft.log.event.BEventFactory;
import org.bonitasoft.properties.BonitaProperties;
import org.bonitasoft.securitycar.SecurityCarAPI.SecurityParameter;
import org.bonitasoft.securitycar.SecurityCarAPI.SecurityStatus;
import org.bonitasoft.securitycar.server.Butler;
import org.bonitasoft.securitycar.server.Butler.RegisterTentative;
import org.bonitasoft.securitycar.server.Butler.SlotStatistics;
import org.bonitasoft.securitycar.users.UsersCustomInfo;

/**
 * Tower Control is used to keep track of all needed information. It is the
 * basis of the Filter and Listener. In order to let the page run as maximum as
 * possible, the tower keep only information relative to the theft and
 * connection.
 */
public class TowerControl {

    private static final int CST_NUMBER_USERS_SEARCH_AT_A_TIME = 50;
    private static Logger logger = Logger.getLogger(TowerControl.class.getName());
    public String logHeader = "--------------------- TowerControl SecurityCar ";

    SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    private static TowerControl towerControl = new TowerControl();

    private static BEvent cstEventNotDeployed = new BEvent(TowerControl.class.getName(), 1, Level.ERROR, "Listener not deployed", "The listener is not deployed, not possible to disconnect the user", "user will not be disconnected", "Install the listener");
    // private static BEvent EventException = new BEvent(TowerControl.class.getName(), 2, Level.APPLICATIONERROR, "Exception during execution", "The execution failed", "No result", "Check the exception");
    private static BEvent EventUserDisconnected = new BEvent(TowerControl.class.getName(), 3, Level.SUCCESS, "User Disconnected", "The user is disconnected");
    private static BEvent EventUserNotDisconnected = new BEvent(TowerControl.class.getName(), 4, Level.APPLICATIONERROR, "User not Disconnected", "The user is not disconnected, because no user connection is found", "", "Refresh the screen");
    private static BEvent EventCantDisableUser = new BEvent(TowerControl.class.getName(), 5, Level.APPLICATIONERROR, "Can't disable user", "The user has too many tentative, and should be disable. An error arrive", "User is not disabled", "Check the error");
    private static BEvent EventParametersSaved = new BEvent(TowerControl.class.getName(), 6, Level.SUCCESS, "Parameters saved", "Parameters saved");

    private TowerControl() {

    }

    public static TowerControl getInstance() {
        return towerControl;
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Theft */
    /*                                                                      */
    /* -------------------------------------------------------------------- */
    public class TheftReport {

        public List<RegisterTentative> listTentativesRegistered;
        public Map<String, SlotStatistics> mapTentativesSlot;
        public List<BEvent> listEvents = new ArrayList<>();

    }

    public static class TheftParameter {

        public boolean reportTentatives = true;
        public boolean reportSlots = true;
        public boolean reportUsersTheft = true;
    }

    /**
     * Get the current Theft. Ask the Butler what he did. Check how many users was disabled in the last week for example.
     * 
     * @param identityAPI
     * @return
     */
    public TheftReport getTheft(TheftParameter theftParameter, IdentityAPI identityAPI) {
        TheftReport theftReport = new TheftReport();
        logger.info(logHeader + ".getListCurrentUserConnected");
        Butler butler = Butler.getInstance();
        if (theftParameter.reportTentatives)
            theftReport.listTentativesRegistered = butler.getTentatives();
        if (theftParameter.reportSlots)
            theftReport.mapTentativesSlot = butler.getTentativesSlot();

        return theftReport;
    }

    /**
     * Information information = new Information();
     * information.startIndex = securityParameter.theftStartIndex;
     * information.maxResults = securityParameter.theftMaxResults;
     * mUserInfo.checkUserCustom(identityAPI);
     * SearchOptionsBuilder optionsBuilder = new SearchOptionsBuilder(securityParameter.theftStartIndex, securityParameter.theftMaxResults);
     * optionsBuilder.filter(CustomUserInfoValueSearchDescriptor.DEFINITION_ID, mUserInfo.mDefinitionTentative);
     * optionsBuilder.greaterThan(CustomUserInfoValueSearchDescriptor.VALUE, Long.valueOf(0));
     * optionsBuilder.sort(CustomUserInfoValueSearchDescriptor.USER_ID, Order.ASC);
     * SearchResult<CustomUserInfoValue> search = identityAPI.searchCustomUserInfoValues(optionsBuilder.done());
     * information.totalResult = search.getCount();
     * for (CustomUserInfoValue userInfoValue : search.getResult()) {
     * Map<String, Object> userMap = information.addOneResult();
     * userMap.put("nbtentative", SecurityToolbox.getInteger(userInfoValue.getValue(), 0));
     * User user;
     * try {
     * user = identityAPI.getUser(userInfoValue.getUserId());
     * fillMapWithUser(userMap, user);
     * } catch (UserNotFoundException e) {
     * }
     * }
     * return information;
     * 
     * @author Firstname Lastname
     */

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Activity */
    /*                                                                      */
    /* -------------------------------------------------------------------- */
    public class UserConnected {

        long userId;
        public User user;
        public int nbOfSessionOpened = 0;

        public UserConnected(long userId) {
            this.userId = userId;
        }
    }

    public class ActivityReport {

        public Map<String, SlotStatistics> mapHttpcallSlot;
        /**
         * Return the list of user connected, according the page size
         */
        public List<UserConnected> listUsersConnected;
        public int nbUsersConnected = 0;
        public List<BEvent> listEvents = new ArrayList<>();

    }

    public enum ORDERCONNECTEDUSER {
        NAME, CONNECTIONTIME
    }

    public static class ActivityReportParameter {

        public boolean reportHttpCall = false;

        public boolean reportUserConnected = false;
        public int userConnectedPageNumber = 0;
        public int userConnectedPageSize = 0;
        public String userFilterName = null;
        public ORDERCONNECTEDUSER orderConnectedUser;

    }

    public ActivityReport getServerActivity(ActivityReportParameter activityReportParameter, IdentityAPI identityAPI) {
        ActivityReport activityReport = new ActivityReport();
        logger.info(logHeader + ".getServerActivity");
        Butler butler = Butler.getInstance();

        if (activityReportParameter.reportHttpCall)
            activityReport.mapHttpcallSlot = butler.getMapHttpCallSlot();

        if (activityReportParameter.reportUserConnected) {
            if (butler.mSecurityCarListenerSession == null) {
                logger.info(logHeader + ".getServerActivity : listener not deployed");
                activityReport.listEvents.add(cstEventNotDeployed);
            } else {
                Map<Long, UserConnected> mapUsersConnectedId = new HashMap<>();

                for (HttpSession httpSession : butler.mSecurityCarListenerSession.getListSession().values()) {
                    APISession apiSession = (APISession) httpSession.getAttribute(SessionUtil.API_SESSION_PARAM_KEY);
                    if (apiSession != null) {
                        mapUsersConnectedId.computeIfAbsent(apiSession.getUserId(), val -> new UserConnected(apiSession.getUserId()));
                        UserConnected userConnected = mapUsersConnectedId.get(apiSession.getUserId());
                        userConnected.nbOfSessionOpened++;
                    }
                }
                activityReport.nbUsersConnected = mapUsersConnectedId.size();
                // second step, calculated the list of users behind the list. 
                // let's based that this number may be very large (10000 users connected), and the page count / number won't works here
                // because the filter will be too large
                loadUsers(mapUsersConnectedId, activityReportParameter.userFilterName, identityAPI);
                // use a list now
                List<UserConnected> listUsersConnected = new ArrayList(mapUsersConnectedId.values());

                // ordered by the criteria : not implemented ORDERCONNECTEDUSER
                Collections.sort(listUsersConnected, new Comparator<UserConnected>() {

                    public int compare(UserConnected s1,
                            UserConnected s2) {
                        if (s1.user != null || s2.user == null)
                            return 0;
                        return s1.user.getUserName().compareTo(s2.user.getUserName());
                    }
                });
                // now, we can keep the page information size
                if (listUsersConnected.size() > activityReportParameter.userConnectedPageSize) {
                    int fromIndex = activityReportParameter.userConnectedPageNumber * activityReportParameter.userConnectedPageSize;
                    int toIndex = activityReportParameter.userConnectedPageNumber * activityReportParameter.userConnectedPageSize + activityReportParameter.userConnectedPageSize - 1;
                    if (fromIndex > listUsersConnected.size())
                        fromIndex = listUsersConnected.size() - 1;
                    if (toIndex > listUsersConnected.size())
                        toIndex = listUsersConnected.size() - 1;

                    listUsersConnected = listUsersConnected.subList(fromIndex, toIndex);
                }
                activityReport.listUsersConnected = listUsersConnected;
            }
        }

        return activityReport;
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Operation */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    /**
     * disconnect a user
     * 
     * @param userId
     * @param identityAPI
     * @return
     */
    public List<BEvent> disconnect(long userId, IdentityAPI identityAPI) {
        List<BEvent> listEvents = new ArrayList<>();
        Butler butler = Butler.getInstance();

        if (butler.mSecurityCarListenerSession == null) {
            logger.info(logHeader + ".getListCurrentUserConnected : listener not deployed");
            listEvents.add(cstEventNotDeployed);
            return listEvents;
        }

        for (HttpSession httpSession : butler.mSecurityCarListenerSession.getListSession().values()) {
            APISession apiSession = (APISession) httpSession.getAttribute(SessionUtil.API_SESSION_PARAM_KEY);
            if (apiSession != null && apiSession.getUserId() == userId) {
                // disconnect : just remove the API Session
                httpSession.setAttribute(SessionUtil.API_SESSION_PARAM_KEY, null);
                listEvents.add(EventUserDisconnected);
                return listEvents;
            }
        }

        listEvents.add(EventUserNotDisconnected);
        return listEvents;

    }

    /* ******************************************************************** */
    /*                                                                      */
    /* Watch Dog function */
    /*                                                                      */
    /* ******************************************************************** */
    public boolean watchDog(Filter filter, ServletRequest httpRequest) {
        return true;
    }

    /* ******************************************************************** */
    /*                                                                      */
    /* parameters */
    /*                                                                      */
    /* ******************************************************************** */
    private final static String CSTPROPERTIE_PARAMPASSWORDEXPIREDMECHANISM = "PasswordExpired";
    private final static String CSTPROPERTIE_PARAMDAYSPASSWORDACTIF = "DaysPasswordActif";
    private final static String CSTPROPERTIE_PARAMMAXOFTENTATIVE = "maxOfTentatives";

    /**
     * if 0, then the mechanism is not activated
     */
    public boolean paramPasswordExpiredMechanismEnable = false;
    public Integer paramDaysPasswordActif = 0;
    public Integer paramMaxOfTentatives = 6;
    /**
     * in order to not reload at each call the param, we kept the last time the load was done, and we reload only after X minutes
     */
    public long paramLastTimeLoad;

    public List<BEvent> init(long tenantId) {
        BonitaProperties bonitaProperties = new BonitaProperties(UsersCustomInfo.PROPERTIESNAME, tenantId);
        // init: load parameter and check the database
        bonitaProperties.setCheckDatabase(true);
        return bonitaProperties.load();
    }

    /**
     * loadParameters
     * 
     * @param tenantId
     * @param securityStatus
     */
    public List<BEvent> loadParameters(long tenantId) {
        List<BEvent> listEvents = new ArrayList<>();
        BonitaProperties bonitaProperties = new BonitaProperties(UsersCustomInfo.PROPERTIESNAME, tenantId);
        bonitaProperties.setCheckDatabase(false);
        listEvents.addAll(bonitaProperties.load());

        String passwordExpiredMechanism = bonitaProperties.getProperty(CSTPROPERTIE_PARAMPASSWORDEXPIREDMECHANISM, "0");
        paramPasswordExpiredMechanismEnable = passwordExpiredMechanism == null ? false : Boolean.valueOf(passwordExpiredMechanism);

        String dayPasswordActifSt = bonitaProperties.getProperty(CSTPROPERTIE_PARAMDAYSPASSWORDACTIF, "0");
        paramDaysPasswordActif = dayPasswordActifSt == null ? 0 : Integer.valueOf(dayPasswordActifSt);

        String maxOfTentativesSt = bonitaProperties.getProperty(CSTPROPERTIE_PARAMMAXOFTENTATIVE, "6");
        paramMaxOfTentatives = maxOfTentativesSt == null ? 6 : Integer.valueOf(maxOfTentativesSt);
        paramLastTimeLoad = System.currentTimeMillis();

        return listEvents;
    }

    /**
     * @param tenantId
     * @param securityParameter
     * @param securityStatus
     */
    public SecurityStatus saveParameters(SecurityParameter securityParameter) {
        SecurityStatus securityStatus = new SecurityStatus();
        BonitaProperties bonitaProperties = new BonitaProperties(UsersCustomInfo.PROPERTIESNAME, securityParameter.tenantId);
        bonitaProperties.setCheckDatabase(false);

        securityStatus.listEvents.addAll(bonitaProperties.load());

        logger.info(logHeader + ",Save passwordActif[" + securityParameter.paramDaysPasswordActif + "] nbTentatives[" + securityParameter.paramMaxOfTentatives + "]");
        bonitaProperties.setProperty(CSTPROPERTIE_PARAMPASSWORDEXPIREDMECHANISM, String.valueOf(securityParameter.paramPasswordExpiredMechanismEnable));
        bonitaProperties.setProperty(CSTPROPERTIE_PARAMDAYSPASSWORDACTIF, String.valueOf(securityParameter.paramDaysPasswordActif));
        bonitaProperties.setProperty(CSTPROPERTIE_PARAMMAXOFTENTATIVE, String.valueOf(securityParameter.paramMaxOfTentatives));

        securityStatus.listEvents.addAll(bonitaProperties.store());
        if (!BEventFactory.isError(securityStatus.listEvents)) {
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
     * load users per page of X items
     * 
     * @param listUsersConnectedId
     * @param userFilterName
     * @param identityAPI
     * @return
     */
    private void loadUsers(Map<Long, UserConnected> mapUsersConnectedId, String userFilterName, IdentityAPI identityAPI) {
        List<UserConnected> listUsersConnectedId = new ArrayList(mapUsersConnectedId.values());
        /** load page per page */
        int fromIndex = 0;
        while (fromIndex <= listUsersConnectedId.size()) {
            SearchOptionsBuilder sob = new SearchOptionsBuilder(0, 1000);
            if (userFilterName != null) {
                sob.leftParenthesis();
                sob.filter(UserSearchDescriptor.USER_NAME, userFilterName);
                sob.or();
                sob.filter(UserSearchDescriptor.FIRST_NAME, userFilterName);
                sob.or();
                sob.filter(UserSearchDescriptor.LAST_NAME, userFilterName);
                sob.rightParenthesis();
                sob.and();
            }
            sob.leftParenthesis();
            for (int i = 0; i < Math.min(CST_NUMBER_USERS_SEARCH_AT_A_TIME, listUsersConnectedId.size()); i++) {
                if (i > 0)
                    sob.or();
                sob.filter(UserSearchDescriptor.ID, listUsersConnectedId.get(fromIndex + i).userId);
            }
            sob.rightParenthesis();
            try {
                SearchResult<User> searchResult = identityAPI.searchUsers(sob.done());
                // apply
                for (User user : searchResult.getResult()) {
                    UserConnected userConnected = mapUsersConnectedId.get(user.getId());
                    if (userConnected != null)
                        userConnected.user = user;
                }

            } catch (SearchException e) {
                logger.severe("Search Error " + e.getMessage());
            }
            fromIndex += CST_NUMBER_USERS_SEARCH_AT_A_TIME;
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
