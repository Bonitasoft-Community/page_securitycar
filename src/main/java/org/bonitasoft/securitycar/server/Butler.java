package org.bonitasoft.securitycar.server;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.exception.UpdateException;
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.engine.identity.UserUpdater;
import org.bonitasoft.securitycar.server.Butler.RegisterTentative;

import groovy.transform.Synchronized;

/**
 * Goal of this class is to be as light as possible. it is called by the filter and the session.
 */
public class Butler {

    private static final int CST_MAXHTTPCALLSLOT = 6 * 24 * 7;

    private static final int CST_MAXTENTATIVESREGISTERED = 100;

    private static final int CST_NUMBEROFACCEPTABLESERROR = 5;

    private static Logger logger = Logger.getLogger(Butler.class.getName());
    public String logHeader = "---------------------  SecurityCar Buttler";

    public static Butler butler = new Butler();

    public static Butler getInstance() {
        return butler;
    }

    public boolean watchDog(Filter filter, ServletRequest httpRequest) {
        return true;
    }

    /**
     * keep track of the listener : we will ask it who is connected
     */
    public SecurityCarListenerSession mSecurityCarListenerSession;

    public void registerListener(SecurityCarListenerSession listener) {
        mSecurityCarListenerSession = listener;
    }
  
    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Register any tentative to connecct */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    /*
     * Attention to save all needed informations, but not so much to pay attention to the memory.
     * Key is a TenantId+UserName
     * Idea is:
     * - Save a record per userName. UserName may be known, or not, in the User Database. Example, a connection to "Tenant 1, Walter.john"
     * - if the connection is correct, remove the connection ONLY if the number of tentative is < 5
     */

    public Map<String, RegisterTentative> mapTentativesRegistration = new LinkedHashMap<>();
    /**
     * We want to keep track on tentatives
     * - save one record per slot. A slot is a 10 mn period, like 10:00 => 10:10
     * - keep one week slot maximum (so 6*24*7 records)
     */
    private static Map<String, SlotStatistics> mapTentativesSlot = new LinkedHashMap<>();

    /**
     * Each time a user connect, we go via this method
     * @param tenantId
     * @param userName
     * @param httpRequest
     * @param correct
     * @param identityAPI
     */
    public void addOneTentative(long tenantId, String userName, HttpServletRequest httpRequest, boolean correct, IdentityAPI identityAPI) {
        String keyRegister = tenantId + "#" + userName;
        RegisterTentative register = null;
        /// optimisation
        if (correct && ! mapTentativesRegistration.containsKey(keyRegister))
            return; // don't entrance the synchronization
        synchronized (mapTentativesRegistration) {
            mapTentativesRegistration.computeIfAbsent(keyRegister, val -> new RegisterTentative(tenantId, userName));
            register = mapTentativesRegistration.get(keyRegister);

            // Keep the information in a reasonable size             
            if (mapTentativesRegistration.size() > CST_MAXTENTATIVESREGISTERED) {
                String firstEntry = mapTentativesRegistration.keySet().iterator().next();
                mapTentativesRegistration.remove(firstEntry);
            }

            if (correct) {
                if (register.nbTentatives < CST_NUMBEROFACCEPTABLESERROR)
                    mapTentativesRegistration.remove(keyRegister);
                register.isFinalyCorrect = true;
                return; // end of the story here
            }
            register.nbTentatives++;
            register.remoteAddr = httpRequest.getRemoteAddr();
            register.remoteHost = httpRequest.getRemoteHost();

            register.lastTentativeTime = System.currentTimeMillis();
        }

        // keep the error in a slot then
        synchronized (mapTentativesSlot) {
            SlotStatistics st = getCurrentSlotStatistics(mapTentativesSlot);

            if (mapTentativesSlot.size() > CST_MAXHTTPCALLSLOT) {
                String firstEntry = mapTentativesSlot.keySet().iterator().next();
                mapTentativesSlot.remove(firstEntry);
            }
            // just add one hit on the slot
            st.nbHits++;
        }

        //-------------- Let's manage our strategy here after 3 tentative, slow down 30 seconds
        if (register.nbTentatives > 3)
            try {
                Thread.sleep(30 * 1000);
            } catch (InterruptedException e) {
            }

        // if there is more than X tentatives, disable the user
        if (register.nbTentatives > 6) {
            logger.info(logHeader + " Too Many tentatives(" + register.nbTentatives + "), disable the user [" + userName + "]");

            // invalidate the user
            UserUpdater userUpdater = new UserUpdater();
            userUpdater.setEnabled(false);
            try {
                User user = identityAPI.getUserByUserName(userName);
                register.userExists=true;
                identityAPI.updateUser(user.getId(), userUpdater);
                register.userIsDisabled = true;
            }catch(UpdateException ue) {
                // do nothing, user exist, update failed (already disabled?)
            } catch (Exception e) {
                // no log, maybe the user does not exist
                register.userExists = false;
            }
        }

    }

    public List<RegisterTentative> getTentatives() {
        return new ArrayList<RegisterTentative>(mapTentativesRegistration.values());
    }

    /**
     * return the last Tentative Slot
     * The map is a Linked map, so the first one is the older slot
     * @return
     */
    public Map<String, SlotStatistics> getTentativesSlot() {
        return mapTentativesSlot;
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Local class */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    /**
     * register a bad tentative for a user.
     * Register the number of tentative, and if finaly, it was correct.
     * In case of correct access, We keep this record only if the number of tentatives is > CST_NUMBEROFACCEPTABLESERROR
     */
    public static class RegisterTentative {

        public long tenantId;
        public String userName;
        public int nbTentatives;
        public boolean isFinalyCorrect;
        public long lastTentativeTime;
        public String remoteAddr;
        public String remoteHost;
        
        public boolean userIsDisabled= false;
        public boolean userExists=false;

        RegisterTentative(long tenantId, String userName) {
            this.tenantId = tenantId;
            this.userName = userName;
        }
        public Map<String,Object> getMap() {
            Map<String,Object> record = new HashMap<>();
            record.put("tenantid", tenantId);
            record.put("userName", userName);
            record.put("nbTentatives",  nbTentatives);
            record.put("isFinalyCorrect", isFinalyCorrect);
            record.put("lastTentativeTime", lastTentativeTime);
            record.put("remoteAddr", remoteAddr);
            record.put("remoteHost", remoteHost);
            record.put("userIsDisabled",userIsDisabled);
            record.put("userExist", userExists);

            return record;
        }
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Register HTTP to keep in mind the heavest URL                        */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    private static Map<String, SlotStatistics> mapHttpCallSlot = new LinkedHashMap<>();

    /**
     * register one HTTP Call
     * 
     * @param timeToExecute
     * @param httpRequest
     */
    public void registerOneHttpCall(long timeToExecute, HttpServletRequest httpRequest) {
        // get the correct timeSlot. There is one timeSlot per 10 mn

        synchronized (mapHttpCallSlot) {
            SlotStatistics st = getCurrentSlotStatistics(mapHttpCallSlot);

            if (mapHttpCallSlot.size() > CST_MAXHTTPCALLSLOT) {
                String firstEntry = mapHttpCallSlot.keySet().iterator().next();
                mapHttpCallSlot.remove(firstEntry);
            }

            st.nbHits++;
            st.sumTime += timeToExecute;
            // register the max number of thread working at this time
            ThreadPhoto threadPhoto = getThreadPhoto();
            if (threadPhoto.nbThreadTomcat > st.picThreadTomcat)
                st.picThreadTomcat = threadPhoto.nbThreadTomcat;
            // Make not a real senses for theses information
            if (threadPhoto.nbThreadWorkers > st.picThreadWorkers)
                st.picThreadWorkers = threadPhoto.nbThreadWorkers;
            if (threadPhoto.nbThreadTConnectors > st.picThreadConnectors)
                st.picThreadConnectors = threadPhoto.nbThreadTConnectors;

            // is this URL in the top 10 ?
            int range = st.getRange(timeToExecute);
            if (range < 10) {
                st.listSlotUrl.add(range, new SlotUrl(timeToExecute, httpRequest));
                if (st.listSlotUrl.size() > 10)
                    st.listSlotUrl = st.listSlotUrl.subList(0, 10);

            }
        }
    }

    /**
     * Return the HttpCall
     * The Map is a LinkedHashMap, so the first one is the older slot
     * @return
     */
    public Map<String, SlotStatistics> getMapHttpCallSlot() {
        return mapHttpCallSlot;
    }
    
    
    
    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* SlotStatistics */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    public static class SlotStatistics {

        public String slotNumber;
        public long slottime;
        public int nbHits = 0;
        public long sumTime = 0;
        public int picThreadTomcat = 0;
        public int picThreadWorkers = 0;
        public int picThreadConnectors = 0;

        public List<SlotUrl> listSlotUrl = new ArrayList<>();

        public SlotStatistics(String slotNumber, long slotTime) {
            this.slotNumber = slotNumber;
            this.slottime = slotTime;
        }

        public Map<String,Object> getMap() {
            Map<String,Object> record = new HashMap<>();
            record.put("slotNumber", slotNumber);
            record.put("slottime", slottime);
            record.put("nbHits",  nbHits);
            record.put("sumTime", sumTime);
            record.put("picThreadTomcat", picThreadTomcat);
            record.put("picThreadWorkers", picThreadWorkers);
            record.put("picThreadConnectors", picThreadConnectors);
            return record;
        }        
        /**
         * return the range of the execution in the listSlotUrl
         * 
         * @param timeToExecute
         * @return
         */
        public int getRange(long timeToExecute) {
            for (int i = 0; i < listSlotUrl.size(); i++) {
                if (timeToExecute > listSlotUrl.get(i).timeToExecute)
                    return i;
            }
            return listSlotUrl.size();
        }
    }

    /**
     * Calculate a SlotStatistic in the current SlotTime. Get it from the map or add in in the map
     * ATTENTION, the method is not synchronized and must be call in a protected environment
     * 
     * @param slotMap
     * @return
     */
    private SlotStatistics getCurrentSlotStatistics(Map<String, SlotStatistics> slotMap) {
        Calendar c = Calendar.getInstance();
        
        String slotNumber = String.valueOf(c.get(Calendar.YEAR)) 
                + String.format("%02d", c.get(Calendar.MONTH)) 
                + String.format("%02d", c.get(Calendar.DAY_OF_MONTH)) 
                + String.format("%02d", c.get(Calendar.HOUR_OF_DAY))
                + String.valueOf( (int) ( (Calendar.MINUTE) / 10 ) )
                +"0";
    
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        c.set(Calendar.MINUTE, 10 * ((int) c.get(Calendar.MINUTE) / 10));

        slotMap.computeIfAbsent(slotNumber, val -> new SlotStatistics(slotNumber, c.getTimeInMillis()));
        SlotStatistics st = slotMap.get(slotNumber);
        return st;
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* Slot URL */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    public static class SlotUrl {

        protected SlotUrl(long timeToExecute, HttpServletRequest httpRequest) {
            this.timeToExecute = timeToExecute;
            this.uri = httpRequest.getRequestURI();
            this.remoteAddr = httpRequest.getRemoteAddr();
            this.remoteHost = httpRequest.getRemoteHost();

        }

        public long timeToExecute = 0;
        public String uri;
        public String remoteAddr;
        public String remoteHost;
    }

    /* -------------------------------------------------------------------- */
    /*                                                                      */
    /* getThreadPhoto : via a ThreadDump, capture the number of thread      */
    /*                                                                      */
    /* -------------------------------------------------------------------- */

    public class ThreadPhoto {

        public int nbThreadTomcat = 0;
        public int nbThreadWorkers = 0;
        public int nbThreadTConnectors = 0;

    }

    private ThreadPhoto getThreadPhoto() {
        ThreadPhoto threadPhoto = new ThreadPhoto();

        Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
        for (Thread th : threadSet) {

            if (!th.isAlive())
                continue;
            // Bonita-Worker-1-10
            if (th.getName().startsWith("http-nio")) {
                threadPhoto.nbThreadTomcat++;
            }
            if (th.getName().startsWith("Bonita-workers")) {
                threadPhoto.nbThreadWorkers++;
            }
            if (th.getName().startsWith("C")) {
                threadPhoto.nbThreadTConnectors++;
            }
        }
        return threadPhoto;
    }
}
