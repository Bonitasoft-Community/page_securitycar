
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.text.SimpleDateFormat;
import java.util.logging.Logger;

import org.json.simple.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.JSONValue;


 
import org.bonitasoft.engine.identity.User;
import org.bonitasoft.console.common.server.page.PageContext
import org.bonitasoft.console.common.server.page.PageController
import org.bonitasoft.console.common.server.page.PageResourceProvider

import org.bonitasoft.engine.api.TenantAPIAccessor;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.engine.api.CommandAPI;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.api.IdentityAPI;

import org.bonitasoft.securitycar.SecurityCarAPI;


public class Actions {

	private static Logger logger= Logger.getLogger("org.bonitasoft.custompage.securitycar.groovy");
	
	
	public static Index.ActionAnswer doAction(HttpServletRequest request, String paramJsonSt, HttpServletResponse response, PageResourceProvider pageResourceProvider, PageContext pageContext) {
				
		logger.info("#### securitycar:Actions start");
		Index.ActionAnswer actionAnswer = new Index.ActionAnswer();	
		try {
			String action=request.getParameter("action");
			logger.info("#### securitycar:Actions   action is["+action+"] !");
			if (action==null || action.length()==0 )
			{
				actionAnswer.isManaged=false;
				logger.info("#### securitycar:Actions  END No Actions");
				return actionAnswer;
			}
			actionAnswer.isManaged=true;
			
			APISession session = pageContext.getApiSession();
			
			ProcessAPI processAPI = TenantAPIAccessor.getProcessAPI(session);
			IdentityAPI identityApi = TenantAPIAccessor.getIdentityAPI(session);
			
			SecurityCarAPI securityCarAPI = new SecurityCarAPI();
			
			HashMap<String,Object> answer = null;
			if ("init".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.getStatus( securityParameter, identityApi).toMap());
            }
			else if ("refresh".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.getStatus( securityParameter, identityApi).toMap());
            }
			else if ("usersoperation".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.getUsersOperations( securityParameter, identityApi).toMap() );
            }
			else if ("deactivate".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.setUserEnable( securityParameter, false, identityApi).toMap() );
            }	
			else if ("activate".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.setUserEnable( securityParameter, true, identityApi).toMap() );
            }
			else if ("disconnect".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.disconnect( securityParameter, identityApi).toMap() );
            }
			else if ("resettentative".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.resetTentative(securityParameter, identityApi).toMap() );
            }
			else if ("resetpassword".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.resetPassword(securityParameter, identityApi).toMap() );
            }
			
			else if ("saveParameters".equals(action))
			{
				SecurityCarAPI.SecurityParameter securityParameter = SecurityCarAPI.SecurityParameter.getInstanceFromJsonSt(session, paramJsonSt );				
				actionAnswer.setResponse( securityCarAPI.saveParameters( securityParameter ).toMap() );
            }
			else
			{
				logger.severe("#### securitycar:Actions ActionUnknown["+action+"]");				
			}
			logger.info("#### securitycar:Actions END action["+action+"]responseMap ="+actionAnswer.responseMap.size());
			return actionAnswer;
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			String exceptionDetails = sw.toString();
			logger.severe("#### securitycar:Actions Exception ["+e.toString()+"] at "+exceptionDetails);
			actionAnswer.isResponseMap=true;
			actionAnswer.responseMap.put("Error", "securitycar:Actions Exception ["+e.toString()+"] at "+exceptionDetails);
			return actionAnswer;
		}
	}

}
