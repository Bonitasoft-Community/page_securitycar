# page_securitycar

This page is an administrative page to manage users, and detect attack on user. An attack is define by a number of tentative to access an user account.
After X tentatives, the user account is disabled for security reason.

Administator can see:
* the last attack on user
* see who are currently connected
* can manage user proviledge, like enable/disable an user, reset the password.

How to install the function?
The function is compose by a custom page and filters. 
1. Install filters
	Stop the Bonita Engine
	Copy the library SecurityCar.jar under the web application library (<TOMCAT>/webapps/bonita/WEBèINF/lib for Tomcat for example)
	Modify the web.xml, adding
	
	 <listener>
		<listener-class>org.bonitasoft.securitycar.listener.SecurityCarListenerSession</listener-class>
	</listener>
