/* SpagoBI, the Open Source Business Intelligence suite

 * Copyright (C) 2012 Engineering Ingegneria Informatica S.p.A. - SpagoBI Competency Center
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0, without the "Incompatible With Secondary Licenses" notice.
 * If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package it.eng.spagobi.commons.filters;

import it.eng.spago.base.Constants;
import it.eng.spago.base.RequestContainer;
import it.eng.spago.base.SessionContainer;
import it.eng.spago.security.DefaultCipher;
import it.eng.spago.security.IEngUserProfile;
import it.eng.spagobi.commons.bo.UserProfile;
import it.eng.spagobi.commons.utilities.ChannelUtilities;
import it.eng.spagobi.commons.utilities.GeneralUtilities;
import it.eng.spagobi.commons.utilities.StringUtilities;
import it.eng.spagobi.services.common.SsoServiceFactory;
import it.eng.spagobi.services.common.SsoServiceInterface;
import it.eng.spagobi.services.security.bo.SpagoBIUserProfile;
import it.eng.spagobi.services.security.service.ISecurityServiceSupplier;
import it.eng.spagobi.services.security.service.SecurityServiceSupplierFactory;
import it.eng.spagobi.tenant.Tenant;
import it.eng.spagobi.tenant.TenantManager;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @author Zerbetto (davide.zerbetto@eng.it)
 *
 *         This filter tries to build the user profile object, using the user identifier
 */

public class ProfileFilter implements Filter {

	private static transient Logger logger = Logger.getLogger(ProfileFilter.class);

	@Override
	public void destroy() {
		// do nothing
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		// logger.debug("IN");
		try {
			if (request instanceof HttpServletRequest) {
				HttpServletRequest httpRequest = (HttpServletRequest) request;
				HttpSession session = httpRequest.getSession();

				RequestContainer requestContainer = (RequestContainer) session.getAttribute(Constants.REQUEST_CONTAINER);
				if (requestContainer == null) {
					// RequestContainer does not exists yet (maybe it is the
					// first call to Spago)
					// initializing Spago objects (user profile object must
					// be put into PermanentContainer)
					requestContainer = new RequestContainer();
					SessionContainer sessionContainer = new SessionContainer(true);
					requestContainer.setSessionContainer(sessionContainer);
					session.setAttribute(Constants.REQUEST_CONTAINER, requestContainer);
				}
				SessionContainer sessionContainer = requestContainer.getSessionContainer();
				SessionContainer permanentSession = sessionContainer.getPermanentContainer();
				IEngUserProfile profile = (IEngUserProfile) permanentSession.getAttribute(IEngUserProfile.ENG_USER_PROFILE);
				if (profile == null) {
					// in case the profile does not exist, creates a new one
					logger.debug("User profile not found in session, creating a new one and putting in session....");

					String userId = null;

					if (ChannelUtilities.isWebRunning() && !GeneralUtilities.isSSOEnabled()) {
						// case of installation as web application without SSO
						try {
							userId = getUserIdInWebModeWithoutSSO(httpRequest);
						} catch (Exception e) {
							logger.error("Error authenticating user", e);
							httpRequest.getRequestDispatcher("/WEB-INF/jsp/commons/silentLoginFailed.jsp").forward(request, response);
							return;
						}
					} else {
						// case of installation as portlet application and/or
						// with SSO
						userId = getUserIdWithSSO(httpRequest);
					}

					logger.debug("User id = " + userId);
					if (userId != null && !userId.trim().equals("")) {
						profile = GeneralUtilities.createNewUserProfile(userId, httpRequest.getRemoteAddr());
						permanentSession.setAttribute(IEngUserProfile.ENG_USER_PROFILE, profile);
						session.setAttribute(IEngUserProfile.ENG_USER_PROFILE, profile);
					} else {
						logger.debug("User identifier not found.");
					}

				} else {
					// in case the profile is different, creates a new one
					// and overwrites the existing
					/*
					 * if (!((UserProfile) profile).getUserUniqueIdentifier().toString ().equals(userId)) {logger.debug(
					 * "Different user profile found in session, creating a new one and replacing in session...." ); profile =
					 * GeneralUtilities.createNewUserProfile(userId); permanentSession .setAttribute(IEngUserProfile.ENG_USER_PROFILE, profile); } else {
					 * logger.debug("User profile object for user [" + userId + "] already existing in session, ok"); }
					 */
				}

				if (profile != null) {
					manageTenant(profile);
				}

				chain.doFilter(request, response);
			}
		} catch (Exception e) {
			logger.error("Error while processing request", e);
		} finally {
			// since TenantManager uses a ThreadLocal, we must clean after
			// request processed in each case
			TenantManager.unset();
		}
	}

	private String getUserIdInWebModeWithoutSSO(HttpServletRequest httpRequest) {
		UsernamePasswordCredentials credentials = this.findUserCredentials(httpRequest);
		if (credentials != null) {
			logger.debug("User credentials found.");
			if (!httpRequest.getMethod().equalsIgnoreCase("POST")) {
				logger.error("Request method is not POST!!!");
				throw new InvalidMethodException();
			}
			logger.debug("Authenticating user ...");
			try {
				this.authenticate(credentials);
				logger.debug("User authenticated");
				httpRequest.getSession().setAttribute(SsoServiceInterface.SILENT_LOGIN, Boolean.TRUE);
			} catch (Throwable t) {
				logger.error("Authentication failed", t);
				throw new SilentAuthenticationFailedException();
			}
		} else {
			logger.debug("User credentials not found.");
		}

		String userId = credentials != null ? credentials.getUserName() : null;
		return userId;
	}

	private void authenticate(UsernamePasswordCredentials credentials) throws Throwable {
		logger.debug("IN: userId = " + credentials.getUserName());
		try {
			ISecurityServiceSupplier supplier = SecurityServiceSupplierFactory.createISecurityServiceSupplier();
			SpagoBIUserProfile profile = supplier.checkAuthentication(credentials.getUserName(), credentials.getPassword());
			if (profile == null) {
				logger.error("Authentication failed for user " + credentials.getUserName());
				throw new SecurityException("Authentication failed");
			}
		} catch (Throwable t) {
			logger.error("Error while authenticating userId = " + credentials.getUserName(), t);
			throw t;
		} finally {
			logger.debug("OUT");
		}

	}

	private UsernamePasswordCredentials findUserCredentials(HttpServletRequest httpRequest) {
		UsernamePasswordCredentials toReturn = null;
		String userId = httpRequest.getParameter(SsoServiceInterface.USER_NAME_REQUEST_PARAMETER.toLowerCase());
		logger.debug("Request parameter " + SsoServiceInterface.USER_NAME_REQUEST_PARAMETER.toLowerCase() + " is [" + userId + "]");
		if (userId == null) {
			userId = httpRequest.getParameter(SsoServiceInterface.USER_NAME_REQUEST_PARAMETER.toUpperCase());
			logger.debug("Request parameter " + SsoServiceInterface.USER_NAME_REQUEST_PARAMETER.toUpperCase() + " is [" + userId + "]");
		}
		String password = httpRequest.getParameter(SsoServiceInterface.PASSWORD_REQUEST_PARAMETER.toLowerCase());
		if (password == null) {
			password = httpRequest.getParameter(SsoServiceInterface.PASSWORD_REQUEST_PARAMETER.toUpperCase());
		}
		if (!StringUtilities.isEmpty(userId) && !StringUtilities.isNull(password)) {
			logger.debug("Read credentials from request: user id is [" + userId + "]");
			String passwordMode = httpRequest.getParameter(SsoServiceInterface.PASSWORD_MODE_REQUEST_PARAMETER);
			if (!StringUtilities.isEmpty(passwordMode) && passwordMode.equalsIgnoreCase(SsoServiceInterface.PASSWORD_MODE_ENCRYPTED)) {
				logger.debug("Password mode is encrypted. Decripting password...");
				DefaultCipher chiper = new DefaultCipher();
				password = chiper.decrypt(password);
				logger.debug("Password decrypted.");
			}
			toReturn = new UsernamePasswordCredentials(userId, password);
		}
		return toReturn;
	}

	private void manageTenant(IEngUserProfile profile) {
		UserProfile userProfile = (UserProfile) profile;
		// retrieving tenant id
		String tenantId = userProfile.getOrganization();
		logger.debug("Retrieved tenantId from user profile object : [" + tenantId + "]");
		// putting tenant id on thread local
		Tenant tenant = new Tenant(tenantId);
		TenantManager.setTenant(tenant);
		logger.debug("Tenant [" + tenantId + "] set into TenantManager");
	}

	@Override
	public void init(FilterConfig config) throws ServletException {
		// do nothing
		logger.debug("IN");
		logger.debug("OUT");
	}

	/**
	 * Finds the user identifier from http request or from SSO system (by the http request in input). Use the SsoServiceInterface for read the userId in all
	 * cases, if SSO is disabled use FakeSsoService. Check spagobi_sso.xml
	 *
	 * @param request
	 *            The http request
	 *
	 * @return the current user unique identified
	 *
	 * @throws Exception
	 *             in case the SSO is enabled and the user identifier specified on http request is different from the SSO detected one.
	 */
	private static String getUserIdWithSSO(HttpServletRequest request) throws Exception {
		logger.debug("IN");
		String userId = null;
		try {
			SsoServiceInterface userProxy = SsoServiceFactory.createProxyService();
			userId = userProxy.readUserIdentifier(request);
		} finally {
			logger.debug("OUT");
		}
		return userId;
	}

	public class SilentAuthenticationFailedException extends RuntimeException {

	}

	public class InvalidMethodException extends RuntimeException {

	}

}
