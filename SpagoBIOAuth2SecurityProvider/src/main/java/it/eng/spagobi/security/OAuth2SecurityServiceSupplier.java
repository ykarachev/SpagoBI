/* SpagoBI, the Open Source Business Intelligence suite

 * Copyright (C) 2012 Engineering Ingegneria Informatica S.p.A. - SpagoBI Competency Center
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0, without the "Incompatible With Secondary Licenses" notice.
 * If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package it.eng.spagobi.security;

import it.eng.spagobi.commons.SingletonConfig;
import it.eng.spagobi.security.oauth2.OAuth2Client;
import it.eng.spagobi.security.oauth2.OAuth2Config;
import it.eng.spagobi.services.security.bo.SpagoBIUserProfile;
import it.eng.spagobi.services.security.service.ISecurityServiceSupplier;
import it.eng.spagobi.utilities.exceptions.SpagoBIRuntimeException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.log4j.LogMF;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

/**
 * @author Alessandro Daniele (alessandro.daniele@eng.it)
 *
 */
public class OAuth2SecurityServiceSupplier implements ISecurityServiceSupplier {
	static private Logger logger = Logger.getLogger(OAuth2SecurityServiceSupplier.class);

	@Override
	public SpagoBIUserProfile createUserProfile(String userUniqueIdentifier, String remoteAddr) {
		logger.debug("IN");

		SpagoBIUserProfile profile;
		try {
			Properties config = OAuth2Config.getInstance().getConfig();

			OAuth2Client oauth2Client = new OAuth2Client();

			HttpClient httpClient = oauth2Client.getHttpClient();

			// We call the OAuth2 provider to get user's info
			GetMethod httpget = new GetMethod(config.getProperty("USER_INFO_URL") + "?access_token=" + userUniqueIdentifier);
			final String authorizationType = config.getProperty("USER_INFO_AUTHORIZATION_TYPE", "Bearer");
			httpget.setRequestHeader("Authorization", authorizationType+ " " + userUniqueIdentifier);
			int statusCode = httpClient.executeMethod(httpget);
			byte[] response = httpget.getResponseBody();
			if (statusCode != HttpStatus.SC_OK) {
				logger.error("Error while getting user information from OAuth2 provider: server returned statusCode = " + statusCode);
				LogMF.error(logger, "Server response is:\n{0}", new Object[] { new String(response) });
				throw new SpagoBIRuntimeException("Error while getting user information from OAuth2 provider: server returned statusCode = " + statusCode);
			}

			String responseStr = new String(response);
			LogMF.debug(logger, "Server response is:\n{0}", responseStr);
			JSONObject jsonObject = new JSONObject(responseStr);
			final String userIdKey = config.getProperty("USER_INFO_ID_KEY", "id");
			logger.debug("User id key is [" + userIdKey + "]");
			String userId = jsonObject.getString(userIdKey);
			logger.debug("User id is [" + userId + "]");

			final String userNameKey = config.getProperty("USER_INFO_NAME_KEY", "displayName");
			logger.debug("User name key is [" + userNameKey + "]");
			String userName = jsonObject.getString(userNameKey);
			logger.debug("User name is [" + userName + "]");

			profile = new SpagoBIUserProfile();
			profile.setUniqueIdentifier(userUniqueIdentifier); // The OAuth2 access token
			profile.setUserId(userId);
			profile.setUserName(userName);
			profile.setOrganization("SPAGOBI");

			/*
			 * If the user's email is the same as the owner of the application (as configured in the oauth2.config.properties file) we consider him as the
			 * superadmin
			 */
			String adminEmail = config.getProperty("ADMIN_EMAIL");
			final String emailKey = config.getProperty("USER_INFO_EMAIL_KEY", "email");
			logger.debug("User email key is [" + emailKey + "]");
			String email = jsonObject.getString(emailKey);
			profile.setIsSuperadmin(email.equalsIgnoreCase(adminEmail));

			final String rolesKey = config.getProperty("USER_INFO_ROLES_KEY", "roles");
			logger.debug("User roles key is [" + rolesKey + "]");

			final boolean parseRoles = config.getProperty("USER_INFO_PARSE_ROLES", "FALSE").equalsIgnoreCase("true");
			final String rolesDelimiter = config.getProperty("USER_INFO_ROLES_DELIMITER", ",");
			List<String> roles = new ArrayList<String>();
			if (parseRoles) {
				for(String role : jsonObject.getString(rolesKey).split(rolesDelimiter)) {
					if (!role.isEmpty()) {
						roles.add(role);
					}
				}
			} else {
				final JSONArray jsonRolesArray = jsonObject.getJSONArray(rolesKey);
				for (int i = 0; i < jsonRolesArray.length(); i++) {
					final String name = jsonRolesArray.getJSONObject(i).getString("name");
					if (!name.equalsIgnoreCase("provider") && !name.equalsIgnoreCase("purchaser"))
						roles.add(name);
				}
			}

			// Read roles

			// If no roles were found, search for roles in the organizations
			if (roles.size() == 0 && !jsonObject.isNull("organizations")) {
				JSONArray organizations = jsonObject.getJSONArray("organizations");

				if (organizations != null) { // TODO: more than one organization
					// For each organization
					for (int i = 0; i < organizations.length() && roles.size() == 0; i++) {
						String organizationName = organizations.getJSONObject(i).getString("name");
						final JSONArray jsonRolesArray = organizations.getJSONObject(i).getJSONArray("roles");

						// For each role in the current organization
						for (int k = 0; k < jsonRolesArray.length(); k++) {
							final String name = jsonRolesArray.getJSONObject(k).getString("name");

							if (!name.equalsIgnoreCase("provider") && !name.equalsIgnoreCase("purchaser")) {
								profile.setOrganization(organizationName);
								roles.add(name);
							}
						}
					}
				}
			}


			final String allowedIp = config.getProperty("ALLOWED_IP");
			if (allowedIp != null) {
				final List<String> ipRanges = Arrays.asList(StringUtils.split(allowedIp, ","));
				checkIPRange(remoteAddr, userName, ipRanges);
			}

			final String allowedIpKey = config.getProperty("USER_INFO_ALLOWED_IP_KEY");
			if (allowedIpKey != null) {
				try {
					List<String> ipRanges = Arrays.asList(StringUtils.split(jsonObject.getString(allowedIpKey), ","));
					checkIPRange(remoteAddr, userName, ipRanges);
				} catch (Exception e) {
					// NO-OP
				}
			}

			if (roles.size() == 0) { // Add the default role
				roles.add(SingletonConfig.getInstance().getConfigValue("SPAGOBI.SECURITY.DEFAULT_ROLE_ON_SIGNUP"));
			}

			String[] rolesString = new String[roles.size()];
			profile.setRoles(roles.toArray(rolesString));

			final String roleKey = config.getProperty("USER_INFO_ROLE_KEY", "role");
			logger.debug("User role key is [" + roleKey + "]");

			String role = null;
			try {
				role = jsonObject.getString(roleKey);
				logger.debug("User name is [" + userName + "]");
			} catch (Exception e) {
				logger.debug("Attribute " + roleKey + " not found in JSON response");
			}


			HashMap<String, String> attributes = new HashMap<String, String>();
			attributes.put("userUniqueIdentifier", userUniqueIdentifier);
			attributes.put("userId", userId);
			attributes.put("username", userName);
			attributes.put("email", email);
			if (role != null) {
				attributes.put("role", role);
			}
			profile.setAttributes(attributes);

			logger.debug("Profile attributes " + attributes.toString());

			return profile;
		} catch (Exception e) {
			throw new SpagoBIRuntimeException("Error while trying to read JSon object containing user profile's information from OAuth2 provider", e);
		} finally {
			logger.debug("OUT");
		}
	}

	private void checkIPRange(String remoteAddr, String userName, Iterable<String> ipRanges) {
		boolean ipCheckSuccess = false;
		Iterator<String> iterator = ipRanges.iterator();
		while(iterator.hasNext() && !ipCheckSuccess) {
			final String ipRange = iterator.next();
			try {
				final SubnetUtils utils = new SubnetUtils(ipRange);
				utils.setInclusiveHostCount(true);
				ipCheckSuccess |= utils.getInfo().isInRange(remoteAddr);
			} catch (Exception e) {
				logger.warn("Error", e);
			}
		}

		if (!ipCheckSuccess) {
			logger.warn("Login '" + userName + "' from '" + remoteAddr + "' is not allowed");
			throw new RuntimeException("Invalid remote address");
		}
	}

	@Override
	public SpagoBIUserProfile checkAuthentication(String userId, String psw) {
		OAuth2Client oauth2Client = new OAuth2Client();
		return createUserProfile(oauth2Client.getAccessToken(userId, psw), null);
	}

	@Override
	public SpagoBIUserProfile checkAuthenticationWithToken(String userId, String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean checkAuthorization(String userId, String function) {
		// TODO Auto-generated method stub
		return false;
	}

}
