/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.controller.api.access;

import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.ws.rs.core.HttpHeaders;
import org.apache.commons.lang3.StringUtils;
import org.apache.pinot.common.auth.BasicAuthUtils;
import org.apache.pinot.controller.helix.core.PinotHelixResourceManager;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * LDAP Authentication based on Pinot Controller UI.
 * Configures LDAP access control using JNDI.
 */
public class LdapAccessControlFactory implements AccessControlFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(LdapAccessControlFactory.class);

  private static final String PREFIX = "controller.access.control.ldap";
  private static final String LDAP_URL = PREFIX + ".url";
  private static final String LDAP_BASE_DN = PREFIX + ".baseDn";
  private static final String LDAP_SEARCH_FILTER = PREFIX + ".searchFilter"; // e.g. (uid={0})
  private static final String LDAP_BIND_DN = PREFIX + ".bindDn"; // Optional: for initial search
  private static final String LDAP_BIND_PASSWORD = PREFIX + ".bindPassword"; // Optional

  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration pinotConfiguration, PinotHelixResourceManager pinotHelixResourceManager) {
    _accessControl = new LdapAccessControl(pinotConfiguration);
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  private static class LdapAccessControl implements AccessControl {
    private final String _ldapUrl;
    private final String _baseDn;
    private final String _searchFilter;
    private final String _bindDn;
    private final String _bindPassword;

    public LdapAccessControl(PinotConfiguration config) {
      _ldapUrl = config.getProperty(LDAP_URL);
      _baseDn = config.getProperty(LDAP_BASE_DN);
      _searchFilter = config.getProperty(LDAP_SEARCH_FILTER, "(uid={0})");
      _bindDn = config.getProperty(LDAP_BIND_DN);
      _bindPassword = config.getProperty(LDAP_BIND_PASSWORD);

      if (StringUtils.isBlank(_ldapUrl) || StringUtils.isBlank(_baseDn)) {
        LOGGER.warn("LDAP Access Control configured but missing URL or Base DN. Authentication will fail.");
      }
    }

    @Override
    public boolean protectAnnotatedOnly() {
      return false;
    }

    @Override
    public boolean hasAccess(String tableName, AccessType accessType, HttpHeaders httpHeaders, String endpointUrl) {
      // For now, allow all operations if authenticated.
      // Finer grained authorization can be added by mapping LDAP groups to roles.
      return authenticate(httpHeaders);
    }

    @Override
    public boolean hasAccess(AccessType accessType, HttpHeaders httpHeaders, String endpointUrl) {
      return authenticate(httpHeaders);
    }

    @Override
    public AuthWorkflowInfo getAuthWorkflowInfo() {
      return new AuthWorkflowInfo(AccessControl.WORKFLOW_BASIC);
    }

    private boolean authenticate(HttpHeaders headers) {
      if (headers == null) {
        return false;
      }
      List<String> authHeaders = headers.getRequestHeader(HttpHeaders.AUTHORIZATION);
      if (authHeaders == null || authHeaders.isEmpty()) {
        return false;
      }

      for (String authHeader : authHeaders) {
        String username = BasicAuthUtils.extractUsername(authHeader);
        String password = BasicAuthUtils.extractPassword(authHeader);

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
          continue;
        }

        if (authenticateLdap(username, password)) {
          return true;
        }
      }
      return false;
    }

    private boolean authenticateLdap(String username, String password) {
      if (_ldapUrl == null) {
        return false;
      }

      DirContext ctx = null;
      try {
        // 1. Bind as manager (or anonymous) to search for user DN
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, _ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        if (_bindDn != null) {
          env.put(Context.SECURITY_PRINCIPAL, _bindDn);
          env.put(Context.SECURITY_CREDENTIALS, _bindPassword);
        }

        ctx = new InitialDirContext(env);

        // 2. Search for the user
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = _searchFilter.replace("{0}", username);
        NamingEnumeration<SearchResult> results = ctx.search(_baseDn, filter, searchControls);

        if (!results.hasMore()) {
          LOGGER.warn("User not found in LDAP: {}", username);
          return false;
        }

        SearchResult result = results.next();
        String userDn = result.getNameInNamespace();

        // Close first context
        ctx.close();

        // 3. Bind as the user to verify password
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        ctx = new InitialDirContext(env);
        return true;
      } catch (NamingException e) {
        LOGGER.error("LDAP authentication failed for user: {}", username, e);
        return false;
      } finally {
        if (ctx != null) {
          try {
            ctx.close();
          } catch (NamingException e) {
            // ignore
          }
        }
      }
    }
  }
}
