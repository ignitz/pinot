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
package org.apache.pinot.broker.broker;

import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Set;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.ws.rs.NotAuthorizedException;
import org.apache.commons.lang3.StringUtils;
import org.apache.helix.store.zk.ZkHelixPropertyStore;
import org.apache.helix.zookeeper.datamodel.ZNRecord;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.common.auth.BasicAuthUtils;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * LDAP Authentication for Pinot Broker.
 * Configures LDAP access control using JNDI.
 */
public class LdapAccessControlFactory extends AccessControlFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(LdapAccessControlFactory.class);

  private static final String PREFIX = "broker.access.control.ldap";
  private static final String LDAP_URL = PREFIX + ".url";
  private static final String LDAP_BASE_DN = PREFIX + ".baseDn";
  private static final String LDAP_SEARCH_FILTER = PREFIX + ".searchFilter"; // e.g. (uid={0})
  private static final String LDAP_BIND_DN = PREFIX + ".bindDn"; // Optional: for initial search
  private static final String LDAP_BIND_PASSWORD = PREFIX + ".bindPassword"; // Optional

  private AccessControl _accessControl;

  public LdapAccessControlFactory() {
    // left blank
  }

  @Override
  public void init(PinotConfiguration configuration, ZkHelixPropertyStore<ZNRecord> propertyStore) {
    _accessControl = new LdapAccessControl(configuration);
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
    public AuthorizationResult authorize(RequesterIdentity requesterIdentity) {
      return authorize(requesterIdentity, (BrokerRequest) null);
    }

    @Override
    public AuthorizationResult authorize(RequesterIdentity requesterIdentity, BrokerRequest brokerRequest) {
      if (brokerRequest == null || !brokerRequest.isSetQuerySource() || !brokerRequest.getQuerySource()
          .isSetTableName()) {
        // No table restrictions? Check authentication only.
        if (!checkAuthentication(requesterIdentity)) {
          throw new NotAuthorizedException("LDAP");
        }
        return TableAuthorizationResult.success();
      }

      return authorize(requesterIdentity, Collections.singleton(brokerRequest.getQuerySource().getTableName()));
    }

    @Override
    public TableAuthorizationResult authorize(RequesterIdentity requesterIdentity, Set<String> tables) {
      if (!checkAuthentication(requesterIdentity)) {
        throw new NotAuthorizedException("LDAP");
      }
      return TableAuthorizationResult.success();
    }

    private boolean checkAuthentication(RequesterIdentity requesterIdentity) {
      Collection<String> tokens = AccessControlFactory.extractAuthorizationTokens(requesterIdentity);
      if (tokens == null || tokens.isEmpty()) {
        return false;
      }

      for (String token : tokens) {
        String username = BasicAuthUtils.extractUsername(token);
        String password = BasicAuthUtils.extractPassword(token);

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
