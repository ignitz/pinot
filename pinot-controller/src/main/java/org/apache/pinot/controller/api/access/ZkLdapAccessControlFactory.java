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

import java.io.IOException;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
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
import org.apache.pinot.common.config.provider.AccessControlUserCache;
import org.apache.pinot.controller.ControllerConf;
import org.apache.pinot.controller.helix.core.PinotHelixResourceManager;
import org.apache.pinot.core.auth.ZkBasicAuthPrincipal;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.builder.TableNameBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Hybrid AccessControlFactory that uses LDAP for Authentication (verifying username/password)
 * and Zookeeper for Authorization (verifying permissions/roles).
 */
public class ZkLdapAccessControlFactory implements AccessControlFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(ZkLdapAccessControlFactory.class);

  private static final String PREFIX = "controller.access.control.ldap";
  private static final String LDAP_URL = PREFIX + ".url";
  private static final String LDAP_BASE_DN = PREFIX + ".baseDn";
  private static final String LDAP_SEARCH_FILTER = PREFIX + ".searchFilter"; // e.g. (uid={0})
  private static final String LDAP_BIND_DN = PREFIX + ".bindDn"; // Optional: for initial search
  private static final String LDAP_BIND_PASSWORD = PREFIX + ".bindPassword"; // Optional

  private AccessControl _accessControl;

  @Override
  public void init(PinotConfiguration pinotConfiguration, PinotHelixResourceManager pinotHelixResourceManager)
      throws IOException {
    // Initialize the ZK User ACL Config to ensure the cache is populated
    pinotHelixResourceManager.initUserACLConfig((ControllerConf) pinotConfiguration);
    AccessControlUserCache userCache = new AccessControlUserCache(pinotHelixResourceManager.getPropertyStore());
    _accessControl = new ZkLdapAccessControl(pinotConfiguration, userCache, pinotHelixResourceManager);
  }

  @Override
  public AccessControl create() {
    return _accessControl;
  }

  private static class ZkLdapAccessControl implements AccessControl {
    private final String _ldapUrl;
    private final String _baseDn;
    private final String _searchFilter;
    private final String _bindDn;
    private final String _bindPassword;
    private final AccessControlUserCache _userCache;
    private final PinotHelixResourceManager _helixResourceManager;

    public ZkLdapAccessControl(PinotConfiguration config, AccessControlUserCache userCache,
        PinotHelixResourceManager helixResourceManager) {
      _ldapUrl = config.getProperty(LDAP_URL);
      _baseDn = config.getProperty(LDAP_BASE_DN);
      _searchFilter = config.getProperty(LDAP_SEARCH_FILTER, "(uid={0})");
      _bindDn = config.getProperty(LDAP_BIND_DN);
      _bindPassword = config.getProperty(LDAP_BIND_PASSWORD);
      _userCache = userCache;
      _helixResourceManager = helixResourceManager;

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
      Optional<ZkBasicAuthPrincipal> principal = getPrincipal(httpHeaders);
      return principal.filter(
          p -> p.hasTable(TableNameBuilder.extractRawTableName(tableName))
              && p.hasPermission(Objects.toString(accessType))).isPresent();
    }

    @Override
    public boolean hasAccess(AccessType accessType, HttpHeaders httpHeaders, String endpointUrl) {
      return getPrincipal(httpHeaders).isPresent();
    }

    @Override
    public AuthWorkflowInfo getAuthWorkflowInfo() {
      return new AuthWorkflowInfo(AccessControl.WORKFLOW_BASIC);
    }

    /**
     * Authenticates via LDAP, then looks up the user in ZK to return a Principal with permissions.
     */
    private Optional<ZkBasicAuthPrincipal> getPrincipal(HttpHeaders headers) {
      if (headers == null) {
        return Optional.empty();
      }
      List<String> authHeaders = headers.getRequestHeader(HttpHeaders.AUTHORIZATION);
      if (authHeaders == null || authHeaders.isEmpty()) {
        return Optional.empty();
      }

      for (String authHeader : authHeaders) {
        String username = BasicAuthUtils.extractUsername(authHeader);
        String password = BasicAuthUtils.extractPassword(authHeader);

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
          continue;
        }

        // 1. Authenticate with LDAP
        if (authenticateLdap(username, password)) {
          // 2. If Auth successful, fetch User Config from ZK to get permissions
          // Note: We create a ZkBasicAuthPrincipal manually or retrieve it.
          // Since ZkBasicAuthPrincipal is constructed from UserConfig, we need to find the UserConfig
          // for this username.

          // Re-build the name2principal map from cache.
          // Ideally this should be optimized, but following ZkBasicAuthAccessControlFactory pattern:
          Map<String, ZkBasicAuthPrincipal> name2principal =
              org.apache.pinot.core.auth.BasicAuthUtils.extractBasicAuthPrincipals(
                  _userCache.getAllControllerUserConfig())
              .stream().collect(Collectors.toMap(ZkBasicAuthPrincipal::getName, p -> p));

          if (name2principal.containsKey(username)) {
            return Optional.of(name2principal.get(username));
          } else {
            // User authenticated in LDAP but not found in Pinot ZK.
            LOGGER.info("User '{}' authenticated via LDAP but not found in Pinot ZK. Provisioning new user...",
                username);
            return provisionUser(username);
          }
        }
      }
      return Optional.empty();
    }

    private Optional<ZkBasicAuthPrincipal> provisionUser(String username) {
      try {
        // Create user for CONTROLLER with USER role, READ permission, and NO tables
        // (explicit dummy table to avoid wildcard)
        org.apache.pinot.spi.config.user.UserConfig controllerUser =
            new org.apache.pinot.spi.config.user.UserConfig(username, "dummy",
                org.apache.pinot.spi.config.user.ComponentType.CONTROLLER.name(),
                org.apache.pinot.spi.config.user.RoleType.USER.name(),
                Collections.singletonList("__none__"), null,
                Collections.singletonList(org.apache.pinot.spi.config.user.AccessType.READ));
        _helixResourceManager.addUser(controllerUser);

        // Create user for BROKER with USER role, READ permission, and NO tables
        org.apache.pinot.spi.config.user.UserConfig brokerUser =
            new org.apache.pinot.spi.config.user.UserConfig(username, "dummy",
                org.apache.pinot.spi.config.user.ComponentType.BROKER.name(),
                org.apache.pinot.spi.config.user.RoleType.USER.name(),
                Collections.singletonList("__none__"), null,
                Collections.singletonList(org.apache.pinot.spi.config.user.AccessType.READ));
        _helixResourceManager.addUser(brokerUser);

        LOGGER.info("Successfully provisioned new user '{}' with USER role and restricted permissions.", username);

        // Return a temporary principal so they don't have to wait for cache refresh/retry
        return Optional.of(new ZkBasicAuthPrincipal(username, "dummy", "dummy",
            org.apache.pinot.spi.config.user.ComponentType.CONTROLLER.name(),
            org.apache.pinot.spi.config.user.RoleType.USER.name(),
            Collections.singleton("__none__"), Collections.emptySet(),
            Collections.singleton("READ")));
      } catch (Exception e) {
        LOGGER.error("Failed to provision user '{}' in ZK.", username, e);
        return Optional.empty();
      }
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
