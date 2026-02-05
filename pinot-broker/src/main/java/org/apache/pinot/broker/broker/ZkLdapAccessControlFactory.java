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
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.ws.rs.NotAuthorizedException;
import org.apache.commons.lang3.StringUtils;
import org.apache.helix.AccessOption;
import org.apache.helix.store.zk.ZkHelixPropertyStore;
import org.apache.helix.zookeeper.datamodel.ZNRecord;
import org.apache.pinot.broker.api.AccessControl;
import org.apache.pinot.common.auth.BasicAuthUtils;
import org.apache.pinot.common.config.provider.AccessControlUserCache;
import org.apache.pinot.common.request.BrokerRequest;
import org.apache.pinot.common.utils.config.AccessControlUserConfigUtils;
import org.apache.pinot.core.auth.ZkBasicAuthPrincipal;
import org.apache.pinot.spi.auth.AuthorizationResult;
import org.apache.pinot.spi.auth.TableAuthorizationResult;
import org.apache.pinot.spi.auth.broker.RequesterIdentity;
import org.apache.pinot.spi.config.user.AccessType;
import org.apache.pinot.spi.config.user.ComponentType;
import org.apache.pinot.spi.config.user.RoleType;
import org.apache.pinot.spi.config.user.UserConfig;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.apache.pinot.spi.utils.builder.TableNameBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Hybrid AccessControlFactory for Pinot Broker that uses LDAP for Authentication
 * and Zookeeper for Authorization.
 */
public class ZkLdapAccessControlFactory extends AccessControlFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(ZkLdapAccessControlFactory.class);

  private static final String PREFIX = "broker.access.control.ldap";
  private static final String LDAP_URL = PREFIX + ".url";
  private static final String LDAP_BASE_DN = PREFIX + ".baseDn";
  private static final String LDAP_SEARCH_FILTER = PREFIX + ".searchFilter"; // e.g. (uid={0})
  private static final String LDAP_BIND_DN = PREFIX + ".bindDn"; // Optional: for initial search
  private static final String LDAP_BIND_PASSWORD = PREFIX + ".bindPassword"; // Optional

  private AccessControl _accessControl;

  public ZkLdapAccessControlFactory() {
    // left blank
  }

  @Override
  public void init(PinotConfiguration configuration, ZkHelixPropertyStore<ZNRecord> propertyStore) {
    AccessControlUserCache userCache = new AccessControlUserCache(propertyStore);
    _accessControl = new ZkLdapAccessControl(configuration, userCache, propertyStore);
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
    private final ZkHelixPropertyStore<ZNRecord> _propertyStore;

    public ZkLdapAccessControl(PinotConfiguration config, AccessControlUserCache userCache,
        ZkHelixPropertyStore<ZNRecord> propertyStore) {
      _ldapUrl = config.getProperty(LDAP_URL);
      _baseDn = config.getProperty(LDAP_BASE_DN);
      _searchFilter = config.getProperty(LDAP_SEARCH_FILTER, "(uid={0})");
      _bindDn = config.getProperty(LDAP_BIND_DN);
      _bindPassword = config.getProperty(LDAP_BIND_PASSWORD);
      _userCache = userCache;
      _propertyStore = propertyStore;

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
        // No table restrictions? Just check auth.
        Optional<ZkBasicAuthPrincipal> principalOpt = getPrincipalAuth(requesterIdentity);
        if (!principalOpt.isPresent()) {
          throw new NotAuthorizedException("LDAP");
        }
        return TableAuthorizationResult.success();
      }

      return authorize(requesterIdentity, Collections.singleton(brokerRequest.getQuerySource().getTableName()));
    }

    @Override
    public TableAuthorizationResult authorize(RequesterIdentity requesterIdentity, Set<String> tables) {
      Optional<ZkBasicAuthPrincipal> principalOpt = getPrincipalAuth(requesterIdentity);
      if (!principalOpt.isPresent()) {
        throw new NotAuthorizedException("LDAP");
      }
      if (tables == null || tables.isEmpty()) {
        return TableAuthorizationResult.success();
      }

      ZkBasicAuthPrincipal principal = principalOpt.get();
      Set<String> failedTables = new HashSet<>();
      for (String table : tables) {
        if (!principal.hasTable(TableNameBuilder.extractRawTableName(table))) {
          failedTables.add(table);
        }
      }
      if (failedTables.isEmpty()) {
        return TableAuthorizationResult.success();
      }
      return new TableAuthorizationResult(failedTables);
    }

    /**
     * Authenticates via LDAP, then looks up the user in ZK (under BROKER component) to return permissions.
     */
    private Optional<ZkBasicAuthPrincipal> getPrincipalAuth(RequesterIdentity requesterIdentity) {
      Collection<String> tokens = extractAuthorizationTokens(requesterIdentity);
      if (tokens == null || tokens.isEmpty()) {
        return Optional.empty();
      }

      for (String token : tokens) {
        String username = BasicAuthUtils.extractUsername(token);
        String password = BasicAuthUtils.extractPassword(token);

        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
          continue;
        }

        // 1. Authenticate with LDAP
        if (authenticateLdap(username, password)) {
          // 2. Lookup permissions in ZK (using Broker User Cache)
          Map<String, ZkBasicAuthPrincipal> name2principal =
              org.apache.pinot.core.auth.BasicAuthUtils.extractBasicAuthPrincipals(_userCache.getAllBrokerUserConfig())
                  .stream().collect(Collectors.toMap(ZkBasicAuthPrincipal::getName, p -> p));

          if (name2principal.containsKey(username)) {
            return Optional.of(name2principal.get(username));
          } else {
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
        // Create user for BROKER with USER role, READ permission, and NO tables (dummy table)
        UserConfig brokerUser = new UserConfig(username, "dummy",
            ComponentType.BROKER.name(),
            RoleType.USER.name(),
            Collections.singletonList("__none__"), null,
            Collections.singletonList(AccessType.READ));

        ZNRecord znRecord = AccessControlUserConfigUtils.toZNRecord(brokerUser);
        String path = "/CONFIGS/USER/" + username + "_BROKER";

        if (_propertyStore.set(path, znRecord, AccessOption.PERSISTENT)) {
            LOGGER.info("Successfully provisioned new user '{}' with USER role.", username);
            // Return temporary principal
            return Optional.of(new ZkBasicAuthPrincipal(username, "dummy", "dummy",
                ComponentType.BROKER.name(),
                RoleType.USER.name(),
                Collections.singleton("__none__"), Collections.emptySet(),
                Collections.singleton("READ")));
        } else {
            LOGGER.error("Failed to write user '{}' to ZK property store.", username);
            return Optional.empty();
        }
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
