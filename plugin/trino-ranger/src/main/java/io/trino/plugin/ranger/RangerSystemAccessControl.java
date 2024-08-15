/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.ranger;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import io.trino.spi.QueryId;
import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.EntityKindAndName;
import io.trino.spi.connector.EntityPrivilege;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.eventlistener.EventListener;
import io.trino.spi.eventlistener.QueryCompletedEvent;
import io.trino.spi.eventlistener.QueryContext;
import io.trino.spi.eventlistener.QueryCreatedEvent;
import io.trino.spi.eventlistener.QueryMetadata;
import io.trino.spi.function.SchemaFunctionName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.Identity;
import io.trino.spi.security.Privilege;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.spi.security.ViewExpression;
import io.trino.spi.type.Type;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.authorization.hadoop.config.RangerPluginConfig;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static java.util.Locale.ENGLISH;
import static java.util.Objects.requireNonNullElse;

public class RangerSystemAccessControl
        implements SystemAccessControl
{
    private static final Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

    public static final String RANGER_TRINO_DEFAULT_HADOOP_CONF = "trino-ranger-site.xml";
    public static final String RANGER_TRINO_SERVICETYPE = "trino";
    public static final String RANGER_TRINO_APPID = "trino";
    public static final String RANGER_TRINO_DEFAULT_SERVICE_NAME = "dev_trino";
    public static final String RANGER_TRINO_DEFAULT_SECURITY_CONF = "ranger-trino-security.xml";
    public static final String RANGER_TRINO_DEFAULT_AUDIT_CONF = "ranger-trino-audit.xml";
    public static final String RANGER_TRINO_DEFAULT_POLICYMGR_SSL_CONF = "ranger-policymgr-ssl.xml";

    private final RangerBasePlugin rangerPlugin;
    private final RangerTrinoEventListener eventListener = new RangerTrinoEventListener();

    @Inject
    public RangerSystemAccessControl(RangerConfig config)
    {
        super();

        setDefaultConfig(config);

        Configuration hadoopConf = new Configuration();

        for (String configPath : config.getHadoopConfigResource()) {
            URL url = hadoopConf.getResource(configPath);

            LOG.info("Trying to load Hadoop config from {} (can be null)", url);

            if (url == null) {
                LOG.warn("Hadoop config {} not found", configPath);
            }
            else {
                hadoopConf.addResource(url);
            }
        }

        UserGroupInformation.setConfiguration(hadoopConf);

        RangerPluginConfig pluginConfig = new RangerPluginConfig(RANGER_TRINO_SERVICETYPE, config.getServiceName(), RANGER_TRINO_APPID, null, null, null);

        for (String configPath : config.getPluginConfigResource()) {
            pluginConfig.addResourceIfReadable(configPath);
        }

        rangerPlugin = new RangerBasePlugin(pluginConfig);

        rangerPlugin.init();

        rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
    }

    @Override
    public void checkCanImpersonateUser(Identity identity, String userName)
    {
        if (!hasPermission(createUserResource(userName), identity, null, TrinoAccessType.IMPERSONATE, "ImpersonateUser")) {
            AccessDeniedException.denyImpersonateUser(identity.getUser(), userName);
        }
    }

    @Deprecated
    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName)
    {
        if (!hasPermission(createUserResource(userName), principal, null, TrinoAccessType.IMPERSONATE, "SetUser")) {
            AccessDeniedException.denySetUser(principal, userName);
        }
    }

    /** QUERY **/
    @Deprecated
    @Override
    public void checkCanExecuteQuery(Identity identity)
    {
        checkCanExecuteQuery(identity, null);
    }

    @Override
    public void checkCanExecuteQuery(Identity identity, QueryId queryId)
    {
        if (!hasPermission(createResource(queryId), identity, queryId, TrinoAccessType.EXECUTE, "ExecuteQuery")) {
            AccessDeniedException.denyExecuteQuery();
        }
    }

    @Override
    public void checkCanViewQueryOwnedBy(Identity identity, Identity queryOwner)
    {
        if (!hasPermission(createUserResource(queryOwner.getUser()), identity, null, TrinoAccessType.IMPERSONATE, "ViewQueryOwnedBy")) {
            AccessDeniedException.denyImpersonateUser(identity.getUser(), queryOwner.getUser());
        }
    }

    @Override
    public Collection<Identity> filterViewQueryOwnedBy(Identity identity, Collection<Identity> queryOwners)
    {
        Set<Identity> toExclude = null;

        for (Identity queryOwner : queryOwners) {
            if (!hasPermissionForFilter(createUserResource(queryOwner.getUser()), identity, null, TrinoAccessType.IMPERSONATE, "filterViewQueryOwnedBy")) {
                LOG.debug("filterViewQueryOwnedBy(user={}): skipping queries owned by {}", identity, queryOwner);

                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(queryOwner);
            }
        }

        Collection<Identity> ret = (toExclude == null) ? queryOwners : queryOwners.stream().filter(((Predicate<? super Identity>) toExclude::contains).negate()).collect(Collectors.toList());

        return ret;
    }

    @Override
    public void checkCanKillQueryOwnedBy(Identity identity, Identity queryOwner)
    {
        if (!hasPermission(createUserResource(queryOwner.getUser()), identity, null, TrinoAccessType.IMPERSONATE, "KillQueryOwnedBy")) {
            AccessDeniedException.denyImpersonateUser(identity.getUser(), queryOwner.getUser());
        }
    }

    @Override
    public void checkCanReadSystemInformation(Identity identity)
    {
        if (!hasPermission(createSystemInformation(), identity, null, TrinoAccessType.READ_SYSINFO, "ReadSystemInformation")) {
            AccessDeniedException.denyReadSystemInformationAccess();
        }
    }

    @Override
    public void checkCanWriteSystemInformation(Identity identity)
    {
        if (!hasPermission(createSystemInformation(), identity, null, TrinoAccessType.WRITE_SYSINFO, "WriteSystemInformation")) {
            AccessDeniedException.denyWriteSystemInformationAccess();
        }
    }

    @Deprecated
    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, String propertyName)
    {
        if (!hasPermission(createSystemPropertyResource(propertyName), identity, null, TrinoAccessType.ALTER, "SetSystemSessionProperty")) {
            AccessDeniedException.denySetSystemSessionProperty(propertyName);
        }
    }

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, QueryId queryId, String propertyName)
    {
        if (!hasPermission(createSystemPropertyResource(propertyName), identity, queryId, TrinoAccessType.ALTER, "SetSystemSessionProperty")) {
            AccessDeniedException.denySetSystemSessionProperty(propertyName);
        }
    }

    /** CATALOG **/
    @Override
    public boolean canAccessCatalog(SystemSecurityContext context, String catalogName)
    {
        return hasPermission(createResource(catalogName), context, TrinoAccessType.USE, "AccessCatalog");
    }

    @Override
    public void checkCanCreateCatalog(SystemSecurityContext context, String catalogName)
    {
        if (!hasPermission(createResource(catalogName), context, TrinoAccessType.CREATE, "CreateCatalog")) {
            AccessDeniedException.denyCreateCatalog(catalogName);
        }
    }

    @Override
    public void checkCanDropCatalog(SystemSecurityContext context, String catalogName)
    {
        if (!hasPermission(createResource(catalogName), context, TrinoAccessType.DROP, "DropCatalog")) {
            AccessDeniedException.denyCreateCatalog(catalogName);
        }
    }

    @Override
    public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName)
    {
        if (!hasPermission(createCatalogSessionResource(catalogName, propertyName), context, TrinoAccessType.ALTER, "SetCatalogSessionProperty")) {
            AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs)
    {
        Set<String> toExclude = null;

        for (String catalog : catalogs) {
            if (!hasPermissionForFilter(createResource(catalog), context, TrinoAccessType._ANY, "filterCatalogs")) {
                LOG.debug("filterCatalogs(user={}): skipping catalog {}", context.getIdentity(), catalog);

                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(catalog);
            }
        }

        return toExclude == null ? catalogs : catalogs.stream().filter(((Predicate<? super String>) toExclude::contains).negate()).collect(Collectors.toSet());
    }

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema, Map<String, Object> properties)
    {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, TrinoAccessType.CREATE, "CreateSchema")) {
            AccessDeniedException.denyCreateSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, TrinoAccessType.DROP, "DropSchema")) {
            AccessDeniedException.denyDropSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName)
    {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, TrinoAccessType.ALTER, "RenameSchema")) {
            AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
        }
    }

    @Override
    public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, TrinoPrincipal principal)
    {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, TrinoAccessType.GRANT, "SetSchemaAuthorization")) {
            AccessDeniedException.denySetSchemaAuthorization(schema.getSchemaName(), principal);
        }
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName)
    {
        if (!hasPermission(createResource(catalogName), context, TrinoAccessType.SHOW, "ShowSchemas")) {
            AccessDeniedException.denyShowSchemas(catalogName);
        }
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames)
    {
        Set<String> toExclude = null;

        for (String schemaName : schemaNames) {
            if (!hasPermissionForFilter(createResource(catalogName, schemaName), context, TrinoAccessType._ANY, "filterSchemas")) {
                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(schemaName);
            }
        }

        return toExclude == null ? schemaNames : schemaNames.stream().filter(((Predicate<? super String>) toExclude::contains).negate()).collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!hasPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, TrinoAccessType.SHOW, "ShowCreateSchema")) {
            AccessDeniedException.denyShowCreateSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Object> properties)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.CREATE, "CreateTable")) {
            AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.DROP, "DropTable")) {
            AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.ALTER, "RenameTable")) {
            AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanSetTableProperties(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Optional<Object>> properties)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.ALTER, "SetTableProperties")) {
            AccessDeniedException.denySetTableProperties(table.toString());
        }
    }

    @Override
    public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.ALTER, "SetTableComment")) {
            AccessDeniedException.denyCommentTable(table.toString());
        }
    }

    @Override
    public void checkCanSetTableAuthorization(SystemSecurityContext context, CatalogSchemaTableName table, TrinoPrincipal principal)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.GRANT, "SetTableAuthorization")) {
            AccessDeniedException.denySetTableAuthorization(table.toString(), principal);
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!hasPermission(createResource(schema), context, TrinoAccessType.SHOW, "ShowTables")) {
            AccessDeniedException.denyShowTables(schema.toString());
        }
    }

    @Override
    public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.SHOW, "ShowCreateTable")) {
            AccessDeniedException.denyShowCreateTable(table.toString());
        }
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        RangerTrinoResource res = createResource(table);

        if (!hasPermission(res, context, TrinoAccessType.INSERT, "InsertIntoTable")) {
            AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.DELETE, "DeleteFromTable")) {
            AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanTruncateTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.DELETE, "TruncateTable")) {
            AccessDeniedException.denyTruncateTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames)
    {
        Set<SchemaTableName> toExclude = null;

        for (SchemaTableName tableName : tableNames) {
            RangerTrinoResource res = createResource(catalogName, tableName.getSchemaName(), tableName.getTableName());

            if (!hasPermissionForFilter(res, context, TrinoAccessType._ANY, "filterTables")) {
                LOG.debug("filterTables(user={}): skipping table {}.{}.{}", context.getIdentity(), catalogName, tableName.getSchemaName(), tableName.getTableName());

                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(tableName);
            }
        }

        return toExclude == null ? tableNames : tableNames.stream().filter(((Predicate<? super SchemaTableName>) toExclude::contains).negate()).collect(Collectors.toSet());
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        RangerTrinoResource res = createResource(table);

        if (!hasPermission(res, context, TrinoAccessType.ALTER, "AddColumn")) {
            AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanAlterColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        RangerTrinoResource res = createResource(table);

        if (!hasPermission(res, context, TrinoAccessType.ALTER, "AlterColumn")) {
            AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.ALTER, "DropColumn")) {
            AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        RangerTrinoResource res = createResource(table);

        if (!hasPermission(res, context, TrinoAccessType.ALTER, "RenameColumn")) {
            AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanSetColumnComment(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.ALTER, "SetColumnComment")) {
            AccessDeniedException.denyCommentColumn(table.toString());
        }
    }

    /**
     * This is evaluated on table level
     */
    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.SHOW, "ShowColumns")) {
            AccessDeniedException.denyShowColumns(table.toString());
        }
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        for (RangerTrinoResource res : createResource(table, columns)) {
            if (!hasPermission(res, context, TrinoAccessType.SELECT, "SelectFromColumns")) {
                AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
            }
        }
    }

    @Override
    public void checkCanUpdateTableColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> updatedColumnNames)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.INSERT, "UpdateTableColumns")) {
            AccessDeniedException.denyUpdateTableColumns(table.getSchemaTableName().getTableName(), updatedColumnNames);
        }
    }

    @Deprecated
    @Override
    public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        Set<String> toExclude = null;
        String catalogName = table.getCatalogName();
        String schemaName = table.getSchemaTableName().getSchemaName();
        String tableName = table.getSchemaTableName().getTableName();

        for (String column : columns) {
            RangerTrinoResource res = createResource(catalogName, schemaName, tableName, column);

            if (!hasPermissionForFilter(res, context, TrinoAccessType._ANY, "filterColumns")) {
                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(column);
            }
        }

        return toExclude == null ? columns : columns.stream().filter(((Predicate<? super String>) toExclude::contains).negate()).collect(Collectors.toSet());
    }

    /**
     * Create view is verified on schema level
     */
    @Override
    public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        if (!hasPermission(createResource(view), context, TrinoAccessType.CREATE, "CreateView")) {
            AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        if (!hasPermission(createResource(view), context, TrinoAccessType.DROP, "DropView")) {
            AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
        }
    }

    /**
     * This is evaluated against the table name as ownership information is not available
     */
    @Override
    public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView)
    {
        if (!hasPermission(createResource(view), context, TrinoAccessType.ALTER, "RenameView")) {
            AccessDeniedException.denyRenameView(view.toString(), newView.toString());
        }
    }

    @Override
    public void checkCanSetViewAuthorization(SystemSecurityContext context, CatalogSchemaTableName view, TrinoPrincipal principal)
    {
        if (!hasPermission(createResource(view), context, TrinoAccessType.ALTER, "SetViewAuthorization")) {
            AccessDeniedException.denySetViewAuthorization(view.toString(), principal);
        }
    }

    /**
     * This check equals the check for checkCanCreateView
     */
    @Override
    public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        try {
            checkCanCreateView(context, table);
        }
        catch (AccessDeniedException ade) {
            AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
        }
    }

    @Override
    public void checkCanSetViewComment(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        if (!hasPermission(createResource(view), context, TrinoAccessType.ALTER, "SetViewComment")) {
            AccessDeniedException.denyCommentView(view.toString());
        }
    }

    /**
     *
     * check if materialized view can be created
     */
    @Override
    public void checkCanCreateMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Object> properties)
    {
        if (!hasPermission(createResource(materializedView), context, TrinoAccessType.CREATE, "CreateMaterializedView")) {
            AccessDeniedException.denyCreateMaterializedView(materializedView.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRefreshMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView)
    {
        if (!hasPermission(createResource(materializedView), context, TrinoAccessType.ALTER, "RefreshMaterializedView")) {
            AccessDeniedException.denyRefreshMaterializedView(materializedView.toString());
        }
    }

    @Override
    public void checkCanSetMaterializedViewProperties(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Optional<Object>> properties)
    {
        if (!hasPermission(createResource(materializedView), context, TrinoAccessType.ALTER, "SetMaterializedViewProperties")) {
            AccessDeniedException.denyRefreshMaterializedView(materializedView.toString());
        }
    }

    @Override
    public void checkCanDropMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView)
    {
        if (!hasPermission(createResource(materializedView), context, TrinoAccessType.DROP, "DropMaterializedView")) {
            AccessDeniedException.denyCreateView(materializedView.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRenameMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView, CatalogSchemaTableName newView)
    {
        if (!hasPermission(createResource(materializedView), context, TrinoAccessType.DROP, "RenameMaterializedView")) {
            AccessDeniedException.denyRenameMaterializedView(materializedView.toString(), newView.toString());
        }
    }

    @Override
    public void checkCanGrantSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee, boolean grantOption)
    {
        if (!hasPermission(createResource(schema), context, TrinoAccessType.GRANT, "GrantSchemaPrivilege")) {
            AccessDeniedException.denyGrantSchemaPrivilege(privilege.toString(), schema.toString());
        }
    }

    @Override
    public void checkCanDenySchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee)
    {
        if (!hasPermission(createResource(schema), context, TrinoAccessType.REVOKE, "DenySchemaPrivilege")) {
            AccessDeniedException.denyDenySchemaPrivilege(privilege.toString(), schema.toString());
        }
    }

    @Override
    public void checkCanRevokeSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal revokee, boolean grantOption)
    {
        if (!hasPermission(createResource(schema), context, TrinoAccessType.REVOKE, "RevokeSchemaPrivilege")) {
            AccessDeniedException.denyRevokeSchemaPrivilege(privilege.toString(), schema.toString());
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean withGrantOption)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.GRANT, "GrantTablePrivilege")) {
            AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
        }
    }

    @Override
    public void checkCanDenyTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.REVOKE, "DenyTablePrivilege")) {
            AccessDeniedException.denyDenyTablePrivilege(privilege.toString(), table.toString());
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOptionFor)
    {
        if (!hasPermission(createResource(table), context, TrinoAccessType.REVOKE, "RevokeTablePrivilege")) {
            AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
        }
    }

    @Override
    public void checkCanGrantEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal grantee, boolean grantOption)
    {
        if (!hasPermission(createResource(entity), context, TrinoAccessType.GRANT, "GrantEntityPrivilege")) {
            AccessDeniedException.denyGrantEntityPrivilege(privilege.toString(), entity);
        }
    }

    @Override
    public void checkCanDenyEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal grantee)
    {
        if (!hasPermission(createResource(entity), context, TrinoAccessType.REVOKE, "DenyEntityPrivilege")) {
            AccessDeniedException.denyDenyEntityPrivilege(privilege.toString(), entity);
        }
    }

    @Override
    public void checkCanRevokeEntityPrivilege(SystemSecurityContext context, EntityPrivilege privilege, EntityKindAndName entity, TrinoPrincipal revokee, boolean grantOption)
    {
        if (!hasPermission(createResource(entity), context, TrinoAccessType.REVOKE, "RevokeEntityPrivilege")) {
            AccessDeniedException.denyRevokeEntityPrivilege(privilege.toString(), entity);
        }
    }

    @Override
    public void checkCanCreateRole(SystemSecurityContext context, String role, Optional<TrinoPrincipal> grantor)
    {
        if (!hasPermission(createRoleResource(role), context, TrinoAccessType.CREATE, "CreateRole")) {
            AccessDeniedException.denyCreateRole(role);
        }
    }

    @Override
    public void checkCanDropRole(SystemSecurityContext context, String role)
    {
        if (!hasPermission(createRoleResource(role), context, TrinoAccessType.DROP, "DropRole")) {
            AccessDeniedException.denyDropRole(role);
        }
    }

    @Override
    public void checkCanShowRoles(SystemSecurityContext context)
    {
        if (!hasPermission(createRoleResource("*"), context, TrinoAccessType.SHOW, "ShowRoles")) {
            AccessDeniedException.denyShowRoles();
        }
    }

    @Override
    public void checkCanGrantRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        if (!hasPermission(createRoleResources(roles), context, TrinoAccessType.GRANT, "GrantRoles")) {
            AccessDeniedException.denyGrantRoles(roles, grantees);
        }
    }

    @Override
    public void checkCanRevokeRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        if (!hasPermission(createRoleResources(roles), context, TrinoAccessType.REVOKE, "RevokeRoles")) {
            AccessDeniedException.denyRevokeRoles(roles, grantees);
        }
    }

    @Override
    public void checkCanShowCurrentRoles(SystemSecurityContext context)
    {
        //allow
    }

    @Override
    public void checkCanShowRoleGrants(SystemSecurityContext context)
    {
        //allow
    }

    /** PROCEDURES **/
    @Override
    public void checkCanExecuteProcedure(SystemSecurityContext context, CatalogSchemaRoutineName procedure)
    {
        if (!hasPermission(createProcedureResource(procedure), context, TrinoAccessType.EXECUTE, "ExecuteProcedure")) {
            AccessDeniedException.denyExecuteProcedure(procedure.getSchemaRoutineName().getRoutineName());
        }
    }

    @Override
    public void checkCanExecuteTableProcedure(SystemSecurityContext context, CatalogSchemaTableName catalogSchemaTableName, String procedure)
    {
        if (!hasPermission(createResource(catalogSchemaTableName), context, TrinoAccessType.ALTER, "ExecuteTableProcedure")) {
            AccessDeniedException.denyExecuteTableProcedure(catalogSchemaTableName.toString(), procedure);
        }
    }

    @Override
    public void checkCanCreateFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName)
    {
        if (!hasPermission(createResource(functionName), context, TrinoAccessType.CREATE, "CreateFunction")) {
            AccessDeniedException.denyCreateFunction(functionName.toString());
        }
    }

    @Override
    public void checkCanDropFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName)
    {
        if (!hasPermission(createResource(functionName), context, TrinoAccessType.DROP, "DropFunction")) {
            AccessDeniedException.denyDropFunction(functionName.toString());
        }
    }

    @Override
    public void checkCanShowCreateFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName)
    {
        if (!hasPermission(createResource(functionName), context, TrinoAccessType.SHOW, "ShowCreateFunction")) {
            AccessDeniedException.denyShowCreateFunction(functionName.toString());
        }
    }

    @Override
    public void checkCanShowFunctions(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!hasPermission(createResource(schema), context, TrinoAccessType.SHOW, "ShowFunctions")) {
            AccessDeniedException.denyShowFunctions(schema.toString());
        }
    }

    @Override
    public boolean canExecuteFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName)
    {
        return hasPermission(createResource(functionName), context, TrinoAccessType.EXECUTE, "ExecuteFunction");
    }

    @Override
    public boolean canCreateViewWithExecuteFunction(SystemSecurityContext context, CatalogSchemaRoutineName functionName)
    {
        return hasPermission(createResource(functionName), context, TrinoAccessType.CREATE, "CreateViewWithExecuteFunction");
    }

    @Override
    public Set<SchemaFunctionName> filterFunctions(SystemSecurityContext context, String catalogName, Set<SchemaFunctionName> functionNames)
    {
        Set<SchemaFunctionName> toExclude = null;

        for (SchemaFunctionName functionName : functionNames) {
            RangerTrinoResource res = createResource(catalogName, functionName);

            if (!hasPermissionForFilter(res, context, TrinoAccessType._ANY, "filterFunctions")) {
                LOG.debug("filterFunctions(user={}): skipping function {}.{}.{}", context.getIdentity(), catalogName, functionName.getSchemaName(), functionName.getFunctionName());

                if (toExclude == null) {
                    toExclude = new HashSet<>();
                }

                toExclude.add(functionName);
            }
        }

        return toExclude == null ? functionNames : functionNames.stream().filter(((Predicate<? super SchemaFunctionName>) toExclude::contains).negate()).collect(Collectors.toSet());
    }

    @Override
    public List<ViewExpression> getRowFilters(SystemSecurityContext context, CatalogSchemaTableName tableName)
    {
        RangerAccessResult result = getRowFilterResult(createAccessRequest(createResource(tableName), context, TrinoAccessType.SELECT, "getRowFilters"));
        ViewExpression viewExpression = null;

        if (isRowFilterEnabled(result)) {
            String filter = result.getFilterExpr();

            viewExpression = ViewExpression.builder().identity(context.getIdentity().getUser())
                    .catalog(tableName.getCatalogName())
                    .schema(tableName.getSchemaTableName().getSchemaName())
                    .expression(filter).build();
        }

        return Optional.ofNullable(viewExpression).map(ImmutableList::of).orElseGet(ImmutableList::of);
    }

    @Override
    public Optional<ViewExpression> getColumnMask(SystemSecurityContext context, CatalogSchemaTableName tableName, String columnName, Type type)
    {
        RangerAccessResult result = getDataMaskResult(createAccessRequest(createResource(tableName.getCatalogName(), tableName.getSchemaTableName().getSchemaName(), tableName.getSchemaTableName().getTableName(), columnName), context, TrinoAccessType.SELECT, "getColumnMask"));
        ViewExpression viewExpression = null;

        if (isDataMaskEnabled(result)) {
            String maskType = result.getMaskType();
            RangerServiceDef.RangerDataMaskTypeDef maskTypeDef = result.getMaskTypeDef();
            String transformer = null;

            if (maskTypeDef != null) {
                transformer = maskTypeDef.getTransformer();
            }

            if (StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_NULL)) {
                transformer = "NULL";
            }
            else if (StringUtils.equalsIgnoreCase(maskType, RangerPolicy.MASK_TYPE_CUSTOM)) {
                String maskedValue = result.getMaskedValue();

                transformer = requireNonNullElse(maskedValue, "NULL");
            }

            if (StringUtils.isNotEmpty(transformer)) {
                transformer = transformer.replace("{col}", columnName).replace("{type}", type.getDisplayName());
            }

            viewExpression = ViewExpression.builder().identity(context.getIdentity().getUser())
                    .catalog(tableName.getCatalogName())
                    .schema(tableName.getSchemaTableName().getSchemaName())
                    .expression(transformer).build();
        }

        return Optional.ofNullable(viewExpression);
    }

    @Override
    public Iterable<EventListener> getEventListeners()
    {
        return Collections.singletonList(eventListener);
    }

    @Override
    public void shutdown()
    {
        // nothing to do here
    }

    /** HELPER FUNCTIONS **/

    private RangerAccessResult getDataMaskResult(RangerTrinoAccessRequest request)
    {
        return rangerPlugin.evalDataMaskPolicies(request, null);
    }

    private RangerAccessResult getRowFilterResult(RangerTrinoAccessRequest request)
    {
        return rangerPlugin.evalRowFilterPolicies(request, null);
    }

    private boolean isDataMaskEnabled(RangerAccessResult result)
    {
        return result != null && result.isMaskEnabled();
    }

    private boolean isRowFilterEnabled(RangerAccessResult result)
    {
        return result != null && result.isRowFilterEnabled();
    }

    private RangerTrinoAccessRequest createAccessRequest(RangerTrinoResource resource, SystemSecurityContext context, TrinoAccessType accessType, String action)
    {
        Set<String> userGroups = context.getIdentity().getGroups();

        return new RangerTrinoAccessRequest(resource, context.getIdentity().getUser(), userGroups, getQueryTime(context), getClientAddress(context), getClientType(context), getQueryText(context), accessType, action);
    }

    private RangerTrinoAccessRequest createAccessRequest(RangerTrinoResource resource, Identity identity, QueryId queryId, TrinoAccessType accessType, String action)
    {
        Set<String> userGroups = identity.getGroups();

        return new RangerTrinoAccessRequest(resource, identity.getUser(), userGroups, getQueryTime(queryId), getClientAddress(queryId), getClientType(queryId), getQueryText(queryId), accessType, action);
    }

    private String getClientAddress(QueryId queryId)
    {
        return queryId != null ? eventListener.getClientAddress(queryId.getId()) : null;
    }

    private String getClientType(QueryId queryId)
    {
        return queryId != null ? eventListener.getClientType(queryId.getId()) : null;
    }

    private String getQueryText(QueryId queryId)
    {
        return queryId != null ? eventListener.getQueryText(queryId.getId()) : null;
    }

    private Instant getQueryTime(QueryId queryId)
    {
        return queryId != null ? eventListener.getQueryTime(queryId.getId()) : null;
    }

    private String getClientAddress(SystemSecurityContext context)
    {
        return context != null ? getClientAddress(context.getQueryId()) : null;
    }

    private String getClientType(SystemSecurityContext context)
    {
        return context != null ? getClientType(context.getQueryId()) : null;
    }

    private String getQueryText(SystemSecurityContext context)
    {
        return context != null ? getQueryText(context.getQueryId()) : null;
    }

    private Instant getQueryTime(SystemSecurityContext context)
    {
        return context != null ? getQueryTime(context.getQueryId()) : null;
    }

    private boolean hasPermission(RangerTrinoResource resource, SystemSecurityContext context, TrinoAccessType accessType, String action)
    {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(createAccessRequest(resource, context, accessType, action));

        return result != null && result.getIsAllowed();
    }

    private boolean hasPermissionForFilter(RangerTrinoResource resource, SystemSecurityContext context, TrinoAccessType accessType, String action)
    {
        RangerTrinoAccessRequest request = createAccessRequest(resource, context, accessType, action);

        request.setResourceMatchingScope(RangerAccessRequest.ResourceMatchingScope.SELF_OR_DESCENDANTS);

        RangerAccessResult result = rangerPlugin.isAccessAllowed(request, null);

        return result != null && result.getIsAllowed();
    }

    private boolean hasPermission(Collection<RangerTrinoResource> resources, SystemSecurityContext context, TrinoAccessType accessType, String action)
    {
        boolean ret = true;

        for (RangerTrinoResource resource : resources) {
            RangerAccessResult result = rangerPlugin.isAccessAllowed(createAccessRequest(resource, context, accessType, action));

            ret = result != null && result.getIsAllowed();

            if (!ret) {
                break;
            }
        }

        return ret;
    }

    private boolean hasPermission(RangerTrinoResource resource, Identity identity, QueryId queryId, TrinoAccessType accessType, String action)
    {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(createAccessRequest(resource, identity, queryId, accessType, action));

        return result != null && result.getIsAllowed();
    }

    private boolean hasPermissionForFilter(RangerTrinoResource resource, Identity identity, QueryId queryId, TrinoAccessType accessType, String action)
    {
        RangerTrinoAccessRequest request = createAccessRequest(resource, identity, queryId, accessType, action);

        request.setResourceMatchingScope(RangerAccessRequest.ResourceMatchingScope.SELF_OR_DESCENDANTS);

        RangerAccessResult result = rangerPlugin.isAccessAllowed(request, null);

        return result != null && result.getIsAllowed();
    }

    private boolean hasPermission(RangerTrinoResource resource, Optional<Principal> principal, QueryId queryId, TrinoAccessType accessType, String action)
    {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(createAccessRequest(resource, toIdentity(principal), queryId, accessType, action));

        return result != null && result.getIsAllowed();
    }

    private static RangerTrinoResource createUserResource(String userName)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_USER, userName);

        return res;
    }

    private static RangerTrinoResource createProcedureResource(CatalogSchemaRoutineName procedure)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_CATALOG, procedure.getCatalogName());
        res.setValue(RangerTrinoResource.KEY_SCHEMA, procedure.getSchemaRoutineName().getSchemaName());
        res.setValue(RangerTrinoResource.KEY_PROCEDURE, procedure.getSchemaRoutineName().getRoutineName());

        return res;
    }

    private static RangerTrinoResource createCatalogSessionResource(String catalogName, String propertyName)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_CATALOG, catalogName);
        res.setValue(RangerTrinoResource.KEY_SESSION_PROPERTY, propertyName);

        return res;
    }

    private static RangerTrinoResource createResource(CatalogSchemaRoutineName procedure)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_CATALOG, procedure.getCatalogName());
        res.setValue(RangerTrinoResource.KEY_SCHEMA, procedure.getSchemaRoutineName().getSchemaName());
        res.setValue(RangerTrinoResource.KEY_SCHEMA_FUNCTION, procedure.getSchemaRoutineName().getRoutineName());

        return res;
    }

    private static RangerTrinoResource createSystemPropertyResource(String property)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_SYSTEM_PROPERTY, property);

        return res;
    }

    private static RangerTrinoResource createSystemInformation()
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_SYSINFO, "*");

        return res;
    }

    private static RangerTrinoResource createResource(CatalogSchemaName catalogSchemaName)
    {
        return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
    }

    private static RangerTrinoResource createResource(CatalogSchemaTableName catalogSchemaTableName)
    {
        return createResource(catalogSchemaTableName.getCatalogName(), catalogSchemaTableName.getSchemaTableName().getSchemaName(), catalogSchemaTableName.getSchemaTableName().getTableName());
    }

    private static RangerTrinoResource createResource(String catalogName)
    {
        return new RangerTrinoResource(catalogName, null, null);
    }

    private static RangerTrinoResource createResource(String catalogName, String schemaName)
    {
        return new RangerTrinoResource(catalogName, schemaName, null);
    }

    private static RangerTrinoResource createResource(String catalogName, String schemaName, final String tableName)
    {
        return new RangerTrinoResource(catalogName, schemaName, tableName);
    }

    private static RangerTrinoResource createResource(String catalogName, String schemaName, final String tableName, final String column)
    {
        return new RangerTrinoResource(catalogName, schemaName, tableName, column);
    }

    private static List<RangerTrinoResource> createResource(CatalogSchemaTableName table, Set<String> columns)
    {
        List<RangerTrinoResource> colRequests = new ArrayList<>();

        if (!columns.isEmpty()) {
            for (String column : columns) {
                RangerTrinoResource rangerTrinoResource = createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName(), table.getSchemaTableName().getTableName(), column);

                colRequests.add(rangerTrinoResource);
            }
        }
        else {
            colRequests.add(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName(), table.getSchemaTableName().getTableName(), null));
        }

        return colRequests;
    }

    private static RangerTrinoResource createResource(String catalogName, SchemaFunctionName functionName)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_CATALOG, catalogName);
        res.setValue(RangerTrinoResource.KEY_SCHEMA, functionName.getSchemaName());
        res.setValue(RangerTrinoResource.KEY_SCHEMA_FUNCTION, functionName.getFunctionName());

        return res;
    }

    private static RangerTrinoResource createResource(EntityKindAndName entity)
    {
        RangerTrinoResource ret = new RangerTrinoResource();

        switch (entity.entityKind().toUpperCase(ENGLISH)) {
            case "SCHEMA":
                ret.setValue(RangerTrinoResource.KEY_CATALOG, entity.name().getFirst());
                ret.setValue(RangerTrinoResource.KEY_SCHEMA, entity.name().get(1));
                break;

            case "TABLE":
            case "VIEW":
            case "MATERIALIZED VIEW":
                ret.setValue(RangerTrinoResource.KEY_CATALOG, entity.name().getFirst());
                ret.setValue(RangerTrinoResource.KEY_SCHEMA, entity.name().get(1));
                ret.setValue(RangerTrinoResource.KEY_TABLE, entity.name().get(2));
                break;
        }

        return ret;
    }

    private static RangerTrinoResource createRoleResource(String roleName)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_ROLE, roleName);

        return res;
    }

    private static Set<RangerTrinoResource> createRoleResources(Set<String> roleNames)
    {
        Set<RangerTrinoResource> ret = new HashSet<>(roleNames.size());

        for (String rolName : roleNames) {
            ret.add(createRoleResource(rolName));
        }

        return ret;
    }

    private static RangerTrinoResource createResource(QueryId queryId)
    {
        RangerTrinoResource res = new RangerTrinoResource();

        res.setValue(RangerTrinoResource.KEY_QUERY_ID, queryId != null ? queryId.getId() : "*");

        return res;
    }

    private void setDefaultConfig(RangerConfig config)
    {
        if (StringUtils.isBlank(config.getServiceName())) {
            config.setServiceName(RANGER_TRINO_DEFAULT_SERVICE_NAME);
        }

        if (config.getPluginConfigResource() == null || config.getPluginConfigResource().isEmpty()) {
            config.setPluginConfigResource(Arrays.asList(RANGER_TRINO_DEFAULT_SECURITY_CONF, RANGER_TRINO_DEFAULT_AUDIT_CONF, RANGER_TRINO_DEFAULT_POLICYMGR_SSL_CONF));
        }

        if (config.getHadoopConfigResource() == null || config.getHadoopConfigResource().isEmpty()) {
            config.setHadoopConfigResource(Arrays.asList(RANGER_TRINO_DEFAULT_HADOOP_CONF));
        }
    }

    private static Identity toIdentity(Optional<Principal> principal)
    {
        return principal.isPresent() ? Identity.ofUser(principal.get().getName()) : Identity.ofUser("");
    }

    private static class RangerTrinoEventListener
            implements EventListener
    {
        private final Map<String, QueryCreatedEvent> activeQueries = new HashMap<>();

        public String getClientAddress(String queryId)
        {
            QueryCreatedEvent qce = activeQueries.get(queryId);
            QueryContext qc = qce != null ? qce.getContext() : null;

            return qc != null && qc.getRemoteClientAddress().isPresent() ? qc.getRemoteClientAddress().get() : null;
        }

        public String getQueryText(String queryId)
        {
            QueryCreatedEvent qce = activeQueries.get(queryId);
            QueryMetadata qm = qce != null ? qce.getMetadata() : null;

            return qm != null ? qm.getQuery() : null;
        }

        public Instant getQueryTime(String queryId)
        {
            QueryCreatedEvent qce = activeQueries.get(queryId);

            return qce != null ? qce.getCreateTime() : null;
        }

        public String getClientType(String queryId)
        {
            QueryCreatedEvent qce = activeQueries.get(queryId);
            QueryContext qc = qce != null ? qce.getContext() : null;

            return qc != null && qc.getUserAgent().isPresent() ? qc.getUserAgent().get() : null;
        }

        @Override
        public void queryCreated(QueryCreatedEvent queryCreatedEvent)
        {
            QueryMetadata qm = queryCreatedEvent.getMetadata();

            if (qm != null && StringUtils.isNotBlank(qm.getQueryId())) {
                activeQueries.put(qm.getQueryId(), queryCreatedEvent);
            }
        }

        @Override
        public void queryCompleted(QueryCompletedEvent queryCompletedEvent)
        {
            QueryMetadata qm = queryCompletedEvent.getMetadata();

            if (qm != null && StringUtils.isNotBlank(qm.getQueryId())) {
                activeQueries.remove(qm.getQueryId());
            }
        }
    }

    private static class RangerTrinoResource
            extends RangerAccessResourceImpl
    {
        public static final String KEY_CATALOG = "catalog";
        public static final String KEY_SCHEMA = "schema";
        public static final String KEY_TABLE = "table";
        public static final String KEY_COLUMN = "column";
        public static final String KEY_USER = "trinouser";
        public static final String KEY_PROCEDURE = "procedure";
        public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
        public static final String KEY_SESSION_PROPERTY = "sessionproperty";
        public static final String KEY_SCHEMA_FUNCTION = "schemafunction";
        public static final String KEY_ROLE = "role";
        public static final String KEY_QUERY_ID = "queryid";
        public static final String KEY_SYSINFO = "sysinfo";

        public RangerTrinoResource()
        {
        }

        public RangerTrinoResource(String catalogName, String schema, String table)
        {
            setValue(KEY_CATALOG, catalogName);
            setValue(KEY_SCHEMA, schema);
            setValue(KEY_TABLE, table);
        }

        public RangerTrinoResource(String catalogName, String schema, String table, String column)
        {
            setValue(KEY_CATALOG, catalogName);
            setValue(KEY_SCHEMA, schema);
            setValue(KEY_TABLE, table);
            setValue(KEY_COLUMN, column);
        }
    }

    private static class RangerTrinoAccessRequest
            extends RangerAccessRequestImpl
    {
        public RangerTrinoAccessRequest(RangerTrinoResource resource, String user, Set<String> userGroups, Instant queryTime, String clientAddress, String clientType, String queryText, TrinoAccessType trinoAccessType, String action)
        {
            super(resource, trinoAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);

            setAction(action);
            setAccessTime(queryTime != null ? new Date(queryTime.getEpochSecond() * 1000) : new Date());
            setClientIPAddress(clientAddress);
            setClientType(clientType);
            setRequestData(queryText);
        }
    }

    private enum TrinoAccessType {
        CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, GRANT, REVOKE, SHOW, IMPERSONATE, EXECUTE, READ_SYSINFO, WRITE_SYSINFO, _ANY
    }
}
