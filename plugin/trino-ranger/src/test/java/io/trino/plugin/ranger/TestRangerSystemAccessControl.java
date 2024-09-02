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

import com.google.common.collect.ImmutableSet;
import io.trino.spi.QueryId;
import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.EntityKindAndName;
import io.trino.spi.connector.EntityPrivilege;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.function.SchemaFunctionName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.BasicPrincipal;
import io.trino.spi.security.Identity;
import io.trino.spi.security.SystemSecurityContext;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.spi.security.ViewExpression;
import io.trino.spi.type.VarcharType;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.security.auth.kerberos.KerberosPrincipal;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.trino.spi.security.PrincipalType.USER;
import static io.trino.spi.security.Privilege.SELECT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestRangerSystemAccessControl
{
    static RangerSystemAccessControl accessControlManager;

    private static final Identity ALICE = new Identity.Builder("alice").withPrincipal(new BasicPrincipal("alice")).build();
    private static final Identity ADMIN = new Identity.Builder("admin").withPrincipal(new BasicPrincipal("admin")).build();
    private static final Identity KERBEROS_INVALID_ALICE = Identity.from(ALICE).withPrincipal(new KerberosPrincipal("mallory/example.com@EXAMPLE.COM")).build();
    private static final Identity BOB = Identity.ofUser("bob");

    private static final Set<String> ALL_CATALOGS = ImmutableSet.of("open-to-all", "all-allowed", "alice-catalog");
    private static final Set<Identity> QUERY_OWNERS = ImmutableSet.of(Identity.ofUser("bob"), Identity.ofUser("alice"), Identity.ofUser("frank"));
    private static final String ALICE_CATALOG = "alice-catalog";
    private static final CatalogSchemaName ALICE_SCHEMA = new CatalogSchemaName(ALICE_CATALOG, "schema");
    private static final CatalogSchemaTableName ALICE_TABLE = new CatalogSchemaTableName(ALICE_CATALOG, "schema", "table");
    private static final CatalogSchemaTableName ALICE_VIEW = new CatalogSchemaTableName(ALICE_CATALOG, "schema", "view");
    private static final CatalogSchemaRoutineName ALICE_PROCEDURE = new CatalogSchemaRoutineName(ALICE_CATALOG, "schema", "procedure");
    private static final CatalogSchemaRoutineName ALICE_FUNCTION = new CatalogSchemaRoutineName(ALICE_CATALOG, "schema", "function");

    @BeforeClass
    public static void setUpBeforeClass()
            throws Exception
    {
        accessControlManager = new RangerSystemAccessControl(new RangerConfig());
    }

    @Test
    @SuppressWarnings("PMD")
    public void testCanSetUserOperations()
    {
        accessControlManager.checkCanSetUser(ADMIN.getPrincipal(), BOB.getUser());
        accessControlManager.checkCanImpersonateUser(ADMIN, BOB.getUser());
        accessControlManager.checkCanViewQueryOwnedBy(ADMIN, BOB);
        accessControlManager.checkCanKillQueryOwnedBy(ADMIN, BOB);
        assertEquals(Collections.emptyList(), accessControlManager.filterViewQueryOwnedBy(ALICE, QUERY_OWNERS));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetUser(ALICE.getPrincipal(), BOB.getUser()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanImpersonateUser(ALICE, BOB.getUser()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanViewQueryOwnedBy(ALICE, BOB));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanKillQueryOwnedBy(ALICE, BOB));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanImpersonateUser(KERBEROS_INVALID_ALICE, BOB.getUser()));
    }

    @Test
    public void testSystemInformationOperations()
    {
        accessControlManager.checkCanReadSystemInformation(ADMIN);
        accessControlManager.checkCanWriteSystemInformation(ADMIN);

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanReadSystemInformation(ALICE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanWriteSystemInformation(ALICE));
    }

    @Test
    public void testSystemSessionPropertyOperations()
    {
        accessControlManager.checkCanSetSystemSessionProperty(ADMIN, "test-property");
        accessControlManager.checkCanSetSystemSessionProperty(ADMIN, new QueryId("q1"), "test-property");

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetSystemSessionProperty(ALICE, "test-property"));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetSystemSessionProperty(ALICE, new QueryId("q1"), "test-property"));
    }

    @Test
    public void testQueryOperations()
    {
        accessControlManager.checkCanExecuteQuery(ADMIN, new QueryId("1"));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanExecuteQuery(ALICE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanExecuteQuery(ALICE, new QueryId("1")));
    }

    @Test
    public void testCatalogOperations()
    {
        accessControlManager.canAccessCatalog(context(ALICE), ALICE_CATALOG);
        accessControlManager.checkCanCreateCatalog(context(ALICE), ALICE_CATALOG);
        accessControlManager.checkCanDropCatalog(context(ALICE), ALICE_CATALOG);
        accessControlManager.checkCanSetCatalogSessionProperty(context(ALICE), ALICE_CATALOG, "property");
        assertEquals(ALL_CATALOGS, accessControlManager.filterCatalogs(context(ALICE), ALL_CATALOGS));
        assertEquals(ImmutableSet.of("open-to-all", "all-allowed"), accessControlManager.filterCatalogs(context(BOB), ALL_CATALOGS));

        assertFalse(accessControlManager.canAccessCatalog(context(BOB), ALICE_CATALOG));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateCatalog(context(BOB), ALICE_CATALOG));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropCatalog(context(BOB), ALICE_CATALOG));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetCatalogSessionProperty(context(BOB), ALICE_CATALOG, "property"));
    }

    @Test
    @SuppressWarnings("PMD")
    public void testSchemaOperations()
    {
        accessControlManager.checkCanCreateSchema(context(ALICE), ALICE_SCHEMA, null);
        accessControlManager.checkCanDropSchema(context(ALICE), ALICE_SCHEMA);
        accessControlManager.checkCanRenameSchema(context(ALICE), ALICE_SCHEMA, "new-schema");
        accessControlManager.checkCanShowSchemas(context(ALICE), ALICE_CATALOG);
        accessControlManager.checkCanSetSchemaAuthorization(context(ALICE), ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"));
        accessControlManager.checkCanShowCreateSchema(context(ALICE), ALICE_SCHEMA);
        accessControlManager.checkCanGrantSchemaPrivilege(context(ALICE), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"), true);
        accessControlManager.checkCanDenySchemaPrivilege(context(ALICE), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"));
        accessControlManager.checkCanRevokeSchemaPrivilege(context(ALICE), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"), true);

        Set<String> aliceSchemas = ImmutableSet.of("schema");
        assertEquals(aliceSchemas, accessControlManager.filterSchemas(context(ALICE), ALICE_CATALOG, aliceSchemas));
        assertEquals(ImmutableSet.of(), accessControlManager.filterSchemas(context(BOB), "alice-catalog", aliceSchemas));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateSchema(context(BOB), ALICE_SCHEMA, null));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropSchema(context(BOB), ALICE_SCHEMA));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRenameSchema(context(BOB), ALICE_SCHEMA, "new-schema"));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowSchemas(context(BOB), ALICE_SCHEMA.getCatalogName()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetSchemaAuthorization(context(BOB), ALICE_SCHEMA, new TrinoPrincipal(USER, "principal")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowCreateSchema(context(BOB), ALICE_SCHEMA));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanGrantSchemaPrivilege(context(BOB), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"), true));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDenySchemaPrivilege(context(BOB), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRevokeSchemaPrivilege(context(BOB), SELECT, ALICE_SCHEMA, new TrinoPrincipal(USER, "principal"), true));
    }

    @Test
    @SuppressWarnings("PMD")
    public void testTableOperations()
    {
        CatalogSchemaTableName newTableName = new CatalogSchemaTableName("alice-catalog", "schema", "new-table");

        accessControlManager.checkCanCreateTable(context(ALICE), ALICE_TABLE, Map.of());
        accessControlManager.checkCanDropTable(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanRenameTable(context(ALICE), ALICE_TABLE, newTableName);
        accessControlManager.checkCanSetTableProperties(context(ALICE), ALICE_TABLE, Collections.emptyMap());
        accessControlManager.checkCanSetTableComment(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanSetTableAuthorization(context(ALICE), ALICE_TABLE, new TrinoPrincipal(USER, "principal"));
        accessControlManager.checkCanShowTables(context(ALICE), ALICE_SCHEMA);
        accessControlManager.checkCanShowCreateTable(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanInsertIntoTable(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanDeleteFromTable(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanTruncateTable(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanGrantTablePrivilege(context(ALICE), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "grantee"), true);
        accessControlManager.checkCanDenyTablePrivilege(context(ALICE), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "grantee"));
        accessControlManager.checkCanRevokeTablePrivilege(context(ALICE), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "revokee"), true);

        Set<SchemaTableName> aliceTables = ImmutableSet.of(new SchemaTableName("schema", "table"));
        assertEquals(aliceTables, accessControlManager.filterTables(context(ALICE), ALICE_CATALOG, aliceTables));
        assertEquals(ImmutableSet.of(), accessControlManager.filterTables(context(BOB), "alice-catalog", aliceTables));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateTable(context(BOB), ALICE_TABLE, Map.of()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropTable(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRenameTable(context(BOB), ALICE_TABLE, newTableName));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetTableProperties(context(BOB), ALICE_TABLE, Collections.emptyMap()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetTableComment(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetTableAuthorization(context(BOB), ALICE_TABLE, new TrinoPrincipal(USER, "principal")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowTables(context(BOB), ALICE_SCHEMA));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowCreateTable(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanInsertIntoTable(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDeleteFromTable(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanTruncateTable(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanGrantTablePrivilege(context(BOB), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "grantee"), true));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDenyTablePrivilege(context(BOB), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "grantee")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRevokeTablePrivilege(context(BOB), SELECT, ALICE_TABLE, new TrinoPrincipal(USER, "revokee"), true));
    }

    @Test
    public void testColumnOperations()
    {
        accessControlManager.checkCanAddColumn(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanAlterColumn(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanDropColumn(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanRenameColumn(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanSetColumnComment(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanShowColumns(context(ALICE), ALICE_TABLE);
        accessControlManager.checkCanSelectFromColumns(context(ALICE), ALICE_TABLE, ImmutableSet.of());
        accessControlManager.checkCanUpdateTableColumns(context(ALICE), ALICE_TABLE, Collections.emptySet());

        Set<String> columns = Collections.singleton("column-1");
        Map<SchemaTableName, Set<String>> tableColumns = Collections.singletonMap(ALICE_TABLE.getSchemaTableName(), columns);

        assertEquals(columns, accessControlManager.filterColumns(context(ALICE), ALICE_TABLE, columns));
        assertEquals(tableColumns, accessControlManager.filterColumns(context(ALICE), ALICE_TABLE.getCatalogName(), tableColumns));
        assertEquals(Collections.emptySet(), accessControlManager.filterColumns(context(BOB), ALICE_TABLE, columns));
        assertEquals(Collections.singletonMap(ALICE_TABLE.getSchemaTableName(), Collections.emptySet()), accessControlManager.filterColumns(context(BOB), ALICE_TABLE.getCatalogName(), tableColumns));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanAddColumn(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanAlterColumn(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropColumn(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRenameColumn(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetColumnComment(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowColumns(context(BOB), ALICE_TABLE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSelectFromColumns(context(BOB), ALICE_TABLE, ImmutableSet.of()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanUpdateTableColumns(context(BOB), ALICE_TABLE, Collections.emptySet()));
    }

    @Test
    @SuppressWarnings("PMD")
    public void testViewOperations()
    {
        CatalogSchemaTableName newViewName = new CatalogSchemaTableName(ALICE_VIEW.getCatalogName(), ALICE_VIEW.getSchemaTableName().getSchemaName(), "new-view");

        accessControlManager.checkCanCreateView(context(ALICE), ALICE_VIEW);
        accessControlManager.checkCanDropView(context(ALICE), ALICE_VIEW);
        accessControlManager.checkCanRenameView(context(ALICE), ALICE_VIEW, newViewName);
        accessControlManager.checkCanSetViewAuthorization(context(ALICE), ALICE_VIEW, new TrinoPrincipal(USER, "user"));
        accessControlManager.checkCanCreateViewWithSelectFromColumns(context(ALICE), ALICE_TABLE, ImmutableSet.of());
        accessControlManager.checkCanSetViewAuthorization(context(ALICE), ALICE_VIEW, new TrinoPrincipal(USER, "user"));
        accessControlManager.checkCanSetViewComment(context(ALICE), ALICE_VIEW);

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateView(context(BOB), ALICE_VIEW));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropView(context(BOB), ALICE_VIEW));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRenameView(context(BOB), ALICE_VIEW, newViewName));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetViewAuthorization(context(BOB), ALICE_VIEW, new TrinoPrincipal(USER, "user")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateViewWithSelectFromColumns(context(BOB), ALICE_TABLE, ImmutableSet.of()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetViewAuthorization(context(BOB), ALICE_VIEW, new TrinoPrincipal(USER, "user")));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetViewComment(context(BOB), ALICE_VIEW));
    }

    @Test
    @SuppressWarnings("PMD")
    public void testMaterializedViewOperations()
    {
        CatalogSchemaTableName newViewName = new CatalogSchemaTableName(ALICE_VIEW.getCatalogName(), ALICE_VIEW.getSchemaTableName().getSchemaName(), "new-view");

        accessControlManager.checkCanCreateMaterializedView(context(ALICE), ALICE_VIEW, Collections.emptyMap());
        accessControlManager.checkCanRefreshMaterializedView(context(ALICE), ALICE_VIEW);
        accessControlManager.checkCanSetMaterializedViewProperties(context(ALICE), ALICE_VIEW, Collections.emptyMap());
        accessControlManager.checkCanDropMaterializedView(context(ALICE), ALICE_VIEW);
        accessControlManager.checkCanRenameMaterializedView(context(ALICE), ALICE_VIEW, newViewName);

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateMaterializedView(context(BOB), ALICE_VIEW, Collections.emptyMap()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRefreshMaterializedView(context(BOB), ALICE_VIEW));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanSetMaterializedViewProperties(context(BOB), ALICE_VIEW, Collections.emptyMap()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropMaterializedView(context(BOB), ALICE_VIEW));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRenameMaterializedView(context(BOB), ALICE_VIEW, newViewName));
    }

    @Test
    public void testRoleOperations()
    {
        accessControlManager.checkCanCreateRole(context(ADMIN), "role-1", Optional.of(new TrinoPrincipal(USER, "principal")));
        accessControlManager.checkCanDropRole(context(ADMIN), "role-1");
        accessControlManager.checkCanShowRoles(context(ADMIN));
        accessControlManager.checkCanGrantRoles(context(ADMIN), Collections.singleton("role-1"), Collections.singleton(new TrinoPrincipal(USER, "principal")), false, Optional.empty());
        accessControlManager.checkCanRevokeRoles(context(ADMIN), Collections.singleton("role-1"), Collections.singleton(new TrinoPrincipal(USER, "principal")), false, Optional.empty());
        accessControlManager.checkCanShowCurrentRoles(context(ALICE));
        accessControlManager.checkCanShowRoleGrants(context(ALICE));

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanCreateRole(context(BOB), "role-1", Optional.of(new TrinoPrincipal(USER, "principal"))));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDropRole(context(BOB), "role-1"));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanShowRoles(context(BOB)));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanGrantRoles(context(BOB), Collections.singleton("role-1"), Collections.singleton(new TrinoPrincipal(USER, "principal")), false, Optional.empty()));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRevokeRoles(context(BOB), Collections.singleton("role-1"), Collections.singleton(new TrinoPrincipal(USER, "principal")), false, Optional.empty()));
    }

    @Test
    public void testProcedureOperations()
    {
        accessControlManager.checkCanExecuteProcedure(context(ALICE), ALICE_PROCEDURE);
        accessControlManager.checkCanExecuteTableProcedure(context(ALICE), ALICE_TABLE, ALICE_PROCEDURE.getRoutineName());

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanExecuteProcedure(context(BOB), ALICE_PROCEDURE));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanExecuteTableProcedure(context(BOB), ALICE_TABLE, ALICE_PROCEDURE.getRoutineName()));
    }

    @Test
    public void testFunctionOperations()
    {
        accessControlManager.checkCanCreateFunction(context(ALICE), ALICE_FUNCTION);
        accessControlManager.checkCanDropFunction(context(ALICE), ALICE_FUNCTION);
        accessControlManager.checkCanShowCreateFunction(context(ALICE), ALICE_FUNCTION);
        accessControlManager.checkCanShowFunctions(context(ALICE), ALICE_SCHEMA);
        accessControlManager.canCreateViewWithExecuteFunction(context(ALICE), ALICE_FUNCTION);

        Set<SchemaFunctionName> functionNames = Collections.singleton(new SchemaFunctionName(ALICE_SCHEMA.getSchemaName(), ALICE_FUNCTION.getRoutineName()));

        assertEquals(functionNames, accessControlManager.filterFunctions(context(ALICE), ALICE_CATALOG, functionNames));
        assertEquals(Collections.emptySet(), accessControlManager.filterFunctions(context(BOB), ALICE_CATALOG, functionNames));
    }

    @Test
    public void testEntityPrivileges()
    {
        EntityPrivilege entPrivSelect = new EntityPrivilege("select");
        TrinoPrincipal grantee = new TrinoPrincipal(USER, "user");
        boolean grantOption = false;
        EntityKindAndName entAliceSchema = new EntityKindAndName("schema", Arrays.asList(ALICE_SCHEMA.getCatalogName(), ALICE_SCHEMA.getSchemaName()));
        EntityKindAndName entAliceTable = new EntityKindAndName("table", Arrays.asList(ALICE_TABLE.getCatalogName(), ALICE_SCHEMA.getSchemaName(), ALICE_TABLE.getSchemaTableName().getTableName()));

        accessControlManager.checkCanGrantEntityPrivilege(context(ALICE), entPrivSelect, entAliceSchema, grantee, grantOption);
        accessControlManager.checkCanGrantEntityPrivilege(context(ALICE), entPrivSelect, entAliceTable, grantee, grantOption);
        accessControlManager.checkCanDenyEntityPrivilege(context(ALICE), entPrivSelect, entAliceSchema, grantee);
        accessControlManager.checkCanDenyEntityPrivilege(context(ALICE), entPrivSelect, entAliceTable, grantee);
        accessControlManager.checkCanRevokeEntityPrivilege(context(ALICE), entPrivSelect, entAliceSchema, grantee, grantOption);
        accessControlManager.checkCanRevokeEntityPrivilege(context(ALICE), entPrivSelect, entAliceTable, grantee, grantOption);

        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanGrantEntityPrivilege(context(BOB), entPrivSelect, entAliceSchema, grantee, grantOption));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanGrantEntityPrivilege(context(BOB), entPrivSelect, entAliceTable, grantee, grantOption));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDenyEntityPrivilege(context(BOB), entPrivSelect, entAliceSchema, grantee));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanDenyEntityPrivilege(context(BOB), entPrivSelect, entAliceTable, grantee));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRevokeEntityPrivilege(context(BOB), entPrivSelect, entAliceSchema, grantee, grantOption));
        assertThrows(AccessDeniedException.class, () -> accessControlManager.checkCanRevokeEntityPrivilege(context(BOB), entPrivSelect, entAliceTable, grantee, grantOption));
    }

    @Test
    @SuppressWarnings("PMD")
    public void testColumnMask()
    {
        final VarcharType varcharType = VarcharType.createVarcharType(20);

        // MASK_NONE
        Optional<ViewExpression> ret = accessControlManager.getColumnMask(context(ALICE), ALICE_TABLE, "national_id", varcharType);
        assertFalse(ret.isPresent());

        // MASK_SHOW_FIRST_4
        ret = accessControlManager.getColumnMask(context(BOB), ALICE_TABLE, "national_id", varcharType);
        assertTrue(ret.isPresent());
        assertEquals("cast(regexp_replace(national_id, '(^.{4})(.*)', x -> x[1] || regexp_replace(x[2], '.', 'X')) as varchar(20))", ret.get().getExpression());
    }

    @Test
    public void testRowFilters()
    {
        List<ViewExpression> retArray = accessControlManager.getRowFilters(context(ALICE), ALICE_TABLE);
        assertTrue(retArray.isEmpty());

        retArray = accessControlManager.getRowFilters(context(BOB), ALICE_TABLE);
        assertFalse(retArray.isEmpty());
        assertEquals(1, retArray.size());
        assertEquals("status = 'active'", retArray.get(0).getExpression());
    }

    private SystemSecurityContext context(Identity id)
    {
        return new SystemSecurityContext(id, new QueryId("id_1"), Instant.now());
    }
}
