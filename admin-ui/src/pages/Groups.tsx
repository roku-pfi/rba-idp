import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  ComboBox,
  DataTable,
  DataTableSkeleton,
  InlineNotification,
  Modal,
  OverflowMenu,
  OverflowMenuItem,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableHeader,
  TableRow,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  Tag,
  TextInput,
} from "@carbon/react";
import { Add } from "@carbon/icons-react";
import { FormEvent, useMemo, useState } from "react";
import { api, type AdminUser, type Application, type Group, type GroupDetail, type Role } from "../api";
import { Avatar, hash, Hint, PageHead, TAG_TYPES, TwoLines } from "../components";
import { useConsole } from "../console";
import { hrefOf, navigate } from "../router";
import { useLoad } from "./load";

const HEADERS = [
  { key: "name", header: "Grupo" },
  { key: "members", header: "Miembros" },
  { key: "roles", header: "Roles" },
];

export function groupTag(name: string) {
  return TAG_TYPES[hash(name) % TAG_TYPES.length];
}

/** Up to four faces, then "+N". */
function Faces({ emails, total }: { emails: string[]; total: number }) {
  if (total === 0) return <span className="rk-secondary">—</span>;
  return (
    <span className="rk-faces" title={emails.join(", ")}>
      {emails.slice(0, 4).map((email) => (
        <Avatar key={email} email={email} />
      ))}
      {total > 4 && <span className="rk-faces-more">+{total - 4}</span>}
    </span>
  );
}

function RoleTags({ roles, appName }: { roles: GroupDetail["roles"]; appName: (id: string) => string }) {
  if (roles.length === 0) return <span className="rk-secondary">—</span>;
  const rest = roles.slice(2);
  return (
    <div className="rk-tags">
      {roles.slice(0, 2).map((role) => (
        <Tag key={role.role_id} size="sm" type="cool-gray" title={appName(role.application_id)}>
          {role.name}
        </Tag>
      ))}
      {rest.length > 0 && (
        <Tag size="sm" type="outline" title={rest.map((role) => role.name).join(", ")}>
          +{rest.length}
        </Tag>
      )}
    </div>
  );
}

function useApps() {
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications").catch(() => []), [] as Application[]);
  return useMemo(() => {
    const names = new Map(apps.map((app) => [app.application_id, app.name]));
    return (id: string) => names.get(id) ?? id;
  }, [apps]);
}

function GroupPage({ groupId }: { groupId: string }) {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const appName = useApps();
  const [group, reload, loading] = useLoad(
    () => api<GroupDetail>(`/admin/api/groups/${groupId}`).catch(() => null),
    null as GroupDetail | null,
  );
  const [users] = useLoad(() => api<AdminUser[]>("/admin/api/users").catch(() => []), [] as AdminUser[]);
  const [roles] = useLoad(() => api<Role[]>("/admin/api/roles").catch(() => []), [] as Role[]);
  const [adding, setAdding] = useState<AdminUser | null>(null);
  const [assigning, setAssigning] = useState<Role | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [editing, setEditing] = useState(false);

  const apply = (request: Promise<unknown>, message?: string) =>
    request
      .then(() => {
        if (message) ok(message);
        return reload();
      })
      .catch(fail);

  const crumbs = (
    <Breadcrumb noTrailingSlash className="rk-breadcrumb">
      <BreadcrumbItem
        href={hrefOf("groups")}
        onClick={(event: React.MouseEvent) => {
          event.preventDefault();
          navigate("groups");
        }}
      >
        Grupos
      </BreadcrumbItem>
      <BreadcrumbItem isCurrentPage>{group?.name ?? "…"}</BreadcrumbItem>
    </Breadcrumb>
  );
  if (loading && !group) return crumbs;
  if (!group) {
    return (
      <>
        {crumbs}
        <InlineNotification kind="error" hideCloseButton title="No encontramos este grupo." />
      </>
    );
  }

  const candidates = users.filter((user) => !group.members.some((member) => member.user_id === user.user_id));
  const assignable = roles.filter((role) => !group.roles.some((held) => held.role_id === role.role_id));

  return (
    <>
      {crumbs}
      <PageHead
        title={group.description ? <Hint text={group.description}>{group.name}</Hint> : group.name}
        sub={`${group.members.length} miembros · ${group.roles.length} roles`}
        lead={
          <span className="rk-group-mark" data-tag={groupTag(group.name)}>
            {group.name[0].toUpperCase()}
          </span>
        }
      >
        {canWrite && (
          <OverflowMenu size="lg" flipped iconDescription="Acciones" aria-label="Acciones del grupo">
            <OverflowMenuItem itemText="Editar" onClick={() => setEditing(true)} />
            <OverflowMenuItem itemText="Eliminar" isDelete hasDivider onClick={() => setDeleting(true)} />
          </OverflowMenu>
        )}
      </PageHead>

      <Tabs>
        <TabList aria-label="Secciones del grupo">
          <Tab>Miembros ({group.members.length})</Tab>
          <Tab>Roles ({group.roles.length})</Tab>
        </TabList>
        <TabPanels>
          <TabPanel className="rk-tabpanel">
            {canWrite && (
              <div className="rk-inline-form">
                <ComboBox
                  id="add-member"
                  titleText=""
                  placeholder="Agregar un usuario"
                  items={candidates}
                  itemToString={(user: AdminUser | null) => user?.email ?? ""}
                  selectedItem={adding}
                  onChange={({ selectedItem }: { selectedItem?: AdminUser | null }) => setAdding(selectedItem ?? null)}
                />
                <Button
                  size="md"
                  disabled={!adding}
                  onClick={() => {
                    if (!adding) return;
                    void apply(
                      api(`/admin/api/groups/${group.group_id}/members`, { method: "POST", body: JSON.stringify({ user_id: adding.user_id }) }),
                    );
                    setAdding(null);
                  }}
                >
                  Agregar
                </Button>
              </div>
            )}
            {group.members.length === 0 ? (
              <p className="rk-secondary">Sin miembros.</p>
            ) : (
              <ul className="rk-list">
                {group.members.map((member) => (
                  <li key={member.user_id}>
                    <div className="rk-cell">
                      <Avatar email={member.email} />
                      <span className="rk-primary">{member.email}</span>
                    </div>
                    {canWrite && (
                      <OverflowMenu size="sm" flipped iconDescription="Acciones" aria-label={`Acciones para ${member.email}`}>
                        <OverflowMenuItem
                          itemText="Quitar del grupo"
                          isDelete
                          onClick={() =>
                            apply(api(`/admin/api/groups/${group.group_id}/members/${member.user_id}`, { method: "DELETE" }))
                          }
                        />
                      </OverflowMenu>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </TabPanel>
          <TabPanel className="rk-tabpanel">
            {canWrite && (
              <div className="rk-inline-form">
                <ComboBox
                  id="assign-role"
                  titleText=""
                  placeholder="Asignar un rol"
                  items={assignable}
                  itemToString={(role: Role | null) => (role ? `${role.name} · ${appName(role.application_id)}` : "")}
                  selectedItem={assigning}
                  onChange={({ selectedItem }: { selectedItem?: Role | null }) => setAssigning(selectedItem ?? null)}
                />
                <Button
                  size="md"
                  disabled={!assigning}
                  onClick={() => {
                    if (!assigning) return;
                    void apply(
                      api(`/admin/api/groups/${group.group_id}/roles`, { method: "POST", body: JSON.stringify({ role_id: assigning.role_id }) }),
                    );
                    setAssigning(null);
                  }}
                >
                  Asignar
                </Button>
              </div>
            )}
            {group.roles.length === 0 ? (
              <p className="rk-secondary">
                <Hint text="Sin un rol en una aplicación, los miembros no pueden iniciar sesión en ella.">Sin roles</Hint>
              </p>
            ) : (
              <ul className="rk-list">
                {group.roles.map((role) => (
                  <li key={role.role_id}>
                    <TwoLines primary={<span className="rk-mono">{role.name}</span>} secondary={appName(role.application_id)} />
                    {canWrite && (
                      <OverflowMenu size="sm" flipped iconDescription="Acciones" aria-label={`Acciones para ${role.name}`}>
                        <OverflowMenuItem
                          itemText="Quitar rol"
                          isDelete
                          onClick={() => apply(api(`/admin/api/groups/${group.group_id}/roles/${role.role_id}`, { method: "DELETE" }))}
                        />
                      </OverflowMenu>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </TabPanel>
        </TabPanels>
      </Tabs>

      <GroupForm
        open={editing}
        group={group}
        onClose={() => setEditing(false)}
        onSaved={() => {
          setEditing(false);
          void reload();
        }}
      />
      <Modal
        open={deleting}
        danger
        modalHeading={`¿Eliminar el grupo ${group.name}?`}
        primaryButtonText="Eliminar"
        secondaryButtonText="Cancelar"
        closeButtonLabel="Cerrar"
        onRequestClose={() => setDeleting(false)}
        onRequestSubmit={() =>
          api(`/admin/api/groups/${group.group_id}`, { method: "DELETE" })
            .then(() => {
              ok(`Grupo ${group.name} eliminado.`);
              navigate("groups");
            })
            .catch(fail)
        }
      >
        <p>Sus miembros pierden los roles que les daba este grupo.</p>
      </Modal>
    </>
  );
}

/** Create or rename a group. */
function GroupForm({
  open,
  group,
  onClose,
  onSaved,
}: {
  open: boolean;
  group?: GroupDetail;
  onClose: () => void;
  onSaved: (saved: GroupDetail) => void;
}) {
  const { ok, fail } = useConsole();
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const body = JSON.stringify({ name: data.get("name"), description: data.get("description") || "" });
    const request = group
      ? api<GroupDetail>(`/admin/api/groups/${group.group_id}`, { method: "PATCH", body })
      : api<GroupDetail>("/admin/api/groups", { method: "POST", body });
    request
      .then((saved) => {
        ok(group ? "Grupo actualizado." : `Grupo ${saved.name} creado.`);
        onSaved(saved);
      })
      .catch(fail);
  };
  return (
    <Modal
      open={open}
      modalHeading={group ? "Editar grupo" : "Nuevo grupo"}
      primaryButtonText={group ? "Guardar" : "Crear grupo"}
      secondaryButtonText="Cancelar"
      closeButtonLabel="Cerrar"
      onRequestClose={onClose}
      onRequestSubmit={() => (document.getElementById("group-form") as HTMLFormElement | null)?.requestSubmit()}
    >
      {open && (
        <form id="group-form" onSubmit={submit}>
          <Stack gap={6}>
            <TextInput id="g-name" name="name" labelText="Nombre" defaultValue={group?.name} required />
            <TextInput id="g-desc" name="description" labelText="Descripción" defaultValue={group?.description} />
          </Stack>
        </form>
      )}
    </Modal>
  );
}

export function Groups({ itemId }: { itemId: string | null }) {
  const { can } = useConsole();
  const appName = useApps();
  const [details, , loading] = useLoad(
    () =>
      api<Group[]>("/admin/api/groups").then((groups) =>
        Promise.all(groups.map((group) => api<GroupDetail>(`/admin/api/groups/${group.group_id}`))),
      ),
    [] as GroupDetail[],
  );
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);

  if (itemId) return <GroupPage groupId={itemId} />;

  const needle = query.trim().toLowerCase();
  const matching = details.filter(
    (group) => !needle || group.name.toLowerCase().includes(needle) || group.members.some((m) => m.email.includes(needle)),
  );
  const byId = new Map(details.map((group) => [group.group_id, group]));
  const rows = matching.map((group) => ({
    id: group.group_id,
    name: group.name,
    members: group.members.length,
    roles: group.roles.length,
  }));
  const open = (id: string) => navigate("groups", id);

  return (
    <>
      <PageHead
        title="Grupos"
        info="Los grupos dicen quién; los roles, qué puede hacer. Un usuario entra a una aplicación solo si alguno de sus grupos tiene un rol en ella."
      />
      {loading && details.length === 0 ? (
        <DataTableSkeleton headers={HEADERS} columnCount={HEADERS.length} rowCount={4} showHeader={false} />
      ) : (
        <DataTable rows={rows} headers={HEADERS} isSortable>
          {({ rows: tableRows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer>
              <TableToolbar aria-label="Grupos">
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    labelText="Buscar grupos"
                    placeholder="Buscar por grupo o miembro"
                    onChange={(event: "" | React.ChangeEvent<HTMLInputElement>) => setQuery(event ? event.target.value : "")}
                  />
                  <Button renderIcon={Add} disabled={!can("admin:write")} onClick={() => setCreating(true)}>
                    Nuevo grupo
                  </Button>
                </TableToolbarContent>
              </TableToolbar>
              <Table {...getTableProps()}>
                <TableHead>
                  <TableRow>
                    {headers.map((header) => {
                      const { key, ...props } = getHeaderProps({ header });
                      return (
                        <TableHeader key={key} {...props}>
                          {header.header}
                        </TableHeader>
                      );
                    })}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tableRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={HEADERS.length}>
                        <span className="rk-secondary">{details.length === 0 ? "Sin grupos." : "Ningún grupo coincide."}</span>
                      </TableCell>
                    </TableRow>
                  )}
                  {tableRows.map((row) => {
                    const group = byId.get(row.id)!;
                    const { key, ...props } = getRowProps({ row });
                    return (
                      <TableRow
                        key={key}
                        {...props}
                        className="rk-clickable"
                        tabIndex={0}
                        onClick={() => open(group.group_id)}
                        onKeyDown={(event: React.KeyboardEvent) => event.key === "Enter" && open(group.group_id)}
                      >
                        <TableCell>
                          <div className="rk-cell">
                            <span className="rk-group-mark" data-tag={groupTag(group.name)}>
                              {group.name[0].toUpperCase()}
                            </span>
                            {group.description ? <Hint text={group.description}>{group.name}</Hint> : <span className="rk-primary">{group.name}</span>}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Faces emails={group.members.map((m) => m.email)} total={group.members.length} />
                        </TableCell>
                        <TableCell>
                          <RoleTags roles={group.roles} appName={appName} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DataTable>
      )}
      <GroupForm
        open={creating}
        onClose={() => setCreating(false)}
        onSaved={(saved) => {
          setCreating(false);
          navigate("groups", saved.group_id);
        }}
      />
    </>
  );
}
