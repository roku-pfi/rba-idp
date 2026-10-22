import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Checkbox,
  DataTable,
  DataTableSkeleton,
  Dropdown,
  InlineNotification,
  Modal,
  Stack,
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
  Tag,
  TextInput,
} from "@carbon/react";
import { Add } from "@carbon/icons-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, type Application, type Permission, type Role, type RoleDetail } from "../api";
import { Hint, PageHead, TwoLines } from "../components";
import { useConsole } from "../console";
import { hrefOf, navigate } from "../router";
import { useLoad } from "./load";

const HEADERS = [
  { key: "name", header: "Rol" },
  { key: "app", header: "Aplicación" },
  { key: "permissions", header: "Permisos" },
];

function RolePage({ roleId, apps }: { roleId: string; apps: Application[] }) {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [role, reload, loading] = useLoad(() => api<RoleDetail>(`/admin/api/roles/${roleId}`).catch(() => null), null as RoleDetail | null);
  const [permissions] = useLoad(() => api<Permission[]>("/admin/api/permissions").catch(() => []), [] as Permission[]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  useEffect(() => setChecked(new Set(role?.permissions.map((p) => p.permission_id) ?? [])), [role]);

  const crumbs = (
    <Breadcrumb noTrailingSlash className="rk-breadcrumb">
      <BreadcrumbItem
        href={hrefOf("roles")}
        onClick={(event: React.MouseEvent) => {
          event.preventDefault();
          navigate("roles");
        }}
      >
        Roles
      </BreadcrumbItem>
      <BreadcrumbItem isCurrentPage>{role?.name ?? "…"}</BreadcrumbItem>
    </Breadcrumb>
  );
  if (loading && !role) return crumbs;
  if (!role) {
    return (
      <>
        {crumbs}
        <InlineNotification kind="error" hideCloseButton title="No encontramos este rol." />
      </>
    );
  }

  const own = permissions.filter((p) => p.application_id === role.application_id);
  // Grouped by resource: "transfer" → create, read…
  const byResource = own.reduce<Record<string, Permission[]>>((acc, p) => {
    (acc[p.resource] ??= []).push(p);
    return acc;
  }, {});
  const original = new Set(role.permissions.map((p) => p.permission_id));
  const dirty = checked.size !== original.size || [...checked].some((id) => !original.has(id));
  const appName = apps.find((app) => app.application_id === role.application_id)?.name ?? role.application_id;

  return (
    <>
      {crumbs}
      <PageHead
        title={role.description ? <Hint text={role.description}><span className="rk-mono">{role.name}</span></Hint> : <span className="rk-mono">{role.name}</span>}
        sub={appName}
      >
        <div className="rk-actions">
          <Button kind="ghost" disabled={!dirty} onClick={() => setChecked(original)}>
            Descartar
          </Button>
          <Button
            disabled={!canWrite || !dirty}
            onClick={() =>
              api<RoleDetail>(`/admin/api/roles/${role.role_id}/permissions`, {
                method: "PUT",
                body: JSON.stringify({ permission_ids: [...checked] }),
              })
                .then(() => {
                  ok(`Permisos de ${role.name} guardados.`);
                  return reload();
                })
                .catch(fail)
            }
          >
            Guardar
          </Button>
        </div>
      </PageHead>

      <section className="rk-card">
        <h2 className="rk-card-title">
          <Hint text="Un permiso es recurso:operación, la cadena que verifica la aplicación.">Permisos</Hint>
        </h2>
        {own.length === 0 ? (
          <p className="rk-secondary">Esta aplicación no define permisos.</p>
        ) : (
          <div className="rk-perm-grid">
            {Object.entries(byResource).map(([resource, items]) => (
              <fieldset key={resource} className="rk-perm-group">
                <legend className="rk-mono">{resource}</legend>
                {items.map((perm) => (
                  <Checkbox
                    key={perm.permission_id}
                    id={`perm-${perm.permission_id}`}
                    labelText={perm.description ? <Hint text={perm.description}>{perm.operation}</Hint> : perm.operation}
                    checked={checked.has(perm.permission_id)}
                    disabled={!canWrite}
                    onChange={(_: unknown, { checked: on }: { checked: boolean }) => {
                      const next = new Set(checked);
                      if (on) next.add(perm.permission_id);
                      else next.delete(perm.permission_id);
                      setChecked(next);
                    }}
                  />
                ))}
              </fieldset>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

export function Roles({ itemId }: { itemId: string | null }) {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [roles, , loading] = useLoad(() => api<Role[]>("/admin/api/roles"), [] as Role[]);
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications").catch(() => []), [] as Application[]);
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);
  const [app, setApp] = useState<Application | null>(null);
  const appName = useMemo(() => {
    const names = new Map(apps.map((a) => [a.application_id, a.name]));
    return (id: string) => names.get(id) ?? id;
  }, [apps]);

  if (itemId) return <RolePage roleId={itemId} apps={apps} />;

  const needle = query.trim().toLowerCase();
  const matching = roles.filter((role) => !needle || role.name.includes(needle) || appName(role.application_id).toLowerCase().includes(needle));
  const byId = new Map(roles.map((role) => [role.role_id, role]));
  const rows = matching.map((role) => ({
    id: role.role_id,
    name: role.name,
    app: appName(role.application_id),
    permissions: role.permission_count,
  }));
  const open = (id: string) => navigate("roles", id);

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!app) return;
    const data = new FormData(event.currentTarget);
    api<RoleDetail>("/admin/api/roles", {
      method: "POST",
      body: JSON.stringify({ application_id: app.application_id, name: data.get("name"), description: data.get("description") || "" }),
    })
      .then((created) => {
        ok(`Rol ${created.name} creado.`);
        setCreating(false);
        navigate("roles", created.role_id);
      })
      .catch(fail);
  };

  return (
    <>
      <PageHead
        title="Roles"
        info="Un rol es un conjunto de permisos sobre una aplicación. Llega a los usuarios a través de sus grupos."
      />
      {loading && roles.length === 0 ? (
        <DataTableSkeleton headers={HEADERS} columnCount={HEADERS.length} rowCount={4} showHeader={false} />
      ) : (
        <DataTable rows={rows} headers={HEADERS} isSortable>
          {({ rows: tableRows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer>
              <TableToolbar aria-label="Roles">
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    labelText="Buscar roles"
                    placeholder="Buscar por rol o aplicación"
                    onChange={(event: "" | React.ChangeEvent<HTMLInputElement>) => setQuery(event ? event.target.value : "")}
                  />
                  <Button renderIcon={Add} disabled={!canWrite} onClick={() => setCreating(true)}>
                    Nuevo rol
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
                        <span className="rk-secondary">{roles.length === 0 ? "Sin roles." : "Ningún rol coincide."}</span>
                      </TableCell>
                    </TableRow>
                  )}
                  {tableRows.map((row) => {
                    const role = byId.get(row.id)!;
                    const { key, ...props } = getRowProps({ row });
                    return (
                      <TableRow
                        key={key}
                        {...props}
                        className="rk-clickable"
                        tabIndex={0}
                        onClick={() => open(role.role_id)}
                        onKeyDown={(event: React.KeyboardEvent) => event.key === "Enter" && open(role.role_id)}
                      >
                        <TableCell>
                          {role.description ? (
                            <Hint text={role.description}>
                              <span className="rk-mono">{role.name}</span>
                            </Hint>
                          ) : (
                            <span className="rk-mono">{role.name}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <TwoLines primary={appName(role.application_id)} secondary={<span className="rk-mono">{role.application_id}</span>} />
                        </TableCell>
                        <TableCell>
                          <Tag size="sm" type="cool-gray">
                            {role.permission_count}
                          </Tag>
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
      <Modal
        open={creating}
        modalHeading="Nuevo rol"
        primaryButtonText="Crear rol"
        primaryButtonDisabled={!app}
        secondaryButtonText="Cancelar"
        closeButtonLabel="Cerrar"
        onRequestClose={() => setCreating(false)}
        onRequestSubmit={() => (document.getElementById("role-form") as HTMLFormElement | null)?.requestSubmit()}
      >
        {creating && (
          <form id="role-form" onSubmit={create}>
            <Stack gap={6}>
              <Dropdown
                id="r-app"
                titleText="Aplicación"
                label="Elegí una aplicación"
                items={apps}
                itemToString={(item: Application | null) => item?.name ?? ""}
                selectedItem={app}
                onChange={({ selectedItem }: { selectedItem: Application | null }) => setApp(selectedItem)}
              />
              <TextInput id="r-name" name="name" labelText="Nombre" placeholder="auditor" required />
              <TextInput id="r-desc" name="description" labelText="Descripción" />
            </Stack>
          </form>
        )}
      </Modal>
    </>
  );
}
