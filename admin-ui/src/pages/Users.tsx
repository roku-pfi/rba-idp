import {
  Button,
  CopyButton,
  DataTable,
  DataTableSkeleton,
  Modal,
  OverflowMenu,
  OverflowMenuItem,
  Pagination,
  PasswordInput,
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
  Toggle,
} from "@carbon/react";
import { Add, CheckmarkFilled, CircleDash, WarningAltFilled } from "@carbon/icons-react";
import { FormEvent, useMemo, useState } from "react";
import { api, type AdminUser } from "../api";
import { useConsole } from "../console";
import { fmt } from "../i18n";
import { useLoad } from "./load";

const HEADERS = [
  { key: "email", header: "Usuario" },
  { key: "groups", header: "Grupos" },
  { key: "passkeys", header: "Passkey" },
  { key: "last_login", header: "Último inicio" },
  { key: "status", header: "Estado" },
];

// A person and a group keep their colour across pages and sessions.
const AVATAR_COLORS = ["#1466e5", "#007d79", "#8a3ffc", "#d02670", "#198038", "#0072c3"];
const TAG_TYPES = ["blue", "teal", "purple", "magenta", "green", "cyan"] as const;
const hash = (text: string) => [...text].reduce((sum, ch) => (sum * 31 + ch.charCodeAt(0)) >>> 0, 7);

function Person({ user }: { user: AdminUser }) {
  return (
    <div className="rk-cell">
      <span className="rk-avatar" style={{ background: AVATAR_COLORS[hash(user.email) % AVATAR_COLORS.length] }} aria-hidden="true">
        {user.email[0].toUpperCase()}
      </span>
      <span className="rk-cell-text">
        <span className="rk-primary">{user.email}</span>
        <span className="rk-secondary">
          {user.is_admin ? "Administrador · " : ""}alta {fmt.dateTime(user.created_at).split(",")[0]}
        </span>
      </span>
    </div>
  );
}

function Groups({ groups }: { groups: AdminUser["groups"] }) {
  if (!groups.length) return <span className="rk-secondary">Sin grupos</span>;
  const shown = groups.slice(0, 2);
  const rest = groups.slice(2);
  return (
    <div className="rk-tags">
      {shown.map((group) => (
        <Tag key={group.group_id} size="sm" type={TAG_TYPES[hash(group.name) % TAG_TYPES.length]}>
          {group.name}
        </Tag>
      ))}
      {rest.length > 0 && (
        <Tag size="sm" type="outline" title={rest.map((group) => group.name).join(", ")}>
          +{rest.length}
        </Tag>
      )}
    </div>
  );
}

/** Whether a step-up can succeed for this person (ADR-0037). */
function Passkey({ count }: { count: number }) {
  if (count > 0) {
    return (
      <span className="rk-status rk-status--ok">
        <CheckmarkFilled size={16} />
        {count === 1 ? "Registrada" : `${count} registradas`}
      </span>
    );
  }
  return (
    <span className="rk-cell-text">
      <span className="rk-status rk-status--warn">
        <WarningAltFilled size={16} />
        Sin passkey
      </span>
      <span className="rk-secondary">No puede completar una verificación</span>
    </span>
  );
}

function LastLogin({ at }: { at: string | null }) {
  if (!at) {
    return (
      <span className="rk-status rk-status--off">
        <CircleDash size={16} />
        Nunca
      </span>
    );
  }
  return (
    <span className="rk-cell-text">
      <span className="rk-primary">{fmt.ago(at)}</span>
      <span className="rk-secondary">{fmt.dateTime(at)}</span>
    </span>
  );
}

export function Users() {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [users, reload, loading] = useLoad(() => api<AdminUser[]>("/admin/api/users"), [] as AdminUser[]);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [creating, setCreating] = useState(false);
  const [disabling, setDisabling] = useState<AdminUser | null>(null);
  const [code, setCode] = useState<{ email: string; code: string; expires_at: string } | null>(null);

  const matching = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return users;
    return users.filter(
      (user) =>
        user.email.includes(needle) || user.groups.some((group) => group.name.toLowerCase().includes(needle)),
    );
  }, [users, query]);
  const shown = matching.slice((page - 1) * pageSize, page * pageSize);
  const byId = new Map(users.map((user) => [user.user_id, user]));
  // DataTable sorts on these plain values; the cells render from the user.
  const rows = shown.map((user) => ({
    id: user.user_id,
    email: user.email,
    groups: user.groups.map((group) => group.name).join(", "),
    passkeys: user.passkeys,
    last_login: user.last_login_at ?? "",
    status: user.enabled ? "1" : "0",
  }));

  const setEnabled = (user: AdminUser, enabled: boolean) =>
    api<AdminUser>(`/admin/api/users/${user.user_id}`, { method: "PATCH", body: JSON.stringify({ enabled }) })
      .then(() => ok(`${user.email} ${enabled ? "puede volver a iniciar sesión" : "ya no puede iniciar sesión"}.`))
      .then(reload)
      .catch(fail);

  // ADR-0037: how a user without a passkey gets one when every login asks for
  // it. Shown once here; the server keeps only its hash.
  const issueCode = (user: AdminUser) =>
    api<{ code: string; expires_at: string }>(`/admin/api/users/${user.user_id}/activation-code`, { method: "POST" })
      .then((issued) => setCode({ email: user.email, ...issued }))
      .catch(fail);

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    api<AdminUser>("/admin/api/users", {
      method: "POST",
      body: JSON.stringify({
        email: data.get("email"),
        password: data.get("password"),
        is_admin: data.get("is_admin") === "on",
      }),
    })
      .then((created) => {
        setCreating(false);
        ok(`${created.email} fue creado. Para su primer passkey, generale un código de activación.`);
        return reload();
      })
      .catch(fail);
  };

  if (loading && users.length === 0) {
    return <DataTableSkeleton headers={HEADERS} columnCount={HEADERS.length + 1} rowCount={5} showHeader={false} />;
  }

  return (
    <>
      <div className="rk-page-head">
        <div>
          <h1>Usuarios</h1>
          <p>
            Las personas de esta organización que pueden iniciar sesión. Lo que cada una puede hacer
            depende de sus grupos.
          </p>
        </div>
      </div>

      <DataTable rows={rows} headers={HEADERS} isSortable>
        {({ rows: tableRows, headers, getHeaderProps, getRowProps, getTableProps, getTableContainerProps }) => (
          <TableContainer {...getTableContainerProps()}>
            <TableToolbar aria-label="Usuarios">
              <TableToolbarContent>
                <TableToolbarSearch
                  persistent
                  placeholder="Buscar por email o grupo"
                  labelText="Buscar usuarios"
                  onChange={(event: "" | React.ChangeEvent<HTMLInputElement>) => {
                    setQuery(event ? event.target.value : "");
                    setPage(1);
                  }}
                />
                <Button renderIcon={Add} disabled={!canWrite} onClick={() => setCreating(true)}>
                  Nuevo usuario
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
                  <TableHeader aria-label="Acciones" />
                </TableRow>
              </TableHead>
              <TableBody>
                {tableRows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={HEADERS.length + 1}>
                      <span className="rk-secondary">Ningún usuario coincide con “{query}”.</span>
                    </TableCell>
                  </TableRow>
                )}
                {tableRows.map((row) => {
                  const user = byId.get(row.id)!;
                  const { key, ...props } = getRowProps({ row });
                  return (
                    <TableRow key={key} {...props}>
                      <TableCell>
                        <Person user={user} />
                      </TableCell>
                      <TableCell>
                        <Groups groups={user.groups} />
                      </TableCell>
                      <TableCell>
                        <Passkey count={user.passkeys} />
                      </TableCell>
                      <TableCell>
                        <LastLogin at={user.last_login_at} />
                      </TableCell>
                      <TableCell>
                        <Tag size="sm" type={user.enabled ? "green" : "gray"}>
                          {user.enabled ? "Activo" : "Deshabilitado"}
                        </Tag>
                      </TableCell>
                      <TableCell className="cds--table-column-menu">
                        {canWrite && (
                          <OverflowMenu size="sm" flipped iconDescription="Acciones" aria-label={`Acciones para ${user.email}`}>
                            {user.enabled && (
                              <OverflowMenuItem itemText="Código de activación" onClick={() => issueCode(user)} />
                            )}
                            {user.enabled ? (
                              <OverflowMenuItem itemText="Deshabilitar" isDelete hasDivider onClick={() => setDisabling(user)} />
                            ) : (
                              <OverflowMenuItem itemText="Habilitar" onClick={() => setEnabled(user, true)} />
                            )}
                          </OverflowMenu>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {matching.length > pageSize && (
              <Pagination
                page={page}
                pageSize={pageSize}
                pageSizes={[10, 25, 50]}
                totalItems={matching.length}
                itemsPerPageText="Por página:"
                backwardText="Página anterior"
                forwardText="Página siguiente"
                itemRangeText={(min: number, max: number, total: number) => `${min}–${max} de ${total}`}
                pageRangeText={(_: number, total: number) => `de ${total}`}
                onChange={({ page: next, pageSize: size }: { page: number; pageSize: number }) => {
                  setPage(next);
                  setPageSize(size);
                }}
              />
            )}
          </TableContainer>
        )}
      </DataTable>

      {/* Modals: Carbon's, so focus, Escape and the backdrop behave the same everywhere. */}
      <Modal
        open={creating}
        modalHeading="Nuevo usuario"
        closeButtonLabel="Cerrar"
        primaryButtonText="Crear usuario"
        secondaryButtonText="Cancelar"
        onRequestClose={() => setCreating(false)}
        onRequestSubmit={() => (document.getElementById("new-user") as HTMLFormElement | null)?.requestSubmit()}
      >
        {creating && (
          <form id="new-user" onSubmit={create}>
            <Stack gap={6}>
              <TextInput id="nu-email" name="email" type="email" labelText="Email" required autoComplete="off" />
              <PasswordInput
                id="nu-password"
                name="password"
                labelText="Contraseña inicial"
                helperText="La persona la usa una vez, junto con su código de activación."
                required
                autoComplete="new-password"
                showPasswordLabel="Mostrar contraseña"
                hidePasswordLabel="Ocultar contraseña"
              />
              <Toggle id="nu-admin" name="is_admin" labelText="Administrador de la organización" labelA="No" labelB="Sí" />
            </Stack>
          </form>
        )}
      </Modal>

      <Modal
        open={disabling !== null}
        danger
        modalHeading={`¿Deshabilitar a ${disabling?.email ?? ""}?`}
        closeButtonLabel="Cerrar"
        primaryButtonText="Deshabilitar"
        secondaryButtonText="Cancelar"
        onRequestClose={() => setDisabling(null)}
        onRequestSubmit={() => {
          if (disabling) void setEnabled(disabling, false);
          setDisabling(null);
        }}
      >
        <p>No va a poder iniciar sesión en ninguna aplicación. Sus grupos y su historial se conservan, y se puede volver a habilitar.</p>
      </Modal>

      <Modal
        open={code !== null}
        passiveModal
        modalHeading="Código de activación"
        closeButtonLabel="Cerrar"
        modalLabel={code?.email}
        onRequestClose={() => setCode(null)}
      >
        {code && (
          <>
            <p>Dáselo a la persona por un canal en el que confíes. Se muestra una sola vez.</p>
            <div className="rk-cell">
              <span className="rk-code">{code.code}</span>
              <CopyButton
                iconDescription="Copiar código"
                feedback="Copiado"
                onClick={() => void navigator.clipboard.writeText(code.code)}
              />
            </div>
            <p className="rk-secondary">
              Vence: {fmt.time(code.expires_at)}. Con el código y su contraseña registra una passkey en{" "}
              <span className="rk-mono">{window.location.origin}/activate</span>.
            </p>
          </>
        )}
      </Modal>
    </>
  );
}
