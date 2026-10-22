import { FormEvent } from "react";
import { api, type AdminUser } from "../api";
import { useConsole } from "../console";
import { fmt } from "../i18n";
import { useLoad } from "./load";

export function Users() {
  const { can, ok, fail } = useConsole();
  const [users, reload] = useLoad(() => api<AdminUser[]>("/admin/api/users"), [] as AdminUser[]);
  const canWrite = can("admin:write");

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    api<AdminUser>("/admin/api/users", {
      method: "POST",
      body: JSON.stringify({
        email: data.get("email"),
        password: data.get("password"),
        is_admin: Boolean(data.get("is_admin")),
      }),
    })
      .then(() => {
        form.reset();
        ok("Usuario creado.");
        return reload();
      })
      .catch(fail);
  };

  const toggle = (row: AdminUser) =>
    api<AdminUser>(`/admin/api/users/${row.user_id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !row.enabled }),
    })
      .then(reload)
      .catch(fail);

  // ADR-0037: the only way a user without a passkey gets one when every login
  // asks for it. Shown once; stored hashed.
  const activationCode = (row: AdminUser) =>
    api<{ code: string; expires_at: string }>(`/admin/api/users/${row.user_id}/activation-code`, {
      method: "POST",
    })
      .then((issued) =>
        ok(
          `Código de activación para ${row.email}: ${issued.code}, válido hasta las ${fmt.time(
            issued.expires_at,
          )}. No se vuelve a mostrar. Se usa en /activate.`,
        ),
      )
      .catch(fail);

  return (
    <section className="panel">
      <h1>Usuarios</h1>
      <p className="lede">El directorio de esta organización. Las contraseñas nunca se muestran.</p>
      <form className="form-row" onSubmit={create}>
        <label>
          Email
          <input name="email" type="email" required />
        </label>
        <label>
          Contraseña
          <input name="password" type="password" required />
        </label>
        <label className="check">
          <input name="is_admin" type="checkbox" />
          Administrador
        </label>
        <button type="submit" disabled={!canWrite}>
          Crear usuario
        </button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Tipo</th>
            <th>Estado</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {users.map((row) => (
            <tr key={row.user_id}>
              <td>
                {row.email}
                <div className="muted mono">{row.user_id}</div>
              </td>
              <td>{row.is_admin ? "Administrador" : "Usuario"}</td>
              <td>{row.enabled ? "Activo" : "Deshabilitado"}</td>
              <td>
                <button className="secondary" type="button" disabled={!canWrite} onClick={() => toggle(row)}>
                  {row.enabled ? "Deshabilitar" : "Habilitar"}
                </button>{" "}
                {canWrite && row.enabled && (
                  <button className="secondary" type="button" onClick={() => activationCode(row)}>
                    Código de activación
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
