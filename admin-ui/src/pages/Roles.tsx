import { FormEvent, useState } from "react";
import { api, type Application, type Permission, type Role, type RoleDetail } from "../api";
import { useConsole } from "../console";
import { useLoad } from "./load";

export function Roles() {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [roles, reloadRoles] = useLoad(() => api<Role[]>("/admin/api/roles"), [] as Role[]);
  const [permissions] = useLoad(() => api<Permission[]>("/admin/api/permissions"), [] as Permission[]);
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications"), [] as Application[]);
  const [selected, setSelected] = useState<RoleDetail | null>(null);

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    api<RoleDetail>("/admin/api/roles", {
      method: "POST",
      body: JSON.stringify({
        application_id: String(data.get("application_id")),
        name: String(data.get("name")),
        description: String(data.get("description") || ""),
      }),
    })
      .then((created) => {
        form.reset();
        ok(`Rol ${created.name} creado.`);
        return reloadRoles();
      })
      .catch(fail);
  };

  const savePermissions = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selected) return;
    const checked = Array.from(new FormData(event.currentTarget).getAll("permission_ids")).map(String);
    api<RoleDetail>(`/admin/api/roles/${selected.role_id}/permissions`, {
      method: "PUT",
      body: JSON.stringify({ permission_ids: checked }),
    })
      .then((updated) => {
        setSelected(updated);
        ok(`Permisos de ${updated.name} guardados.`);
        return reloadRoles();
      })
      .catch(fail);
  };

  return (
    <section className="panel">
      <h1>Roles y permisos</h1>
      <p className="lede">
        Un rol es un conjunto de permisos sobre <em>una</em> aplicación. Un permiso tiene la forma{" "}
        <code>recurso:operación</code>, la misma cadena que verifica la aplicación. Los roles llegan
        a los usuarios a través de grupos.
      </p>
      <form className="form-row" onSubmit={create}>
        <label>
          Aplicación
          <select name="application_id" required>
            {apps.map((app) => (
              <option key={app.application_id} value={app.application_id}>
                {app.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Nombre
          <input name="name" placeholder="auditor" required />
        </label>
        <label>
          Descripción
          <input name="description" placeholder="Para qué sirve" />
        </label>
        <button type="submit" disabled={!canWrite}>
          Crear rol
        </button>
      </form>

      <div className="split">
        <table>
          <thead>
            <tr>
              <th>Rol</th>
              <th>Aplicación</th>
              <th>Permisos</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {roles.map((role) => (
              <tr key={role.role_id} className={selected?.role_id === role.role_id ? "selected" : ""}>
                <td>
                  <span className="mono">{role.name}</span>
                  <div className="muted">{role.description}</div>
                </td>
                <td className="mono">{role.application_id}</td>
                <td>{role.permission_count}</td>
                <td>
                  <button
                    className="secondary"
                    type="button"
                    onClick={() => api<RoleDetail>(`/admin/api/roles/${role.role_id}`).then(setSelected).catch(fail)}
                  >
                    {canWrite ? "Editar" : "Ver"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {selected ? (
          <div className="detail">
            <h2>
              {selected.name}
              <span className="muted"> en {selected.application_id}</span>
            </h2>
            <p className="muted">{selected.description}</p>
            {/* Keyed by role: the checkboxes are uncontrolled and must reset. */}
            <form key={selected.role_id} onSubmit={savePermissions}>
              <ul className="plain">
                {permissions
                  .filter((perm) => perm.application_id === selected.application_id)
                  .map((perm) => (
                    <li key={perm.permission_id}>
                      <label className="check">
                        <input
                          type="checkbox"
                          name="permission_ids"
                          value={perm.permission_id}
                          disabled={!canWrite}
                          defaultChecked={selected.permissions.some((held) => held.permission_id === perm.permission_id)}
                        />
                        <span className="mono">{perm.scope}</span>
                        <span className="muted"> {perm.description}</span>
                      </label>
                    </li>
                  ))}
              </ul>
              <button type="submit" disabled={!canWrite}>
                Guardar permisos
              </button>
            </form>
          </div>
        ) : (
          <p className="muted">Elegí un rol para ver sus permisos.</p>
        )}
      </div>
    </section>
  );
}
