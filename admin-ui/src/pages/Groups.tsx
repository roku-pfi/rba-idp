import { FormEvent, useState } from "react";
import { api, type AdminUser, type Group, type GroupDetail, type Role } from "../api";
import { useConsole } from "../console";
import { useLoad } from "./load";

export function Groups() {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [groups, reloadGroups] = useLoad(() => api<Group[]>("/admin/api/groups"), [] as Group[]);
  const [users] = useLoad(() => api<AdminUser[]>("/admin/api/users"), [] as AdminUser[]);
  const [roles] = useLoad(() => api<Role[]>("/admin/api/roles"), [] as Role[]);
  const [selected, setSelected] = useState<GroupDetail | null>(null);

  // Every change to a group returns its detail; the list's member counts follow.
  const apply = (request: Promise<GroupDetail>) =>
    request
      .then((detail) => {
        setSelected(detail);
        return reloadGroups();
      })
      .catch(fail);

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    apply(
      api<GroupDetail>("/admin/api/groups", {
        method: "POST",
        body: JSON.stringify({ name: data.get("name"), description: data.get("description") || "" }),
      }).then((created) => {
        form.reset();
        ok("Grupo creado.");
        return created;
      }),
    );
  };

  return (
    <section className="panel">
      <h1>Grupos</h1>
      <p className="lede">
        Los grupos dicen <em>quién</em>; los roles, <em>qué puede hacer</em>. Un usuario entra a
        una aplicación solo si alguno de sus grupos tiene un rol en ella (ADR-0029).
      </p>
      <form className="form-row" onSubmit={create}>
        <label>
          Nombre
          <input name="name" required />
        </label>
        <label>
          Descripción
          <input name="description" />
        </label>
        <button type="submit" disabled={!canWrite}>
          Crear grupo
        </button>
      </form>
      <div className="split">
        <table>
          <thead>
            <tr>
              <th>Grupo</th>
              <th>Miembros</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((row) => (
              <tr key={row.group_id} className={selected?.group_id === row.group_id ? "selected" : ""}>
                <td>
                  <button
                    className="linkish"
                    type="button"
                    onClick={() => api<GroupDetail>(`/admin/api/groups/${row.group_id}`).then(setSelected).catch(fail)}
                  >
                    {row.name}
                  </button>
                  <div className="muted">{row.description}</div>
                </td>
                <td>{row.member_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {selected ? (
          <div>
            <h2>{selected.name}</h2>
            <p className="muted">{selected.description || "Sin descripción"}</p>
            <button
              className="secondary"
              type="button"
              disabled={!canWrite}
              onClick={() => {
                if (!window.confirm(`¿Eliminar el grupo ${selected.name}?`)) return;
                api(`/admin/api/groups/${selected.group_id}`, { method: "DELETE" })
                  .then(() => {
                    setSelected(null);
                    ok("Grupo eliminado.");
                    return reloadGroups();
                  })
                  .catch(fail);
              }}
            >
              Eliminar grupo
            </button>
            <h3>Miembros</h3>
            <form
              className="form-row"
              onSubmit={(event: FormEvent<HTMLFormElement>) => {
                event.preventDefault();
                const userId = String(new FormData(event.currentTarget).get("user_id"));
                apply(
                  api<GroupDetail>(`/admin/api/groups/${selected.group_id}/members`, {
                    method: "POST",
                    body: JSON.stringify({ user_id: userId }),
                  }),
                );
              }}
            >
              <label>
                Usuario
                <select name="user_id" required>
                  {users
                    .filter((user) => !selected.members.some((member) => member.user_id === user.user_id))
                    .map((user) => (
                      <option key={user.user_id} value={user.user_id}>
                        {user.email}
                      </option>
                    ))}
                </select>
              </label>
              <button type="submit" disabled={!canWrite}>
                Agregar
              </button>
            </form>
            <ul className="plain">
              {selected.members.map((member) => (
                <li key={member.user_id}>
                  {member.email}
                  <button
                    className="secondary"
                    type="button"
                    disabled={!canWrite}
                    onClick={() =>
                      apply(
                        api<GroupDetail>(`/admin/api/groups/${selected.group_id}/members/${member.user_id}`, {
                          method: "DELETE",
                        }),
                      )
                    }
                  >
                    Quitar
                  </button>
                </li>
              ))}
            </ul>
            <h3>Roles</h3>
            <form
              className="form-row"
              onSubmit={(event: FormEvent<HTMLFormElement>) => {
                event.preventDefault();
                const roleId = String(new FormData(event.currentTarget).get("role_id"));
                apply(
                  api<GroupDetail>(`/admin/api/groups/${selected.group_id}/roles`, {
                    method: "POST",
                    body: JSON.stringify({ role_id: roleId }),
                  }),
                );
              }}
            >
              <label>
                Rol
                <select name="role_id" required>
                  {roles
                    .filter((role) => !selected.roles.some((held) => held.role_id === role.role_id))
                    .map((role) => (
                      <option key={role.role_id} value={role.role_id}>
                        {role.application_id} · {role.name}
                      </option>
                    ))}
                </select>
              </label>
              <button type="submit" disabled={!canWrite}>
                Asignar rol
              </button>
            </form>
            <ul className="plain">
              {selected.roles.map((role) => (
                <li key={role.role_id}>
                  <span>
                    <span className="mono">{role.name}</span>
                    <span className="muted"> en {role.application_id}</span>
                  </span>
                  <button
                    className="secondary"
                    type="button"
                    disabled={!canWrite}
                    onClick={() =>
                      apply(
                        api<GroupDetail>(`/admin/api/groups/${selected.group_id}/roles/${role.role_id}`, {
                          method: "DELETE",
                        }),
                      )
                    }
                  >
                    Quitar
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="muted">Elegí un grupo para ver sus miembros y roles.</p>
        )}
      </div>
    </section>
  );
}
