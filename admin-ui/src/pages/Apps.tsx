import { FormEvent } from "react";
import { api, type Application } from "../api";
import { useConsole } from "../console";
import { useLoad } from "./load";

export function Apps() {
  const { can, ok, fail } = useConsole();
  const [apps, reload] = useLoad(() => api<Application[]>("/admin/api/applications"), [] as Application[]);
  const canWrite = can("admin:write");

  const register = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    api<Application>("/admin/api/applications", {
      method: "POST",
      body: JSON.stringify({ application_id: data.get("application_id"), name: data.get("name") }),
    })
      .then(() => {
        form.reset();
        ok("Aplicación registrada.");
        return reload();
      })
      .catch(fail);
  };

  const toggle = (row: Application) =>
    api<Application>(`/admin/api/applications/${row.application_id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !row.enabled }),
    })
      .then(reload)
      .catch(fail);

  return (
    <section className="panel">
      <h1>Aplicaciones</h1>
      <p className="lede">
        Las aplicaciones que envían a sus usuarios a iniciar sesión acá. El login solo atiende a
        una aplicación registrada.
      </p>
      <form className="form-row" onSubmit={register}>
        <label>
          ID de la aplicación
          <input name="application_id" required />
        </label>
        <label>
          Nombre
          <input name="name" required />
        </label>
        <button type="submit" disabled={!canWrite}>
          Registrar aplicación
        </button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Aplicación</th>
            <th>Estado</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {apps.map((row) => (
            <tr key={row.application_id}>
              <td>
                {row.name}
                <div className="muted mono">{row.application_id}</div>
              </td>
              <td>{row.enabled ? "Activa" : "Deshabilitada"}</td>
              <td>
                <button className="secondary" type="button" disabled={!canWrite} onClick={() => toggle(row)}>
                  {row.enabled ? "Deshabilitar" : "Habilitar"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
