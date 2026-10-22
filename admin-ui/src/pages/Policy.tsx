import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { useConsole } from "../console";
import { useLoad } from "./load";

export function Policy() {
  const { can, ok, fail } = useConsole();
  const [policy] = useLoad(() => api<unknown>("/admin/api/policy"), null);
  const [text, setText] = useState("");
  useEffect(() => setText(policy ? JSON.stringify(policy, null, 2) : ""), [policy]);

  const save = (event: FormEvent) => {
    event.preventDefault();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      fail(new Error("El JSON no es válido."));
      return;
    }
    api<Record<string, unknown>>("/admin/api/policy", { method: "PUT", body: JSON.stringify(parsed) })
      .then((saved) => {
        setText(JSON.stringify(saved, null, 2));
        ok(`La política ${String(saved.policy_version)} está activa.`);
      })
      .catch(fail);
  };

  return (
    <section className="panel">
      <h1>Política</h1>
      <p className="lede">
        Bandas de puntaje, acción por nivel y modo del motor. Al guardar, el próximo inicio de
        sesión ya usa los nuevos valores. Hace falta <code>policy:write</code>: soporte puede
        leerla pero no cambiarla.
      </p>
      <form onSubmit={save}>
        <textarea value={text} onChange={(event) => setText(event.target.value)} />
        <button type="submit" style={{ marginTop: "0.9rem" }} disabled={!can("policy:write")}>
          Guardar política
        </button>
      </form>
    </section>
  );
}
