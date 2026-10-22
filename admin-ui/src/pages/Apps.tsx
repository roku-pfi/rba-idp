import { Button, InlineLoading, Modal, OverflowMenu, OverflowMenuItem, Stack, Tag, TextInput } from "@carbon/react";
import { Add } from "@carbon/icons-react";
import { FormEvent, useState } from "react";
import { api, type Application } from "../api";
import { hash, Hint, PageHead } from "../components";
import { useConsole } from "../console";
import { fmt } from "../i18n";
import { useLoad } from "./load";

// An app without a logo of its own gets a monogram on a colour of its own.
const MONOGRAM = ["#1466e5", "#007d79", "#8a3ffc", "#d02670", "#198038", "#0072c3"];

function AppForm({ app, open, onClose, onSaved }: { app?: Application; open: boolean; onClose: () => void; onSaved: () => void }) {
  const { ok, fail } = useConsole();
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const redirect = String(data.get("redirect_uri") || "").trim();
    const request = app
      ? api<Application>(`/admin/api/applications/${app.application_id}`, {
          method: "PATCH",
          body: JSON.stringify({ name: data.get("name"), redirect_uri: redirect || null }),
        })
      : api<Application>("/admin/api/applications", {
          method: "POST",
          body: JSON.stringify({ application_id: data.get("application_id"), name: data.get("name"), redirect_uri: redirect || null }),
        });
    request
      .then((saved) => {
        ok(app ? `${saved.name} actualizada.` : `${saved.name} registrada.`);
        onSaved();
      })
      .catch(fail);
  };
  return (
    <Modal
      open={open}
      modalHeading={app ? `Editar ${app.name}` : "Registrar aplicación"}
      primaryButtonText={app ? "Guardar" : "Registrar"}
      secondaryButtonText="Cancelar"
      closeButtonLabel="Cerrar"
      onRequestClose={onClose}
      onRequestSubmit={() => (document.getElementById("app-form") as HTMLFormElement | null)?.requestSubmit()}
    >
      {open && (
        <form id="app-form" onSubmit={submit}>
          <Stack gap={6}>
            {!app && (
              <TextInput
                id="a-id"
                name="application_id"
                labelText="ID"
                helperText="Lo que la aplicación manda al pedir el inicio de sesión. No se puede cambiar."
                placeholder="mi-app-web"
                required
              />
            )}
            <TextInput id="a-name" name="name" labelText="Nombre" defaultValue={app?.name} required />
            <TextInput
              id="a-redirect"
              name="redirect_uri"
              labelText="URL de retorno"
              placeholder="https://mi-app.example/callback"
              defaultValue={app?.redirect_uri ?? ""}
            />
          </Stack>
        </form>
      )}
    </Modal>
  );
}

export function Apps() {
  const { can, ok, fail } = useConsole();
  const canWrite = can("admin:write");
  const [apps, reload, loading] = useLoad(() => api<Application[]>("/admin/api/applications"), [] as Application[]);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Application | null>(null);
  const [disabling, setDisabling] = useState<Application | null>(null);

  const setEnabled = (app: Application, enabled: boolean) =>
    api(`/admin/api/applications/${app.application_id}`, { method: "PATCH", body: JSON.stringify({ enabled }) })
      .then(() => ok(`${app.name} ${enabled ? "habilitada" : "deshabilitada"}.`))
      .then(reload)
      .catch(fail);

  return (
    <>
      <PageHead
        title="Aplicaciones"
        info="Las aplicaciones que mandan a sus usuarios a iniciar sesión acá. El inicio de sesión solo atiende a las registradas."
      >
        <Button renderIcon={Add} disabled={!canWrite} onClick={() => setCreating(true)}>
          Registrar aplicación
        </Button>
      </PageHead>

      {loading && apps.length === 0 ? (
        <InlineLoading description="Cargando…" />
      ) : apps.length === 0 ? (
        <p className="rk-secondary">Sin aplicaciones.</p>
      ) : (
        <ul className="rk-app-grid">
          {apps.map((app) => (
            <li key={app.application_id} className={`rk-app${app.enabled ? "" : " is-off"}`}>
              <div className="rk-app-top">
                <span className="rk-monogram" style={{ background: MONOGRAM[hash(app.application_id) % MONOGRAM.length] }} aria-hidden="true">
                  {app.name[0].toUpperCase()}
                </span>
                {canWrite && (
                  <OverflowMenu size="sm" flipped iconDescription="Acciones" aria-label={`Acciones para ${app.name}`}>
                    <OverflowMenuItem itemText="Editar" onClick={() => setEditing(app)} />
                    {app.enabled ? (
                      <OverflowMenuItem itemText="Deshabilitar" isDelete hasDivider onClick={() => setDisabling(app)} />
                    ) : (
                      <OverflowMenuItem itemText="Habilitar" onClick={() => setEnabled(app, true)} />
                    )}
                  </OverflowMenu>
                )}
              </div>
              <div className="rk-app-name">{app.name}</div>
              <div className="rk-secondary rk-mono">{app.application_id}</div>
              <div className="rk-app-foot">
                <Tag size="sm" type={app.enabled ? "green" : "gray"}>
                  {app.enabled ? "Activa" : "Deshabilitada"}
                </Tag>
                <span className="rk-secondary">
                  {app.redirect_uri ? <Hint text={app.redirect_uri}>Retorno</Hint> : "Sin retorno"} · {fmt.dateTime(app.created_at).split(",")[0]}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}

      <AppForm
        open={creating}
        onClose={() => setCreating(false)}
        onSaved={() => {
          setCreating(false);
          void reload();
        }}
      />
      <AppForm
        app={editing ?? undefined}
        open={editing !== null}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          void reload();
        }}
      />
      <Modal
        open={disabling !== null}
        danger
        modalHeading={`¿Deshabilitar ${disabling?.name ?? ""}?`}
        primaryButtonText="Deshabilitar"
        secondaryButtonText="Cancelar"
        closeButtonLabel="Cerrar"
        onRequestClose={() => setDisabling(null)}
        onRequestSubmit={() => {
          if (disabling) void setEnabled(disabling, false);
          setDisabling(null);
        }}
      >
        <p>Nadie va a poder iniciar sesión en ella hasta que se vuelva a habilitar.</p>
      </Modal>
    </>
  );
}
