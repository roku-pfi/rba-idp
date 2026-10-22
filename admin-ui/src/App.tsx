import { useEffect, useState } from "react";
import {
  actingTenant,
  api,
  currentToken,
  logout,
  redirectToLogin,
  switchTenant,
  type SessionUser,
  type Tenant,
} from "./api";
import { ConsoleProvider } from "./console";
import { Apps } from "./pages/Apps";
import { Decisions } from "./pages/Decisions";
import { Groups } from "./pages/Groups";
import { Policy } from "./pages/Policy";
import { Roles } from "./pages/Roles";
import { Users } from "./pages/Users";
import { hrefOf, navigate, PAGES, usePage, type Page } from "./router";

const PAGE_VIEW: Record<Page, () => JSX.Element> = {
  decisions: Decisions,
  policy: Policy,
  users: Users,
  groups: Groups,
  roles: Roles,
  apps: Apps,
};

/** The session's standing in one phrase; the scopes themselves are listed below it. */
function standing(granted: string[]): string {
  if (granted.includes("tenants:read")) return "Operador de la plataforma";
  if (granted.includes("admin:write")) return "Administrador";
  return "Soporte · solo lectura";
}

export default function App() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [granted, setGranted] = useState<string[]>([]);
  const [forbidden, setForbidden] = useState(false);
  const [bootError, setBootError] = useState("");
  // ADR-0033: the tenant this console is scoped to, and — for a platform
  // operator only — every tenant, for the switcher.
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [scope, setScope] = useState<string | null>(actingTenant());
  const page = usePage();

  useEffect(() => {
    if (!currentToken()) {
      redirectToLogin();
      return;
    }
    api<{ user: SessionUser; permissions?: string[] }>("/session")
      .then((session) => {
        const perms = session.permissions ?? [];
        if (!perms.includes("admin:read")) {
          setForbidden(true);
          return;
        }
        setGranted(perms);
        setUser(session.user);
        if (perms.includes("tenants:read")) {
          // The server decides whether this is a platform operator; a 403 here
          // simply means no switcher.
          api<Tenant[]>("/admin/api/tenants").then(setTenants).catch(() => setTenants([]));
        }
      })
      .catch((err: Error) => {
        if (err.message !== "unauthorized") setBootError(err.message);
      });
  }, []);

  useEffect(() => {
    if (user) api<Tenant>("/admin/api/tenant").then(setTenant).catch(() => setTenant(null));
  }, [user, scope]);

  if (forbidden || bootError) {
    return (
      <div className="center-note">
        <img className="brand-logo" src="/static/brand/rokusec-logo-horizontal-inverse.svg" alt="RokuSec" />
        <section className="panel">
          <h1>{forbidden ? "Esta sesión no es de la consola" : "La consola no está disponible"}</h1>
          <p className="lede">
            {forbidden
              ? "Iniciá sesión con una cuenta de operador de tu organización."
              : bootError}
          </p>
          <a href="/console/login?next=/admin">Ir al inicio de sesión</a>
        </section>
      </div>
    );
  }
  if (!user) return null;

  const scopeId = scope ?? user.tenant_id;
  const View = PAGE_VIEW[page];

  return (
    <ConsoleProvider
      value={{
        user,
        tenant,
        scope: scopeId,
        can: (permission) => granted.includes(permission),
      }}
    >
      <div className="app">
        <aside className="sidebar">
          <a className="sidebar-logo" href={hrefOf("decisions")} onClick={(e) => { e.preventDefault(); navigate("decisions"); }}>
            <img className="brand-logo" src="/static/brand/rokusec-logo-horizontal-inverse.svg" alt="RokuSec" width={77} height={34} />
          </a>

          <div className="org">
            <span className="eyebrow">Organización</span>
            {tenants.length > 0 ? (
              <select
                aria-label="Organización"
                value={scopeId}
                onChange={(event) => {
                  const next = event.target.value;
                  switchTenant(next === user.tenant_id ? null : next);
                  setScope(next === user.tenant_id ? null : next);
                }}
              >
                {tenants.map((item) => (
                  <option key={item.tenant_id} value={item.tenant_id}>
                    {item.name}
                  </option>
                ))}
              </select>
            ) : (
              <strong>{tenant?.name ?? " "}</strong>
            )}
            {scope && scope !== user.tenant_id && (
              <span className="acting">Actuando sobre otra organización</span>
            )}
          </div>

          <nav className="nav" aria-label="Secciones">
            {PAGES.map((item) => (
              <a
                key={item.id}
                href={hrefOf(item.id)}
                aria-current={page === item.id ? "page" : undefined}
                onClick={(event) => {
                  event.preventDefault();
                  navigate(item.id);
                }}
              >
                {item.label}
              </a>
            ))}
          </nav>

          <details className="account">
            <summary>
              <span className="avatar" aria-hidden="true">
                {user.email[0].toUpperCase()}
              </span>
              <span className="account-who">
                <span className="account-email">{user.email}</span>
                <span className="account-role">{standing(granted)}</span>
              </span>
            </summary>
            <div className="account-menu">
              {/* What this session actually holds: the answer to "why can I see
                  this button and my colleague cannot" belongs on screen. */}
              <span className="eyebrow">Permisos de esta sesión</span>
              <div className="scopes">
                {granted.map((item) => (
                  <span className="scope" key={item}>
                    {item}
                  </span>
                ))}
              </div>
              <button className="secondary" type="button" onClick={() => void logout()}>
                Cerrar sesión
              </button>
            </div>
          </details>
        </aside>

        <main className="content">
          {/* Remounted per tenant, so no page shows the previous tenant's rows. */}
          <View key={scopeId} />
          {/* CC BY 4.0 attribution for the IP → country/ASN data (ADR-0032). */}
          <p className="attribution">
            <a href="https://db-ip.com" rel="noopener">
              Geolocalización IP por DB-IP
            </a>
          </p>
        </main>
      </div>
    </ConsoleProvider>
  );
}
