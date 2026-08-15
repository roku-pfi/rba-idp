import { FormEvent, useEffect, useState } from "react";
import {
  api,
  currentToken,
  logout,
  redirectToLogin,
  type AdminUser,
  type Application,
  type Decision,
  type SessionUser,
  type Tab,
} from "./api";

export default function App() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [bootError, setBootError] = useState("");
  const [tab, setTab] = useState<Tab>("decisions");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [apps, setApps] = useState<Application[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [policyText, setPolicyText] = useState("");

  useEffect(() => {
    if (!currentToken()) {
      redirectToLogin();
      return;
    }
    api<{ user: SessionUser }>("/session")
      .then((session) => {
        if (!session.user?.is_admin) {
          setForbidden(true);
          return;
        }
        setUser(session.user);
      })
      .catch((err: Error) => {
        if (err.message !== "unauthorized") setBootError(err.message);
      });
  }, []);

  useEffect(() => {
    if (!user) return;
    setError("");
    setNotice("");
    const load = async () => {
      if (tab === "users") setUsers(await api<AdminUser[]>("/admin/api/users"));
      if (tab === "apps") setApps(await api<Application[]>("/admin/api/applications"));
      if (tab === "decisions") {
        const body = await api<{ items: Decision[] }>("/admin/api/decisions");
        setDecisions(body.items || []);
      }
      if (tab === "policy") {
        const policy = await api<unknown>("/admin/api/policy");
        setPolicyText(JSON.stringify(policy, null, 2));
      }
    };
    load().catch((err: Error) => setError(err.message));
  }, [user, tab]);

  if (forbidden) {
    return (
      <div className="admin-shell">
        <section className="panel">
          <h1>Admin required</h1>
          <p className="lede">This session is not an operator. Sign in as the seeded admin user.</p>
        </section>
      </div>
    );
  }
  if (bootError) {
    return (
      <div className="admin-shell">
        <section className="panel">
          <h1>Admin unavailable</h1>
          <p className="lede">{bootError}</p>
        </section>
      </div>
    );
  }
  if (!user) return null;

  const banner = error ? (
    <p className="form-error">{error}</p>
  ) : notice ? (
    <p className="ok-msg">{notice}</p>
  ) : null;

  return (
    <div className="admin-shell">
      <header className="admin-top">
        <div>
          <p className="brand-mark">RBA Identity</p>
          <p className="brand-sub">Admin console</p>
        </div>
        <div className="who">
          {user.email}
          <button className="secondary" type="button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      <nav className="tabs">
        {(["decisions", "policy", "users", "apps"] as Tab[]).map((id) => (
          <button
            key={id}
            type="button"
            className={tab === id ? "active" : ""}
            onClick={() => setTab(id)}
          >
            {id === "apps" ? "Applications" : id[0].toUpperCase() + id.slice(1)}
          </button>
        ))}
      </nav>

      {tab === "decisions" && (
        <section className="panel">
          <h1>Decisions</h1>
          <p className="lede">
            Every scored login with the PDP action and per-signal reasons. This is the thesis core,
            browsable.
          </p>
          {banner}
          {decisions.length === 0 ? (
            <p className="muted">
              No scored logins yet. Sign in once (demo or admin) so the PDP
            persists a decision — this list reads that table, not the async
            audit pipeline.
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Who</th>
                  <th>Decision</th>
                  <th>Reasons</th>
                </tr>
              </thead>
              <tbody>
                {decisions.map((item) => (
                  <tr key={item.event_id}>
                    <td>
                      <div className="mono">{item.event_id}</div>
                      <div className="muted">{new Date(item.occurred_at).toLocaleString()}</div>
                    </td>
                    <td>
                      <div>{item.user_id}</div>
                      <div className="muted">{item.application_id}</div>
                    </td>
                    <td>
                      <span className={`badge ${item.risk_level}`}>{item.risk_level}</span>
                      <span className={`badge ${item.action}`}>{item.action}</span>
                      <div className="muted">
                        score {item.risk_score.toFixed(2)} · policy {item.policy_version}
                      </div>
                    </td>
                    <td>
                      {item.reasons?.length ? (
                        <ul className="reasons">
                          {item.reasons.map((reason, index) => (
                            <li key={`${item.event_id}-${index}`}>
                              {reason.detail || reason.code}
                              {reason.signal ? <div className="signal">{reason.signal}</div> : null}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="muted">No reasons</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      {tab === "policy" && (
        <section className="panel">
          <h1>Policy</h1>
          <p className="lede">
            Score bands and level→action map. Saving hot-reloads the PDP; the next login uses the
            new thresholds.
          </p>
          {banner}
          <form
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              try {
                const parsed = JSON.parse(policyText);
                api<Record<string, unknown>>("/admin/api/policy", {
                  method: "PUT",
                  body: JSON.stringify(parsed),
                })
                  .then((saved) => {
                    setPolicyText(JSON.stringify(saved, null, 2));
                    setNotice(`Policy ${String(saved.policy_version)} is active.`);
                    setError("");
                  })
                  .catch((err: Error) => setError(err.message));
              } catch (err) {
                setError(err instanceof Error ? err.message : "Invalid JSON");
              }
            }}
          >
            <textarea value={policyText} onChange={(event) => setPolicyText(event.target.value)} />
            <button type="submit" style={{ marginTop: "0.9rem" }}>
              Save policy
            </button>
          </form>
        </section>
      )}

      {tab === "users" && (
        <section className="panel">
          <h1>Users</h1>
          <p className="lede">Directory of this IdP. Passwords are never listed.</p>
          {banner}
          <form
            className="form-row"
            onSubmit={(event: FormEvent<HTMLFormElement>) => {
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
                  setNotice("User created.");
                  return api<AdminUser[]>("/admin/api/users");
                })
                .then(setUsers)
                .catch((err: Error) => setError(err.message));
            }}
          >
            <label>
              Email
              <input name="email" type="email" required />
            </label>
            <label>
              Password
              <input name="password" type="password" required />
            </label>
            <label className="check">
              <input name="is_admin" type="checkbox" />
              Admin
            </label>
            <button type="submit">Create user</button>
          </form>
          <table>
            <thead>
              <tr>
                <th>User id</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((row) => (
                <tr key={row.user_id}>
                  <td className="mono">{row.user_id}</td>
                  <td>{row.email}</td>
                  <td>{row.is_admin ? "admin" : "user"}</td>
                  <td>{row.enabled ? "enabled" : "disabled"}</td>
                  <td>
                    <button
                      className="secondary"
                      type="button"
                      onClick={() => {
                        api<AdminUser>(`/admin/api/users/${row.user_id}`, {
                          method: "PATCH",
                          body: JSON.stringify({ enabled: !row.enabled }),
                        })
                          .then(() => api<AdminUser[]>("/admin/api/users"))
                          .then(setUsers)
                          .catch((err: Error) => setError(err.message));
                      }}
                    >
                      {row.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === "apps" && (
        <section className="panel">
          <h1>Applications</h1>
          <p className="lede">Registered clients. Hosted login requires a known application_id.</p>
          {banner}
          <form
            className="form-row"
            onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              const form = event.currentTarget;
              const data = new FormData(form);
              api<Application>("/admin/api/applications", {
                method: "POST",
                body: JSON.stringify({
                  application_id: data.get("application_id"),
                  name: data.get("name"),
                }),
              })
                .then(() => {
                  form.reset();
                  setNotice("Application registered.");
                  return api<Application[]>("/admin/api/applications");
                })
                .then(setApps)
                .catch((err: Error) => setError(err.message));
            }}
          >
            <label>
              Application id
              <input name="application_id" required />
            </label>
            <label>
              Name
              <input name="name" required />
            </label>
            <button type="submit">Register app</button>
          </form>
          <table>
            <thead>
              <tr>
                <th>Id</th>
                <th>Name</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {apps.map((row) => (
                <tr key={row.application_id}>
                  <td className="mono">{row.application_id}</td>
                  <td>{row.name}</td>
                  <td>{row.enabled ? "enabled" : "disabled"}</td>
                  <td>
                    <button
                      className="secondary"
                      type="button"
                      onClick={() => {
                        api<Application>(`/admin/api/applications/${row.application_id}`, {
                          method: "PATCH",
                          body: JSON.stringify({ enabled: !row.enabled }),
                        })
                          .then(() => api<Application[]>("/admin/api/applications"))
                          .then(setApps)
                          .catch((err: Error) => setError(err.message));
                      }}
                    >
                      {row.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
