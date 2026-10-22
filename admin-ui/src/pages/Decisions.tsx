import { api, type Decision } from "../api";
import { ACTION_LABEL, fmt, label, LEVEL_LABEL, MODE_LABEL, reasonText } from "../i18n";
import { useLoad } from "./load";

export function Decisions() {
  const [decisions, , loading] = useLoad(
    () => api<{ items: Decision[] }>("/admin/api/decisions").then((body) => body.items || []),
    [] as Decision[],
  );

  return (
    <section className="panel">
      <h1>Decisiones</h1>
      <p className="lede">
        Cada inicio de sesión evaluado: el nivel de riesgo, lo que se aplicó y las señales que
        pesaron.
      </p>
      {loading ? null : decisions.length === 0 ? (
        <p className="muted">
          Todavía no hay inicios de sesión evaluados en esta organización.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Cuándo</th>
              <th>Quién</th>
              <th>Decisión</th>
              <th>Motivos</th>
            </tr>
          </thead>
          <tbody>
            {decisions.map((item) => (
              <tr key={item.event_id}>
                <td>
                  <div>{fmt.dateTime(item.occurred_at)}</div>
                  <div className="muted mono" title="ID del evento">
                    {item.event_id.slice(0, 8)}
                  </div>
                </td>
                <td>
                  <div>{item.user_id}</div>
                  <div className="muted">{item.application_id}</div>
                </td>
                <td>
                  <span className={`badge ${item.risk_level}`} title={item.risk_level}>
                    {label(LEVEL_LABEL, item.risk_level)}
                  </span>
                  <span className={`badge ${item.enforced_action}`} title={item.enforced_action}>
                    {label(ACTION_LABEL, item.enforced_action)}
                  </span>
                  {item.action !== item.enforced_action && (
                    // Monitor mode: what the engine would have done.
                    <div className="muted">
                      el motor habría pedido:{" "}
                      <span className={`badge ${item.action}`} title={item.action}>
                        {label(ACTION_LABEL, item.action)}
                      </span>
                    </div>
                  )}
                  <div className="muted">
                    puntaje {fmt.score(item.risk_score)} · {label(MODE_LABEL, item.engine_mode)}
                    {item.simulated ? " · simulado" : ""}
                  </div>
                </td>
                <td>
                  {item.reasons?.length ? (
                    <ul className="reasons">
                      {item.reasons.map((reason, index) => {
                        const { text, title } = reasonText(reason);
                        return (
                          <li key={`${item.event_id}-${index}`} title={title}>
                            {text}
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <span className="muted">Sin motivos</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
