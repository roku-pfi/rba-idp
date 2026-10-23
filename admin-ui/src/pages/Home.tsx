import { ClickableTile, InlineLoading, InlineNotification, Link } from "@carbon/react";
import { ArrowRight, CheckmarkFilled, CircleDash, View, WarningAltFilled } from "@carbon/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type AdminUser, type Application, type Decision } from "../api";
import { Avatar, Hint, PageHead, TwoLines } from "../components";
import { useConsole } from "../console";
import { countryName, fmt, label, OUTCOME_LABEL } from "../i18n";
import { hrefOf, navigate } from "../router";
import { useLoad } from "./load";

const DAYS = 7;
const OUTCOMES = ["ALLOW", "REQUIRE_MFA", "REAUTHENTICATE", "BLOCK"] as const;
type Outcome = (typeof OUTCOMES)[number];

// Carbon's 50 steps in the order of the severity ramp (ADR-0030); validated as a
// categorical set on the g100 layer (#262626): lightness band, CVD ΔE ≥ 8, 3:1.
const OUTCOME_COLOR: Record<Outcome, string> = {
  ALLOW: "#24a148",
  REQUIRE_MFA: "#1192e8",
  REAUTHENTICATE: "#8a3ffc",
  BLOCK: "#ee5396",
};

type Day = { start: Date; label: string; counts: Record<Outcome, number>; total: number };

type Summary = {
  hours: { hour: string; counts: Record<string, number> }[];
  countries: { country: string; count: number }[];
};

/** The store counts by UTC hour; the days are this browser's. */
function lastDays(summary: Summary | null): Day[] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const days: Day[] = [];
  for (let i = DAYS - 1; i >= 0; i--) {
    const start = new Date(today);
    start.setDate(today.getDate() - i);
    days.push({
      start,
      label: i === 0 ? "Hoy" : i === 1 ? "Ayer" : start.toLocaleDateString("es-AR", { weekday: "short", day: "numeric" }),
      counts: { ALLOW: 0, REQUIRE_MFA: 0, REAUTHENTICATE: 0, BLOCK: 0 },
      total: 0,
    });
  }
  for (const { hour, counts } of summary?.hours ?? []) {
    const at = new Date(hour);
    const day = [...days].reverse().find((d) => at >= d.start);
    if (!day) continue;
    for (const [outcome, n] of Object.entries(counts)) {
      if (outcome in day.counts) day.counts[outcome as Outcome] += n;
      day.total += n;
    }
  }
  return days;
}

/** Clean ticks: 0 and three steps of 1, 2 or 5 × 10ⁿ covering the max. */
function ticks(max: number): number[] {
  const raw = Math.max(1, max) / 3;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * pow).find((s) => s >= raw)!;
  return [0, step, step * 2, step * 3];
}

function useWidth(): [React.RefObject<HTMLDivElement>, number] {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  useEffect(() => {
    if (!ref.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

/** Logins per day, stacked by outcome. One axis, thin columns, 2px gaps. */
function OutcomeChart({ days }: { days: Day[] }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const height = 220;
  const pad = { top: 8, right: 8, bottom: 28, left: 32 };
  const plotW = Math.max(120, width - pad.left - pad.right);
  const plotH = height - pad.top - pad.bottom;
  const scale = ticks(Math.max(...days.map((d) => d.total)));
  const top = scale[scale.length - 1];
  const band = plotW / days.length;
  const barW = Math.min(24, band * 0.5);
  const y = (v: number) => pad.top + plotH - (v / top) * plotH;

  return (
    <div className="rk-chart" ref={ref}>
      <ul className="rk-legend" aria-hidden="true">
        {OUTCOMES.map((o) => (
          <li key={o}>
            <span className="rk-swatch" style={{ background: OUTCOME_COLOR[o] }} />
            {OUTCOME_LABEL[o]}
          </li>
        ))}
      </ul>
      <svg width={width} height={height} role="img" aria-label="Inicios de sesión por día y resultado, últimos 7 días">
        {scale.map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={pad.left + plotW} y1={y(t)} y2={y(t)} className="rk-grid" />
            <text x={pad.left - 8} y={y(t)} className="rk-tick" textAnchor="end" dominantBaseline="middle">
              {fmt.count(t)}
            </text>
          </g>
        ))}
        {days.map((day, i) => {
          const cx = pad.left + band * i + band / 2;
          let base = 0;
          const segments = OUTCOMES.filter((o) => day.counts[o] > 0);
          return (
            <g
              key={day.label}
              tabIndex={0}
              className={`rk-col${hover === i ? " is-hover" : ""}`}
              onPointerEnter={() => setHover(i)}
              onPointerLeave={() => setHover(null)}
              onFocus={() => setHover(i)}
              onBlur={() => setHover(null)}
              aria-label={`${day.label}: ${day.total} inicios`}
            >
              {/* The hit target is the whole day's band, not the painted pixels. */}
              <rect x={cx - band / 2} y={pad.top} width={band} height={plotH} fill="transparent" />
              {segments.map((o, k) => {
                const y0 = y(base);
                base += day.counts[o];
                const y1 = y(base);
                const last = k === segments.length - 1;
                const h = Math.max(0, y0 - y1 - (k > 0 ? 2 : 0)); // 2px surface gap between segments
                const r = last ? Math.min(4, h) : 0;
                const x = cx - barW / 2;
                const yTop = y1;
                // Rounded data-end on the top segment only; square at the baseline.
                const d = `M${x},${yTop + h} V${yTop + r} Q${x},${yTop} ${x + r},${yTop} H${x + barW - r} Q${x + barW},${yTop} ${x + barW},${yTop + r} V${yTop + h} Z`;
                return <path key={o} d={d} fill={OUTCOME_COLOR[o]} />;
              })}
              <text x={cx} y={height - 8} className="rk-tick" textAnchor="middle">
                {day.label}
              </text>
            </g>
          );
        })}
      </svg>
      {hover !== null && (
        <div
          className="rk-tooltip"
          style={{ left: Math.min(width - 180, Math.max(0, pad.left + band * hover + band / 2 - 90)) }}
          role="status"
        >
          <div className="rk-tooltip-title">
            {days[hover].label} · {fmt.count(days[hover].total)} inicios
          </div>
          {OUTCOMES.map((o) => (
            <div key={o} className="rk-tooltip-row">
              <span className="rk-key" style={{ background: OUTCOME_COLOR[o] }} />
              <strong>{fmt.count(days[hover].counts[o])}</strong>
              <span>{OUTCOME_LABEL[o]}</span>
            </div>
          ))}
        </div>
      )}
      {/* The same numbers without hovering, for screen readers. */}
      <table className="cds--visually-hidden">
        <caption>Inicios de sesión por día y resultado</caption>
        <thead>
          <tr>
            <th>Día</th>
            {OUTCOMES.map((o) => (
              <th key={o}>{OUTCOME_LABEL[o]}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {days.map((day) => (
            <tr key={day.label}>
              <td>{day.label}</td>
              {OUTCOMES.map((o) => (
                <td key={o}>{day.counts[o]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type Policy = { engine_mode: "OFF" | "MONITOR" | "ACTIVE"; base_policy: string; policy_version: string };

const ENGINE: Record<Policy["engine_mode"], { icon: typeof View; tone: string; title: string; text: string }> = {
  ACTIVE: { icon: CheckmarkFilled, tone: "ok", title: "Activo", text: "El motor decide y su decisión se aplica." },
  MONITOR: { icon: View, tone: "info", title: "Monitoreo", text: "El motor decide pero no se aplica: se registra lo que habría hecho." },
  OFF: { icon: CircleDash, tone: "off", title: "Apagado", text: "No se evalúa el riesgo; rige solo la política base." },
};

const BASE_POLICY: Record<string, string> = {
  PASSWORD_ONLY: "solo contraseña",
  ALWAYS_MFA: "contraseña y passkey siempre",
};

function go(page: "events" | "users" | "policy", id?: string) {
  return (event: React.SyntheticEvent) => {
    event.preventDefault();
    navigate(page, id);
  };
}

type Alert = { name: string; severity: string; summary: string; since?: string | null };

// Never red (ADR-0030): critical and warning share the warning style;
// critical ones are listed first.
const ALERT_KIND: Record<string, "warning" | "info"> = {
  critical: "warning",
  warning: "warning",
  info: "info",
};

export function Home() {
  const { tenant } = useConsole();
  // Counted by the decision store; the newest 200 records alone were all load
  // users after one load test.
  const [summary, , summaryLoading] = useLoad(
    () => api<Summary>("/admin/api/decisions/summary?days=8").catch(() => null),
    null as Summary | null,
  );
  const [items] = useLoad(
    () => api<{ items: Decision[] }>("/admin/api/decisions?limit=200").then((body) => body.items || []).catch(() => null),
    [] as Decision[] | null,
  );
  const [users] = useLoad(() => api<AdminUser[]>("/admin/api/users").catch(() => []), [] as AdminUser[]);
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications").catch(() => []), [] as Application[]);
  const [policy] = useLoad(() => api<Policy>("/admin/api/policy").catch(() => null), null as Policy | null);
  const [alerts] = useLoad(() => api<Alert[]>("/admin/api/alerts").catch(() => []), [] as Alert[]);

  const emails = useMemo(() => new Map(users.map((u) => [u.user_id, u.email])), [users]);
  const appNames = useMemo(() => new Map(apps.map((a) => [a.application_id, a.name])), [apps]);
  const days = useMemo(() => lastDays(summary), [summary]);
  const since = days[0].start;
  const total = days.reduce((sum, d) => sum + d.total, 0);
  const count = (o: Outcome) => days.reduce((sum, d) => sum + d.counts[o], 0);
  const attention = (items ?? [])
    .filter((item) => new Date(item.occurred_at) >= since && item.enforced_action !== "ALLOW")
    .slice(0, 6);
  const countries = (summary?.countries ?? []).slice(0, 6).map((c) => [c.country, c.count] as [string, number]);
  const noPasskey = users.filter((u) => u.enabled && u.passkeys === 0).length;
  const engine = policy ? ENGINE[policy.engine_mode] : null;

  return (
    <>
      <PageHead
        title="Resumen"
        sub={`${tenant?.name ?? "Tu organización"} · últimos 7 días`}
        info="Lo que pasó en los inicios de sesión de tu organización esta semana y el estado de la protección."
      />

      {alerts.map((alert) => (
        // RF-16: alarms evaluated by Prometheus, this tenant's and the platform's.
        <InlineNotification
          key={alert.name}
          kind={ALERT_KIND[alert.severity] ?? "info"}
          lowContrast
          hideCloseButton
          title={alert.summary || alert.name}
          subtitle={alert.since ? `desde ${fmt.ago(alert.since)}` : undefined}
          className="rk-alert"
        />
      ))}

      {summary === null && !summaryLoading ? (
        <p className="rk-secondary rk-metrics-note">Eventos no disponibles.</p>
      ) : summaryLoading && total === 0 ? (
        <InlineLoading description="Cargando eventos…" />
      ) : (
        <dl className="rk-metrics">
          <div>
            <dt>
              <Hint text="Inicios de sesión evaluados por el motor en los últimos 7 días.">Inicios</Hint>
            </dt>
            <dd>{fmt.count(total)}</dd>
          </div>
          <div>
            <dt>
              <Hint text="Entraron solo con la contraseña: el motor los reconoció como habituales.">Sin pasos extra</Hint>
            </dt>
            <dd>{total ? `${Math.round((count("ALLOW") / total) * 100)} %` : "—"}</dd>
          </div>
          <div>
            <dt>
              <Hint text="Se les pidió la passkey o volver a autenticarse.">Verificados</Hint>
            </dt>
            <dd>{fmt.count(count("REQUIRE_MFA") + count("REAUTHENTICATE"))}</dd>
          </div>
          <div>
            <dt>
              <Hint text="El motor no los dejó entrar.">Bloqueados</Hint>
            </dt>
            <dd>{fmt.count(count("BLOCK"))}</dd>
          </div>
        </dl>
      )}

      <div className="rk-home">
        <section className="rk-card rk-card--wide">
          <h2 className="rk-card-title">Inicios de sesión por día</h2>
          <OutcomeChart days={days} />
        </section>

        <section className="rk-card">
          <h2 className="rk-card-title">Motor de riesgo</h2>
          {engine && policy ? (
            <>
              <div className={`rk-state rk-state--${engine.tone}`}>
                <engine.icon size={24} />
                <Hint text={engine.text}>{engine.title}</Hint>
              </div>
              <p className="rk-secondary">
                <Hint text="Lo que rige si el motor está apagado.">Base</Hint>: {BASE_POLICY[policy.base_policy] ?? policy.base_policy} · v{policy.policy_version}
              </p>
            </>
          ) : (
            <p className="rk-secondary">Sin datos de la política.</p>
          )}
          <Link href={hrefOf("policy")} onClick={go("policy")} renderIcon={ArrowRight} className="rk-card-link">
            Ver política
          </Link>

          <h2 className="rk-card-title rk-card-title--gap">Passkeys</h2>
          <div className={`rk-state rk-state--${noPasskey ? "warn" : "ok"}`}>
            {noPasskey ? <WarningAltFilled size={24} /> : <CheckmarkFilled size={24} />}
            <Hint
              text={
                noPasskey
                  ? "Si el motor les pide confirmar su identidad, no van a poder. Generales un código de activación."
                  : "Cualquier usuario puede completar una verificación."
              }
            >
              {noPasskey ? `${noPasskey} sin passkey` : "Todos tienen"}
            </Hint>
          </div>
          <Link href={hrefOf("users")} onClick={go("users")} renderIcon={ArrowRight} className="rk-card-link">
            Ver usuarios
          </Link>
        </section>

        <section className="rk-card rk-card--wide">
          <h2 className="rk-card-title">Requirieron atención</h2>
          {attention.length === 0 ? (
            <p className="rk-secondary">Ninguno.</p>
          ) : (
            <ul className="rk-attention">
              {attention.map((item) => (
                <li key={item.event_id}>
                  <ClickableTile href={hrefOf("events", item.event_id)} onClick={go("events", item.event_id)}>
                    <div className="rk-cell">
                      <Avatar email={emails.get(item.user_id) ?? item.user_id} />
                      <TwoLines
                        primary={emails.get(item.user_id) ?? item.user_id}
                        secondary={`${appNames.get(item.application_id) ?? item.application_id} · ${countryName(item.login?.country)}`}
                      />
                    </div>
                    <span className="rk-attention-outcome">
                      <span className="rk-swatch" style={{ background: OUTCOME_COLOR[item.enforced_action as Outcome] }} />
                      {label(OUTCOME_LABEL, item.enforced_action)}
                    </span>
                    <span className="rk-secondary">{fmt.ago(item.occurred_at)}</span>
                  </ClickableTile>
                </li>
              ))}
            </ul>
          )}
          <Link href={hrefOf("events")} onClick={go("events")} renderIcon={ArrowRight} className="rk-card-link">
            Ver todos los eventos
          </Link>
        </section>

        <section className="rk-card">
          <h2 className="rk-card-title">Desde dónde</h2>
          {countries.length === 0 ? (
            <p className="rk-secondary">Sin datos.</p>
          ) : (
            <table className="rk-share">
              <tbody>
                {countries.map(([code, n]) => (
                  <tr key={code}>
                    <td>{code === "??" ? "Desconocido" : countryName(code)}</td>
                    <td className="rk-num">{fmt.count(n)}</td>
                    <td className="rk-share-bar">
                      <span style={{ width: `${(n / countries[0][1]) * 100}%` }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </>
  );
}
