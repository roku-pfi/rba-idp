import { ClickableTile, InlineLoading, Link } from "@carbon/react";
import { ArrowRight, CheckmarkFilled, CircleDash, View, WarningAltFilled } from "@carbon/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type AdminUser, type Application, type Decision } from "../api";
import { Avatar, TwoLines } from "../components";
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

function lastDays(items: Decision[]): Day[] {
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
  for (const item of items) {
    const at = new Date(item.occurred_at);
    const day = [...days].reverse().find((d) => at >= d.start);
    if (!day) continue;
    day.counts[item.enforced_action as Outcome] += 1;
    day.total += 1;
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

export function Home() {
  const { tenant } = useConsole();
  const [items, , loading] = useLoad(
    () => api<{ items: Decision[] }>("/admin/api/decisions?limit=200").then((body) => body.items || []).catch(() => null),
    [] as Decision[] | null,
  );
  const [users] = useLoad(() => api<AdminUser[]>("/admin/api/users").catch(() => []), [] as AdminUser[]);
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications").catch(() => []), [] as Application[]);
  const [policy] = useLoad(() => api<Policy>("/admin/api/policy").catch(() => null), null as Policy | null);

  const emails = useMemo(() => new Map(users.map((u) => [u.user_id, u.email])), [users]);
  const appNames = useMemo(() => new Map(apps.map((a) => [a.application_id, a.name])), [apps]);
  const days = useMemo(() => lastDays(items ?? []), [items]);
  const since = days[0].start;
  const inRange = (items ?? []).filter((item) => new Date(item.occurred_at) >= since);
  const total = inRange.length;
  const count = (o: Outcome) => inRange.filter((item) => item.enforced_action === o).length;
  const attention = inRange.filter((item) => item.enforced_action !== "ALLOW").slice(0, 6);
  const countries = Object.entries(
    inRange.reduce<Record<string, number>>((acc, item) => {
      const code = item.login?.country ?? "??";
      acc[code] = (acc[code] ?? 0) + 1;
      return acc;
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  const noPasskey = users.filter((u) => u.enabled && u.passkeys === 0).length;
  const engine = policy ? ENGINE[policy.engine_mode] : null;

  return (
    <>
      <div className="rk-page-head">
        <div>
          <h1>Resumen</h1>
          <p>{tenant?.name ?? "Tu organización"} · últimos 7 días</p>
        </div>
      </div>

      {items === null ? (
        <p className="rk-lead">No pudimos leer los eventos ahora. El resto del resumen sigue disponible.</p>
      ) : loading && total === 0 ? (
        <InlineLoading description="Cargando eventos…" />
      ) : total === 0 ? (
        <p className="rk-lead">Todavía no hubo inicios de sesión en estos 7 días.</p>
      ) : (
        // One sentence instead of a row of stat cards: the numbers in context.
        <p className="rk-lead">
          Hubo <strong>{fmt.count(total)}</strong> inicios de sesión. El{" "}
          <strong>{Math.round((count("ALLOW") / total) * 100)} %</strong> entró sin pasos extra,{" "}
          <strong>{fmt.count(count("REQUIRE_MFA") + count("REAUTHENTICATE"))}</strong> tuvieron que confirmar
          su identidad y <strong>{fmt.count(count("BLOCK"))}</strong> se bloquearon.
        </p>
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
                <span>{engine.title}</span>
              </div>
              <p className="rk-card-text">{engine.text}</p>
              <p className="rk-secondary">
                Política base: {BASE_POLICY[policy.base_policy] ?? policy.base_policy} · versión {policy.policy_version}
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
            <span>{noPasskey ? `${noPasskey} sin passkey` : "Todos tienen"}</span>
          </div>
          <p className="rk-card-text">
            {noPasskey
              ? "Si el motor les pide confirmar su identidad, no van a poder. Generales un código de activación."
              : "Cualquier usuario puede completar una verificación."}
          </p>
          <Link href={hrefOf("users")} onClick={go("users")} renderIcon={ArrowRight} className="rk-card-link">
            Ver usuarios
          </Link>
        </section>

        <section className="rk-card rk-card--wide">
          <h2 className="rk-card-title">Requirieron atención</h2>
          {attention.length === 0 ? (
            <p className="rk-secondary">Ningún inicio necesitó pasos extra en estos 7 días.</p>
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
            <p className="rk-secondary">Sin inicios en estos 7 días.</p>
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
