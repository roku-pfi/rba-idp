import { InlineLoading, Tag } from "@carbon/react";
import { useState } from "react";
import { api } from "../api";
import { Hint, PageHead } from "../components";
import { fmt } from "../i18n";
import { useLoad } from "./load";

/* D-2 on screen: how each authentication policy did on the held-out evaluation
   logins (rba-ml-training/ml/policy_compare.py, ADR-0040). The numbers are the
   same for every organisation: evidence about the engine, not the tenant's data. */

type Rate = { k: number; n: number; rate: number; wilson: [number, number]; bootstrap_users: [number, number] };
type PolicyResult = { legit_friction: Rate; legit_blocked: Rate; ato_stopped: Rate; ato_blocked: Rate };
type Comparison = {
  meta: { successful_test_logins: number; legit: number; ato: number; split_at: string; models: string[] };
  policies: Record<string, PolicyResult>;
  sweep_low_max: { low_max: number; legit_friction: number; ato_stopped: number }[];
  adaptive_by_depth: { depth: string; legit_n: number; legit_friction: number | null; ato_n: number; ato_stopped: number }[];
};

// Validated as a pair on the g100 layer (lightness, CVD ΔE ≥ 8, 3:1):
// friction is what legitimate users pay; stopped takes "Bloqueado"'s hue.
const FRICTION = "#4589ff";
const STOPPED = "#ee5396";

const ROWS: { id: string; name: string; hint: string; current?: boolean }[] = [
  { id: "password_only", name: "Solo contraseña", hint: "Lo habitual: nunca pide un segundo factor." },
  { id: "always_mfa", name: "Passkey siempre", hint: "Pide la passkey en cada inicio de sesión." },
  { id: "adaptive", name: "Adaptativa, anterior", hint: "El motor con los valores anteriores: Bajo hasta 0,30 y bloqueo en Crítico." },
  {
    id: "adaptive_default",
    name: "Adaptativa, actual",
    hint: "El motor con los valores por defecto actuales: Bajo hasta 0,40 y Crítico pide reautenticación (ADR-0040).",
    current: true,
  },
];

const pct = (x: number, digits = 0) => `${(x * 100).toLocaleString("es-AR", { maximumFractionDigits: digits, minimumFractionDigits: digits })} %`;
const interval = (r: Rate) => `IC 95 %: ${pct(r.wilson[0], 1)} – ${pct(r.wilson[1], 1)}`;

/** A 0–100 % bar with its 95 % interval as a whisker. */
function RateBar({ rate, color, label }: { rate: Rate; color: string; label: string }) {
  const [lo, hi] = rate.wilson;
  return (
    <div className="rk-ratebar" title={`${label}: ${pct(rate.rate, 1)} (${rate.k.toLocaleString("es-AR")} de ${rate.n.toLocaleString("es-AR")}). ${interval(rate)}`}>
      <div className="rk-ratebar-track">
        <span className="rk-ratebar-fill" style={{ width: `${rate.rate * 100}%`, background: color }} />
        <span className="rk-ratebar-ci" style={{ left: `${lo * 100}%`, width: `${Math.max(0.4, (hi - lo) * 100)}%` }} />
      </div>
      <span className="rk-ratebar-value">{pct(rate.rate)}</span>
    </div>
  );
}

/** Friction and stopped as the LOW band's upper limit moves. One axis (%). */
function Sweep({ points, current }: { points: Comparison["sweep_low_max"]; current: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const w = 560;
  const h = 220;
  const pad = { top: 12, right: 92, bottom: 30, left: 40 };
  const pw = w - pad.left - pad.right;
  const ph = h - pad.top - pad.bottom;
  const xs = points.map((p) => p.low_max);
  const x = (v: number) => pad.left + ((v - xs[0]) / (xs[xs.length - 1] - xs[0])) * pw;
  const y = (v: number) => pad.top + ph - v * ph;
  const line = (key: "legit_friction" | "ato_stopped") => points.map((p, i) => `${i ? "L" : "M"}${x(p.low_max)},${y(p[key])}`).join(" ");
  const last = points[points.length - 1];
  return (
    <div className="rk-chart rk-sweep">
      <ul className="rk-legend" aria-hidden="true">
        <li><span className="rk-key-line" style={{ background: STOPPED }} />Robos frenados</li>
        <li><span className="rk-key-line" style={{ background: FRICTION }} />Fricción</li>
      </ul>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Robos frenados y fricción según el límite de Bajo">
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={pad.left + pw} y1={y(t)} y2={y(t)} className="rk-grid" />
            <text x={pad.left - 8} y={y(t)} className="rk-tick" textAnchor="end" dominantBaseline="middle">{t * 100} %</text>
          </g>
        ))}
        {xs.map((v) => (
          <text key={v} x={x(v)} y={h - 8} className="rk-tick" textAnchor="middle">{v.toLocaleString("es-AR", { minimumFractionDigits: 2 })}</text>
        ))}
        {/* The value in force, marked rather than coloured. */}
        <line x1={x(current)} x2={x(current)} y1={pad.top} y2={pad.top + ph} className="rk-current" />
        <text x={x(current) + 4} y={pad.top + 10} className="rk-tick">actual</text>
        <path d={line("ato_stopped")} fill="none" stroke={STOPPED} strokeWidth={2} strokeLinejoin="round" />
        <path d={line("legit_friction")} fill="none" stroke={FRICTION} strokeWidth={2} strokeLinejoin="round" />
        <text x={x(last.low_max) + 8} y={y(last.ato_stopped)} className="rk-tick" dominantBaseline="middle">Frenados</text>
        <text x={x(last.low_max) + 8} y={y(last.legit_friction)} className="rk-tick" dominantBaseline="middle">Fricción</text>
        {points.map((p, i) => (
          <g key={p.low_max} onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} tabIndex={0}>
            <rect x={x(p.low_max) - 20} y={pad.top} width={40} height={ph} fill="transparent" />
            {hover === i && <line x1={x(p.low_max)} x2={x(p.low_max)} y1={pad.top} y2={pad.top + ph} className="rk-crosshair" />}
            <circle cx={x(p.low_max)} cy={y(p.ato_stopped)} r={4} fill={STOPPED} className="rk-dot" />
            <circle cx={x(p.low_max)} cy={y(p.legit_friction)} r={4} fill={FRICTION} className="rk-dot" />
          </g>
        ))}
      </svg>
      {hover !== null && (
        <div className="rk-tooltip" style={{ left: `${(x(points[hover].low_max) / w) * 100}%` }} role="status">
          <div className="rk-tooltip-title">Bajo hasta {points[hover].low_max.toLocaleString("es-AR", { minimumFractionDigits: 2 })}</div>
          <div className="rk-tooltip-row"><span className="rk-key" style={{ background: STOPPED }} /><strong>{pct(points[hover].ato_stopped)}</strong><span>robos frenados</span></div>
          <div className="rk-tooltip-row"><span className="rk-key" style={{ background: FRICTION }} /><strong>{pct(points[hover].legit_friction)}</strong><span>fricción</span></div>
        </div>
      )}
      <table className="cds--visually-hidden">
        <caption>Robos frenados y fricción según el límite de Bajo</caption>
        <thead><tr><th>Bajo hasta</th><th>Robos frenados</th><th>Fricción</th></tr></thead>
        <tbody>{points.map((p) => <tr key={p.low_max}><td>{p.low_max}</td><td>{pct(p.ato_stopped, 1)}</td><td>{pct(p.legit_friction, 1)}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

export function Effectiveness() {
  const [data, , loading] = useLoad(() => api<Comparison>("/admin/api/effectiveness").catch(() => null), null as Comparison | null);
  if (loading && !data) return <InlineLoading description="Cargando…" />;
  if (!data) return <PageHead title="Efectividad" sub="No disponible." />;
  const current = data.policies.adaptive_default;
  const ablation = data.policies.freeman_only;

  return (
    <>
      <PageHead
        title="Efectividad"
        sub={`Evaluación: ${fmt.count(data.meta.legit)} inicios legítimos y ${data.meta.ato} robos de cuenta reales`}
        info="Cómo le habría ido a cada política con inicios de sesión reales que el motor nunca vio al entrenarse (Wiefling et al.). Todos los robos usaron la contraseña correcta: es el caso que el motor existe para frenar. Mismos números para todas las organizaciones."
      />

      <dl className="rk-metrics">
        <div>
          <dt><Hint text={`${current.ato_stopped.k} de ${current.ato_stopped.n}. ${interval(current.ato_stopped)}. Pedir la passkey frena a quien no la tiene.`}>Robos frenados</Hint></dt>
          <dd>{pct(current.ato_stopped.rate)}</dd>
        </div>
        <div>
          <dt><Hint text={`Inicios legítimos a los que se les pidió algo más que la contraseña. ${interval(current.legit_friction)}. Con «Passkey siempre» es el 100 %.`}>Fricción</Hint></dt>
          <dd>{pct(current.legit_friction.rate)}</dd>
        </div>
        <div>
          <dt><Hint text="Inicios legítimos que no pudieron entrar. Vienen solo de la regla de intentos fallidos: un puntaje alto pide reautenticación, no bloquea.">Bloqueos legítimos</Hint></dt>
          <dd>{pct(current.legit_blocked.rate, 2)}</dd>
        </div>
      </dl>

      <section className="rk-card rk-eff-card">
        <h2 className="rk-card-title">Políticas comparadas</h2>
        <div className="rk-eff-table" role="table" aria-label="Políticas comparadas">
          <div className="rk-eff-row rk-eff-head" role="row">
            <span role="columnheader">Política</span>
            <span role="columnheader"><Hint text="Inicios legítimos desafiados. La línea fina es el intervalo de confianza del 95 %.">Fricción</Hint></span>
            <span role="columnheader"><Hint text="Robos de cuenta que no entraron. La línea fina es el intervalo de confianza del 95 %: con 38 casos es ancho.">Robos frenados</Hint></span>
            <span role="columnheader"><Hint text="Inicios legítimos que no pudieron entrar.">Bloqueos</Hint></span>
          </div>
          {ROWS.map((row) => {
            const r = data.policies[row.id];
            return (
              <div key={row.id} className={`rk-eff-row${row.current ? " is-current" : ""}`} role="row">
                <span role="cell" className="rk-eff-name">
                  <Hint text={row.hint}>{row.name}</Hint>
                  {row.current && <Tag size="sm" type="blue">Actual</Tag>}
                </span>
                <span role="cell"><RateBar rate={r.legit_friction} color={FRICTION} label="Fricción" /></span>
                <span role="cell"><RateBar rate={r.ato_stopped} color={STOPPED} label="Robos frenados" /></span>
                <span role="cell" className="rk-num">{pct(r.legit_blocked.rate, 2)}</span>
              </div>
            );
          })}
        </div>
        <p className="rk-secondary rk-eff-foot">
          <Hint text={`Sin reglas ni segundo modelo, el puntaje solo frena ${ablation.ato_stopped.k} de ${ablation.ato_stopped.n}; las reglas y el modelo supervisado suman el resto.`}>
            Solo el puntaje: {ablation.ato_stopped.k}/{ablation.ato_stopped.n}
          </Hint>
        </p>
      </section>

      <div className="rk-home">
        <section className="rk-card">
          <h2 className="rk-card-title">
            <Hint text="Subir el límite de Bajo deja entrar sin pasos extra a más inicios. Hasta 0,40 no se pierde ningún robo frenado; después cae de golpe.">Límite de «Bajo»</Hint>
          </h2>
          <Sweep points={data.sweep_low_max} current={0.4} />
        </section>
        <section className="rk-card">
          <h2 className="rk-card-title">
            <Hint text="Inicios previos del usuario. El primer inicio no tiene historia contra la cual comparar: se desafía siempre.">Según el historial</Hint>
          </h2>
          <table className="rk-share rk-depth">
            <thead><tr><th>Inicios previos</th><th>Fricción</th><th>Frenados</th></tr></thead>
            <tbody>
              {data.adaptive_by_depth.map((row) => (
                <tr key={row.depth}>
                  <td>{row.depth === "0" ? "Ninguno" : row.depth}</td>
                  <td>
                    <div className="rk-depth-bar">
                      <div className="rk-depth-track">
                        <span style={{ width: `${(row.legit_friction ?? 0) * 100}%`, background: FRICTION }} />
                      </div>
                      <em>{row.legit_friction === null ? "—" : pct(row.legit_friction)}</em>
                    </div>
                  </td>
                  <td className="rk-num">{row.ato_stopped}/{row.ato_n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </>
  );
}
