import { Accordion, AccordionItem, Dropdown, InlineLoading, Tag } from "@carbon/react";
import { useRef, useState } from "react";
import { api } from "../api";
import { Hint, PageHead } from "../components";
import { useConsole } from "../console";
import { fmt } from "../i18n";
import { useLoad } from "./load";

/* Efectividad: what RokuSec did for this organization's logins, against not
   using it (password only) and against asking everyone (passkey always).
   Counted per organization by the decision store (GET /admin/api/impact).
   Below, folded: the engine's evaluation on public data (ADR-0040), the same
   for every organization. */

type ImpactDay = { day: string; allowed: number; verified: number; stopped: number };
type Impact = {
  since: string;
  engine_mode: string | null;
  right_password: number;
  allowed: number;
  verified: number;
  stopped_step_up: number;
  stopped_blocked: number;
  wrong_password: number;
  wrong_password_from_blocked_ip: number;
  days: ImpactDay[];
};

type Rate = { k: number; n: number; rate: number; wilson: [number, number]; bootstrap_users: [number, number] };
type PolicyResult = { legit_friction: Rate; legit_blocked: Rate; ato_stopped: Rate; ato_blocked: Rate };
type Comparison = {
  meta: { successful_test_logins: number; legit: number; ato: number; split_at: string; models: string[] };
  policies: Record<string, PolicyResult>;
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

const ALLOWED = "#8d8d8d";
const PERIODS = [
  { days: 7, label: "Últimos 7 días" },
  { days: 30, label: "Últimos 30 días" },
  { days: 90, label: "Últimos 90 días" },
];

const share = (k: number, n: number) => (n ? pct(k / n) : "—");

/** Logins per day: in without a step, verified with the passkey, stopped. */
function Days({ days }: { days: ImpactDay[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (!days.length) return <p className="rk-secondary">Sin inicios en el período.</p>;
  const w = 560;
  const h = 200;
  const pad = { top: 8, right: 8, bottom: 26, left: 36 };
  const pw = w - pad.left - pad.right;
  const ph = h - pad.top - pad.bottom;
  const max = Math.max(1, ...days.map((d) => d.allowed + d.verified + d.stopped));
  const slot = pw / days.length;
  const bw = Math.max(2, Math.min(28, slot * 0.7));
  const y = (v: number) => (v / max) * ph;
  const label = (d: string) => new Date(`${d}T12:00:00`).toLocaleDateString("es-AR", { day: "numeric", month: "numeric" });
  const every = Math.ceil(days.length / 8);
  return (
    <div className="rk-chart">
      <ul className="rk-legend" aria-hidden="true">
        <li><span className="rk-key" style={{ background: ALLOWED }} />Sin pasos</li>
        <li><span className="rk-key" style={{ background: FRICTION }} />Con passkey</li>
        <li><span className="rk-key" style={{ background: STOPPED }} />Frenados</li>
      </ul>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Inicios por día">
        {[0, 0.5, 1].map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={pad.left + pw} y1={pad.top + ph - t * ph} y2={pad.top + ph - t * ph} className="rk-grid" />
            <text x={pad.left - 6} y={pad.top + ph - t * ph} className="rk-tick" textAnchor="end" dominantBaseline="middle">{Math.round(t * max)}</text>
          </g>
        ))}
        {days.map((d, i) => {
          const x = pad.left + i * slot + (slot - bw) / 2;
          let base = pad.top + ph;
          const parts: [number, string][] = [[d.allowed, ALLOWED], [d.verified, FRICTION], [d.stopped, STOPPED]];
          return (
            <g key={d.day} onPointerEnter={() => setHover(i)} onPointerLeave={() => setHover(null)}>
              <rect x={pad.left + i * slot} y={pad.top} width={slot} height={ph} fill="transparent" />
              {parts.map(([v, color]) => {
                const hgt = y(v);
                base -= hgt;
                return v ? <rect key={color} x={x} y={base} width={bw} height={hgt} fill={color} /> : null;
              })}
              {i % every === 0 && <text x={x + bw / 2} y={h - 8} className="rk-tick" textAnchor="middle">{label(d.day)}</text>}
            </g>
          );
        })}
      </svg>
      {hover !== null && (
        <div className="rk-tooltip" style={{ left: `${((pad.left + (hover + 0.5) * slot) / w) * 100}%` }} role="status">
          <div className="rk-tooltip-title">{label(days[hover].day)}</div>
          <div className="rk-tooltip-row"><span className="rk-key" style={{ background: ALLOWED }} /><strong>{days[hover].allowed}</strong><span>sin pasos</span></div>
          <div className="rk-tooltip-row"><span className="rk-key" style={{ background: FRICTION }} /><strong>{days[hover].verified}</strong><span>con passkey</span></div>
          <div className="rk-tooltip-row"><span className="rk-key" style={{ background: STOPPED }} /><strong>{days[hover].stopped}</strong><span>frenados</span></div>
        </div>
      )}
    </div>
  );
}

/** One policy's row: share of logins asked for the passkey, and intrusions that get in. */
function Versus({ name, hint, asked, total, intrusions, current }: {
  name: string; hint: string; asked: number; total: number; intrusions: number; current?: boolean;
}) {
  const rate = total ? asked / total : 0;
  return (
    <div className={`rk-eff-row rk-vs-row${current ? " is-current" : ""}`} role="row">
      <span role="cell" className="rk-eff-name">
        <Hint text={hint}>{name}</Hint>
        {current && <Tag size="sm" type="blue">RokuSec</Tag>}
      </span>
      <span role="cell">
        <div className="rk-ratebar">
          <div className="rk-ratebar-track"><span className="rk-ratebar-fill" style={{ width: `${rate * 100}%`, background: FRICTION }} /></div>
          <span className="rk-ratebar-value">{total ? pct(rate) : "—"}</span>
        </div>
        <span className="rk-secondary rk-vs-sub">{fmt.count(asked)} de {fmt.count(total)}</span>
      </span>
      <span role="cell" className={`rk-num rk-vs-in${intrusions ? " is-bad" : ""}`}>{fmt.count(intrusions)}</span>
    </div>
  );
}

export function Effectiveness() {
  const { tenant } = useConsole();
  const [days, setDays] = useState(30);
  const daysRef = useRef(days);
  const [impact, reload, loading] = useLoad(
    () =>
      api<Impact>(`/admin/api/impact?days=${daysRef.current}&utc_offset_minutes=${-new Date().getTimezoneOffset()}`).catch(() => null),
    null as Impact | null,
  );
  const [data] = useLoad(() => api<Comparison>("/admin/api/effectiveness").catch(() => null), null as Comparison | null);

  const org = tenant?.name ?? "tu organización";
  const period = PERIODS.find((p) => p.days === days) ?? PERIODS[1];
  const head = (
    <PageHead
      title="Efectividad"
      sub={`${org} · ${period.label.toLowerCase()}`}
      info={`Lo que hizo RokuSec con los inicios de sesión de ${org}, comparado con no usarlo (solo contraseña) y con pedir la passkey siempre. Cuenta los inicios con la contraseña correcta: son los que una contraseña sola dejaría entrar.`}
    >
      <Dropdown
        id="effectiveness-period"
        size="sm"
        titleText=""
        hideLabel
        label="Período"
        items={PERIODS}
        itemToString={(p: (typeof PERIODS)[number] | null) => p?.label ?? ""}
        selectedItem={period}
        onChange={({ selectedItem }: { selectedItem: (typeof PERIODS)[number] | null }) => {
          if (!selectedItem) return;
          daysRef.current = selectedItem.days;
          setDays(selectedItem.days);
          void reload();
        }}
      />
    </PageHead>
  );

  if (loading && !impact) return <>{head}<InlineLoading description="Cargando…" /></>;

  const i = impact;
  const stopped = i ? i.stopped_step_up + i.stopped_blocked : 0;
  const asked = i ? i.verified + i.stopped_step_up : 0;
  const monitor = i?.engine_mode === "MONITOR";

  return (
    <>
      {head}
      {!i ? (
        <p className="rk-secondary">No disponible.</p>
      ) : (
        <>
          {monitor && (
            <p className="rk-metrics-note">
              <Hint text="En Monitoreo el motor decide y registra, pero se aplica la política base. Los números muestran lo que haría el motor activo.">
                <Tag size="sm" type="warm-gray">Monitoreo</Tag>
              </Hint>
            </p>
          )}
          <dl className="rk-metrics">
            <div>
              <dt><Hint text={`Inicios con la contraseña correcta que no completaron la passkey (${i.stopped_step_up}) o fueron bloqueados (${i.stopped_blocked}). Con solo contraseña, habrían entrado.`}>Intrusiones frenadas</Hint></dt>
              <dd>{fmt.count(stopped)}</dd>
            </div>
            <div>
              <dt><Hint text={`A ${fmt.count(asked)} de ${fmt.count(i.right_password)} inicios se les pidió la passkey. Con «Passkey siempre» sería a todos.`}>Passkey pedida</Hint></dt>
              <dd>{share(asked, i.right_password)}</dd>
            </div>
            <div>
              <dt><Hint text="Inicios que entraron sin ningún paso extra porque el motor los reconoció como habituales.">Entraron sin pasos</Hint></dt>
              <dd>{share(i.allowed, i.right_password)}</dd>
            </div>
            <div>
              <dt><Hint text="Contraseñas incorrectas rechazadas porque venían de una IP bloqueada por intentos fallidos.">Ataques de contraseña bloqueados</Hint></dt>
              <dd>{fmt.count(i.wrong_password_from_blocked_ip)}</dd>
            </div>
          </dl>

          <section className="rk-card rk-eff-card">
            <h2 className="rk-card-title">Con y sin RokuSec</h2>
            <div className="rk-eff-table rk-vs-table" role="table" aria-label="Con y sin RokuSec">
              <div className="rk-eff-row rk-vs-row rk-eff-head" role="row">
                <span role="columnheader">Política</span>
                <span role="columnheader"><Hint text="Inicios con la contraseña correcta a los que se les pide la passkey.">Passkey pedida</Hint></span>
                <span role="columnheader"><Hint text="Intrusiones detectadas que habrían entrado. Las que el motor no detecta no se ven acá: para eso está la evaluación con datos públicos, abajo.">Intrusiones que entran</Hint></span>
              </div>
              <Versus name="Solo contraseña" hint="Sin RokuSec: la contraseña alcanza." asked={0} total={i.right_password} intrusions={stopped} />
              <Versus name="Passkey siempre" hint="Pedir la passkey en cada inicio de sesión." asked={i.right_password} total={i.right_password} intrusions={0} />
              <Versus name="Adaptativa" hint="RokuSec: la passkey solo cuando el inicio no se parece a los habituales." asked={asked} total={i.right_password} intrusions={0} current />
            </div>
          </section>

          <section className="rk-card">
            <h2 className="rk-card-title">
              <Hint text="Inicios con la contraseña correcta, por día y por lo que hizo el motor.">Por día</Hint>
            </h2>
            <Days days={i.days} />
          </section>
        </>
      )}

      {data && (
        <Accordion className="rk-eff-public">
          <AccordionItem title="Evaluación del motor con datos públicos (igual para todas las organizaciones)">
            <p className="rk-secondary">
              {fmt.count(data.meta.legit)} inicios legítimos y {data.meta.ato} intrusiones reales que el motor no vio al entrenarse (Wiefling et al.).
            </p>
            <div className="rk-eff-table" role="table" aria-label="Políticas comparadas con datos públicos">
              <div className="rk-eff-row rk-eff-head" role="row">
                <span role="columnheader">Política</span>
                <span role="columnheader"><Hint text="Inicios legítimos a los que se les pidió la passkey. La línea fina es el intervalo de confianza del 95 %.">Passkey pedida</Hint></span>
                <span role="columnheader"><Hint text="Tomas de control de cuenta (ATO) que no entraron. La línea fina es el intervalo de confianza del 95 %: con 38 casos es ancho.">Intrusiones frenadas</Hint></span>
                <span role="columnheader"><Hint text="Inicios legítimos que no pudieron entrar.">Bloqueos</Hint></span>
              </div>
              {ROWS.filter((row) => row.id !== "adaptive").map((row) => {
                const r = data.policies[row.id];
                return (
                  <div key={row.id} className={`rk-eff-row${row.current ? " is-current" : ""}`} role="row">
                    <span role="cell" className="rk-eff-name"><Hint text={row.hint}>{row.current ? "Adaptativa" : row.name}</Hint></span>
                    <span role="cell"><RateBar rate={r.legit_friction} color={FRICTION} label="Passkey pedida" /></span>
                    <span role="cell"><RateBar rate={r.ato_stopped} color={STOPPED} label="Intrusiones frenadas" /></span>
                    <span role="cell" className="rk-num">{pct(r.legit_blocked.rate, 2)}</span>
                  </div>
                );
              })}
            </div>
          </AccordionItem>
        </Accordion>
      )}
    </>
  );
}
