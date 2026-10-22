import {
  Button,
  Dropdown,
  InlineLoading,
  Modal,
  NumberInput,
  RadioButton,
  RadioButtonGroup,
  RadioTile,
  Tag,
  TileGroup,
} from "@carbon/react";
import { CheckmarkFilled, CircleDash, Locked, View } from "@carbon/icons-react";
import { useEffect, useMemo, useState } from "react";
import { api, type Decision } from "../api";
import { Hint, PageHead } from "../components";
import { useConsole } from "../console";
import { fmt, label, LEVEL_LABEL, OUTCOME_LABEL } from "../i18n";
import { useLoad } from "./load";

type Level = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type Action = "ALLOW" | "REQUIRE_MFA" | "REAUTHENTICATE" | "BLOCK";
type Mode = "OFF" | "MONITOR" | "ACTIVE";

type TenantPolicy = {
  tenant_id: string;
  policy_version: string;
  base_policy: "PASSWORD_ONLY" | "ALWAYS_MFA";
  engine_mode: Mode;
  score_to_level: { max: number; level: Level }[];
  level_to_action: Record<Level, Action>;
  fallback_action: Action;
};

const ACTIONS: Action[] = ["ALLOW", "REQUIRE_MFA", "REAUTHENTICATE", "BLOCK"];
// The same severity ramp as the tags elsewhere (ADR-0030), as Carbon 50 steps.
const LEVEL_COLOR: Record<Level, string> = { LOW: "#24a148", MEDIUM: "#1192e8", HIGH: "#8a3ffc", CRITICAL: "#ee5396" };
const LEVEL_TAG: Record<Level, "green" | "cyan" | "purple" | "magenta"> = {
  LOW: "green",
  MEDIUM: "cyan",
  HIGH: "purple",
  CRITICAL: "magenta",
};

const MODES: { id: Mode; title: string; short: string; hint: string; icon: typeof View }[] = [
  { id: "OFF", title: "Apagado", short: "Solo la política base", hint: "No se consulta al motor. Rige la política base.", icon: CircleDash },
  { id: "MONITOR", title: "Monitoreo", short: "Registra, no aplica", hint: "El motor evalúa y se registra lo que habría hecho, pero rige la política base. Para probar umbrales sin afectar a nadie.", icon: View },
  { id: "ACTIVE", title: "Activo", short: "Aplica la decisión", hint: "La decisión del motor se aplica a cada inicio de sesión.", icon: CheckmarkFilled },
];

const BASE: { id: TenantPolicy["base_policy"]; label: string }[] = [
  { id: "PASSWORD_ONLY", label: "Solo contraseña" },
  { id: "ALWAYS_MFA", label: "Contraseña y passkey siempre" },
];

const ACTION_VERB: Record<Action, string> = {
  ALLOW: "Permitir",
  REQUIRE_MFA: "Pedir passkey",
  REAUTHENTICATE: "Reautenticar",
  BLOCK: "Bloquear",
};

function nextVersion(version: string): string {
  const parts = version.split(".");
  const last = Number(parts[parts.length - 1]);
  if (Number.isNaN(last)) return `${version}.1`;
  parts[parts.length - 1] = String(last + 1);
  return parts.join(".");
}

function levelOf(score: number, bands: TenantPolicy["score_to_level"]): Level {
  return (bands.find((band) => score <= band.max) ?? bands[bands.length - 1]).level;
}

/** Problems that would make the PDP reject the policy, in the operator's words. */
function problems(policy: TenantPolicy): string[] {
  const out: string[] = [];
  const maxima = policy.score_to_level.map((band) => band.max);
  for (let i = 1; i < maxima.length; i++) {
    if (!(maxima[i] > maxima[i - 1])) out.push(`El límite de ${label(LEVEL_LABEL, policy.score_to_level[i].level)} tiene que ser mayor que el de ${label(LEVEL_LABEL, policy.score_to_level[i - 1].level)}.`);
  }
  if (maxima.some((max) => max <= 0 || max > 1)) out.push("Los límites van entre 0 y 1.");
  return out;
}

/** The 0–1 score line, split where the levels change. */
function BandBar({ bands, scores }: { bands: TenantPolicy["score_to_level"]; scores: number[] }) {
  let from = 0;
  return (
    <div className="rk-bandbar" aria-hidden="true">
      <div className="rk-bandbar-track">
        {bands.map((band) => {
          const width = Math.max(0, band.max - from) * 100;
          const start = from;
          from = band.max;
          return (
            <span key={band.level} style={{ width: `${width}%`, background: LEVEL_COLOR[band.level] }} title={`${label(LEVEL_LABEL, band.level)}: ${fmt.score(start)}–${fmt.score(band.max)}`} />
          );
        })}
      </div>
      {/* Where recent logins actually scored, so a threshold is moved knowingly. */}
      <div className="rk-bandbar-dots">
        {scores.map((score, index) => (
          <i key={index} style={{ left: `${score * 100}%` }} />
        ))}
      </div>
      <div className="rk-bandbar-scale">
        <span>0</span>
        <span>0,5</span>
        <span>1</span>
      </div>
    </div>
  );
}

export function Policy() {
  const { can, ok, fail } = useConsole();
  const canWrite = can("policy:write");
  const [saved, reload, loading] = useLoad(() => api<TenantPolicy>("/admin/api/policy").catch(() => null), null as TenantPolicy | null);
  const [events] = useLoad(
    () => api<{ items: Decision[] }>("/admin/api/decisions?limit=200").then((body) => body.items || []).catch(() => []),
    [] as Decision[],
  );
  const [draft, setDraft] = useState<TenantPolicy | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);
  useEffect(() => setDraft(saved), [saved]);

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(saved), [draft, saved]);
  const scored = events.filter((event) => !event.fallback);
  // What the engine would decide for the recent logins under the draft, next
  // to what it decided under the policy in force at the time.
  const impact = useMemo(() => {
    const now: Record<Action, number> = { ALLOW: 0, REQUIRE_MFA: 0, REAUTHENTICATE: 0, BLOCK: 0 };
    const then: Record<Action, number> = { ALLOW: 0, REQUIRE_MFA: 0, REAUTHENTICATE: 0, BLOCK: 0 };
    if (!draft) return { now, then };
    for (const event of scored) {
      now[draft.level_to_action[levelOf(event.risk_score, draft.score_to_level)]] += 1;
      then[event.action as Action] += 1;
    }
    return { now, then };
  }, [draft, scored]);

  if (loading && !draft) return <InlineLoading description="Cargando política…" />;
  if (!draft || !saved) {
    return (
      <>
        <PageHead title="Política" />
        <p className="rk-secondary">Política no disponible.</p>
      </>
    );
  }

  const set = (patch: Partial<TenantPolicy>) => setDraft({ ...draft, ...patch });
  const issues = problems(draft);
  const modeChanged = draft.engine_mode !== saved.engine_mode;

  const save = () => {
    setSaving(true);
    const body = { ...draft, policy_version: nextVersion(saved.policy_version) };
    api<TenantPolicy>("/admin/api/policy", { method: "PUT", body: JSON.stringify(body) })
      .then((result) => {
        ok(`Política v${result.policy_version} activa.`);
        return reload();
      })
      .catch(fail)
      .finally(() => {
        setSaving(false);
        setConfirming(false);
      });
  };

  let from = 0;
  return (
    <>
      <PageHead
        title="Política"
        sub={`v${saved.policy_version}`}
        info="Cómo se decide cada inicio de sesión de esta organización. Los cambios rigen desde el próximo inicio."
      >
        <div className="rk-actions">
          {!canWrite && (
            <Tag type="cool-gray" renderIcon={Locked}>
              <Hint text="Hace falta el permiso policy:write para cambiarla.">Solo lectura</Hint>
            </Tag>
          )}
          <Button kind="ghost" disabled={!dirty || saving} onClick={() => setDraft(saved)}>
            Descartar
          </Button>
          <Button
            disabled={!canWrite || !dirty || issues.length > 0 || saving}
            onClick={() => (modeChanged ? setConfirming(true) : save())}
          >
            {saving ? "Guardando…" : "Guardar"}
          </Button>
        </div>
      </PageHead>

      <div className="rk-policy">
        <section className="rk-card">
          <h2 className="rk-card-title">
            <Hint text="Si el motor de riesgo decide, solo registra, o no participa.">Modo del motor</Hint>
          </h2>
          <TileGroup
            name="engine-mode"
            legend=""
            valueSelected={draft.engine_mode}
            onChange={(value: string) => set({ engine_mode: value as Mode })}
            className="rk-modes"
          >
            {MODES.map((mode) => (
              <RadioTile key={mode.id} id={`mode-${mode.id}`} value={mode.id} disabled={!canWrite}>
                <span className="rk-mode">
                  <mode.icon size={20} />
                  <Hint text={mode.hint}>{mode.title}</Hint>
                  <span className="rk-secondary">{mode.short}</span>
                </span>
              </RadioTile>
            ))}
          </TileGroup>
        </section>

        <section className="rk-card">
          <h2 className="rk-card-title">
            <Hint text="Lo que rige con el motor apagado o en monitoreo. El segundo factor es siempre la passkey.">Política base</Hint>
          </h2>
          <RadioButtonGroup
            name="base-policy"
            legendText=""
            orientation="vertical"
            valueSelected={draft.base_policy}
            onChange={(value: string | number | undefined) => set({ base_policy: value as TenantPolicy["base_policy"] })}
            disabled={!canWrite}
          >
            {BASE.map((base) => (
              <RadioButton key={base.id} id={`base-${base.id}`} value={base.id} labelText={base.label} />
            ))}
          </RadioButtonGroup>
          <h2 className="rk-card-title rk-card-title--gap">
            <Hint text="Qué se hace si el motor no responde o falla al evaluar.">Si el motor falla</Hint>
          </h2>
          <Dropdown
            id="fallback"
            titleText=""
            label="Acción"
            hideLabel
            items={ACTIONS}
            itemToString={(value: Action | null) => (value ? ACTION_VERB[value] : "")}
            selectedItem={draft.fallback_action}
            onChange={({ selectedItem }: { selectedItem: Action | null }) => selectedItem && set({ fallback_action: selectedItem })}
            disabled={!canWrite}
          />
        </section>

        <section className="rk-card rk-card--full">
          <h2 className="rk-card-title">
            <Hint text="El motor da un puntaje de 0 a 1. Cada franja es un nivel de riesgo, y cada nivel tiene una acción. Los puntos son los inicios recientes.">
              Niveles de riesgo
            </Hint>
          </h2>
          <BandBar bands={draft.score_to_level} scores={scored.map((event) => event.risk_score)} />
          <table className="rk-levels">
            <thead>
              <tr>
                <th>Nivel</th>
                <th>Desde</th>
                <th>Hasta</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody>
              {draft.score_to_level.map((band, index) => {
                const start = from;
                from = band.max;
                const last = index === draft.score_to_level.length - 1;
                return (
                  <tr key={band.level}>
                    <td>
                      <Tag size="sm" type={LEVEL_TAG[band.level]}>
                        {label(LEVEL_LABEL, band.level)}
                      </Tag>
                    </td>
                    <td className="rk-num">{fmt.score(start)}</td>
                    <td>
                      {last ? (
                        <span className="rk-num">1,00</span>
                      ) : (
                        <NumberInput
                          id={`max-${band.level}`}
                          label=""
                          hideLabel
                          size="sm"
                          min={0.01}
                          max={0.99}
                          step={0.05}
                          value={band.max}
                          disabled={!canWrite}
                          hideSteppers={!canWrite}
                          invalidText=""
                          onChange={(_: unknown, { value }: { value: number | string }) => {
                            const max = Math.round(Number(value) * 100) / 100;
                            if (Number.isNaN(max)) return;
                            set({
                              score_to_level: draft.score_to_level.map((item, i) => (i === index ? { ...item, max } : item)),
                            });
                          }}
                        />
                      )}
                    </td>
                    <td>
                      <Dropdown
                        id={`action-${band.level}`}
                        titleText=""
                        label="Acción"
                        hideLabel
                        size="sm"
                        items={ACTIONS}
                        itemToString={(value: Action | null) => (value ? ACTION_VERB[value] : "")}
                        selectedItem={draft.level_to_action[band.level]}
                        disabled={!canWrite}
                        onChange={({ selectedItem }: { selectedItem: Action | null }) =>
                          selectedItem && set({ level_to_action: { ...draft.level_to_action, [band.level]: selectedItem } })
                        }
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {issues.length > 0 && (
            <ul className="rk-issues">
              {issues.map((issue) => (
                <li key={issue}>{issue}</li>
              ))}
            </ul>
          )}
        </section>

        <section className="rk-card rk-card--full">
          <h2 className="rk-card-title">
            <Hint
              text={`Cómo habrían terminado los últimos ${fmt.count(scored.length)} inicios evaluados con estos valores, frente a lo que decidió el motor en su momento.`}
            >
              Impacto estimado
            </Hint>
          </h2>
          {scored.length === 0 ? (
            <p className="rk-secondary">Sin inicios recientes para estimar.</p>
          ) : (
            <dl className="rk-metrics rk-impact">
              {ACTIONS.map((action) => {
                const delta = impact.now[action] - impact.then[action];
                return (
                  <div key={action}>
                    <dt>{label(OUTCOME_LABEL, action)}</dt>
                    <dd>
                      {fmt.count(impact.now[action])}
                      {dirty && delta !== 0 && (
                        <span className={`rk-delta ${delta > 0 ? "up" : "down"}`}>
                          {delta > 0 ? "+" : "−"}
                          {fmt.count(Math.abs(delta))}
                        </span>
                      )}
                    </dd>
                  </div>
                );
              })}
            </dl>
          )}
        </section>
      </div>

      <Modal
        open={confirming}
        danger={draft.engine_mode === "OFF"}
        modalHeading={`¿Pasar el motor a ${MODES.find((mode) => mode.id === draft.engine_mode)?.title.toLowerCase()}?`}
        primaryButtonText="Guardar"
        secondaryButtonText="Cancelar"
        closeButtonLabel="Cerrar"
        onRequestClose={() => setConfirming(false)}
        onRequestSubmit={save}
      >
        <p>{MODES.find((mode) => mode.id === draft.engine_mode)?.hint}</p>
      </Modal>
    </>
  );
}
