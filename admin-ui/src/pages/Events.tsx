import {
  Accordion,
  AccordionItem,
  Breadcrumb,
  BreadcrumbItem,
  DataTable,
  DataTableSkeleton,
  Dropdown,
  IconButton,
  InlineNotification,
  Link,
  Pagination,
  StructuredListBody,
  StructuredListCell,
  StructuredListRow,
  StructuredListWrapper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableExpandedRow,
  TableExpandHeader,
  TableExpandRow,
  TableHead,
  TableHeader,
  TableRow,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Tag,
} from "@carbon/react";
import {
  ArrowDown,
  ArrowUp,
  Checkmark,
  CheckmarkOutline,
  Locked,
  Misuse,
  Renew,
  RuleTest,
  Time,
  UserIdentification,
  View,
} from "@carbon/icons-react";
import { useEffect, useMemo, useState } from "react";
import { api, type AdminUser, type Application, type Decision } from "../api";
import { Avatar, Hint, PageHead, TwoLines } from "../components";
import { useConsole } from "../console";
import { countryName, DEVICE_LABEL, fmt, label, LEVEL_LABEL, MODE_LABEL, OUTCOME_LABEL, reasonDetail, reasonText } from "../i18n";
import { hrefOf, navigate } from "../router";
import { useLoad } from "./load";

const HEADERS = [
  { key: "when", header: "Cuándo" },
  { key: "who", header: "Usuario" },
  { key: "origin", header: "Origen" },
  { key: "device", header: "Dispositivo" },
  { key: "risk", header: "Riesgo" },
  { key: "outcome", header: "Resultado" },
];

// The severity ramp of ADR-0030 (green → cyan → indigo → plum), in Carbon's tags.
const LEVEL_TAG: Record<string, "green" | "cyan" | "purple" | "magenta"> = {
  LOW: "green",
  MEDIUM: "cyan",
  HIGH: "purple",
  CRITICAL: "magenta",
};

const OUTCOME_ICON: Record<string, typeof Checkmark> = {
  ALLOW: CheckmarkOutline,
  REQUIRE_MFA: UserIdentification,
  REAUTHENTICATE: Locked,
  BLOCK: Misuse,
};

// The action each rule raises to (rba-decision-service services/escalate).
const RULE_FLOOR: Record<string, string> = {
  failed_login_lockout: "BLOCK",
  source_blocked: "BLOCK",
  account_cooldown: "BLOCK",
  failed_login_burst: "REAUTHENTICATE",
  impossible_travel: "REQUIRE_MFA",
  vpn_or_hosting: "REQUIRE_MFA",
  supervised_second_opinion: "REQUIRE_MFA",
};

/** The rule that set the engine's verdict, if the score alone did not (ADR-0040). */
function decidingRule(item: Decision) {
  return (item.reasons ?? []).find((reason) => RULE_FLOOR[reason.code] === item.action);
}

const REFRESH_MS = 15000;

type Lookup = { email: (userId: string) => string; app: (appId: string) => string };

function useLookup(): Lookup {
  const [users] = useLoad(() => api<AdminUser[]>("/admin/api/users").catch(() => []), [] as AdminUser[]);
  const [apps] = useLoad(() => api<Application[]>("/admin/api/applications").catch(() => []), [] as Application[]);
  return useMemo(() => {
    const emails = new Map(users.map((user) => [user.user_id, user.email]));
    const names = new Map(apps.map((app) => [app.application_id, app.name]));
    return {
      email: (userId) => emails.get(userId) ?? userId,
      app: (appId) => names.get(appId) ?? appId,
    };
  }, [users, apps]);
}

const STEP_UP = new Set(["REQUIRE_MFA", "REAUTHENTICATE"]);

/** Whether a step-up was passed (RF-11). Recent ones may still be in progress. */
function StepUp({ item }: { item: Decision }) {
  if (!STEP_UP.has(item.enforced_action)) return null;
  return item.step_up_passed_at ? (
    <span className="rk-secondary rk-status">
      <CheckmarkOutline size={12} />
      Passkey completada
    </span>
  ) : (
    <span className="rk-secondary rk-status">
      <Time size={12} />
      <Hint text="Nadie pasó la passkey de este inicio: lo abandonó, o era alguien sin ella.">Sin completar</Hint>
    </span>
  );
}

function Outcome({ item }: { item: Decision }) {
  const Icon = OUTCOME_ICON[item.enforced_action] ?? Checkmark;
  const monitored = item.action !== item.enforced_action;
  const rule = decidingRule(item);
  return (
    <span className="rk-cell-text">
      <span className={`rk-status rk-outcome rk-outcome--${item.enforced_action}`}>
        <Icon size={16} />
        {label(OUTCOME_LABEL, item.enforced_action)}
      </span>
      {monitored && (
        // MONITOR (ADR-0034): what the engine would have done.
        <span className="rk-secondary rk-status">
          <View size={12} />
          El motor: {label(OUTCOME_LABEL, item.action).toLowerCase()}
        </span>
      )}
      <StepUp item={item} />
      {rule && (
        // A BLOCK next to a LOW score is a rule, not the score (ADR-0040).
        <span className="rk-secondary rk-status">
          <RuleTest size={12} />
          <Hint text={reasonDetail(rule.code, rule.detail) ?? reasonText(rule).text}>Por regla</Hint>
        </span>
      )}
    </span>
  );
}

function Risk({ item }: { item: Decision }) {
  return (
    <span className="rk-cell-text">
      <span>
        <Tag size="sm" type={LEVEL_TAG[item.risk_level]} title={item.risk_level}>
          {label(LEVEL_LABEL, item.risk_level)}
        </Tag>
      </span>
      <span className="rk-secondary">puntaje {fmt.score(item.risk_score)}</span>
    </span>
  );
}

function Origin({ item }: { item: Decision }) {
  const login = item.login;
  if (!login) return <span className="rk-secondary">Sin datos</span>;
  const isNew = item.features?.country_seen_before === 0;
  return (
    <TwoLines
      primary={
        <>
          {countryName(login.country)}
          {isNew && (
            <Tag size="sm" type="purple" className="rk-inline-tag">
              Nuevo
            </Tag>
          )}
        </>
      }
      secondary={
        <span className="rk-mono">
          {login.asn ? `AS${login.asn} · ` : ""}
          {login.ip_address}
        </span>
      }
    />
  );
}

function Device({ item }: { item: Decision }) {
  const login = item.login;
  if (!login) return <span className="rk-secondary">Sin datos</span>;
  const what = [login.browser, login.os].filter(Boolean).join(" en ");
  return <TwoLines primary={what || "Desconocido"} secondary={label(DEVICE_LABEL, login.device_type ?? "")} />;
}

/** Why: the reasons the engine gave, strongest first, and the login as it was seen. */
export function Explanation({ item }: { item: Decision }) {
  const reasons = [...(item.reasons ?? [])].sort(
    (a, b) => Math.abs(b.contribution ?? 1) - Math.abs(a.contribution ?? 1),
  );
  const strongest = Math.max(0.01, ...reasons.map((reason) => Math.abs(reason.contribution ?? 0)));
  const login = item.login;
  const features = item.features;
  const familiar = (flag: number | undefined) =>
    flag === undefined ? null : flag ? (
      <Tag size="sm" type="green">
        Habitual
      </Tag>
    ) : (
      <Tag size="sm" type="purple">
        Nuevo
      </Tag>
    );
  const signals: [string, React.ReactNode, number | undefined][] = login
    ? [
        ["País", countryName(login.country), features?.country_seen_before],
        ["Red", login.asn ? `AS${login.asn}` : "—", features?.asn_seen_before],
        ["Dirección IP", <span className="rk-mono">{login.ip_address}</span>, features?.ip_seen_before],
        ["Dispositivo", label(DEVICE_LABEL, login.device_type ?? "—"), features?.device_type_seen_before],
        ["Sistema operativo", login.os ?? "—", features?.os_seen_before],
        ["Navegador", login.browser ?? "—", features?.browser_seen_before],
        ["Hora del día", fmt.time(login.login_timestamp), features?.hour_seen_before],
      ]
    : [];

  return (
    <div className="rk-explain">
      <section>
        <h3 className="rk-section-title">Por qué</h3>
        {reasons.length === 0 ? (
          <p className="rk-secondary">Sin motivos.</p>
        ) : (
          <ul className="rk-reasons">
            {reasons.map((reason, index) => {
              const { text, title } = reasonText(reason);
              const weight = reason.contribution;
              const rule = weight === null || weight === undefined || !reason.code.startsWith("signal_");
              const raises = rule || (weight ?? 0) > 0;
              const Icon = rule ? RuleTest : raises ? ArrowUp : ArrowDown;
              return (
                <li key={index} title={title}>
                  <Icon size={16} className={raises ? "rk-raises" : "rk-lowers"} />
                  <span className="rk-reason-text">
                    {rule && reasonDetail(reason.code, reason.detail) ? (
                      <Hint text={reasonDetail(reason.code, reason.detail)}>{text}</Hint>
                    ) : (
                      text
                    )}
                  </span>
                  {!rule && (
                    <span className="rk-weight" aria-hidden="true">
                      <span
                        className={raises ? "rk-raises-bg" : "rk-lowers-bg"}
                        style={{ width: `${(Math.abs(weight ?? 0) / strongest) * 100}%` }}
                      />
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section>
        <h3 className="rk-section-title">El inicio de sesión</h3>
        {signals.length === 0 ? (
          <p className="rk-secondary">Sin datos del inicio.</p>
        ) : (
          <StructuredListWrapper isCondensed className="rk-signals" aria-label="Señales del inicio">
            <StructuredListBody>
              {signals.map(([name, value, flag]) => (
                <StructuredListRow key={name}>
                  <StructuredListCell className="rk-secondary">{name}</StructuredListCell>
                  <StructuredListCell>{value}</StructuredListCell>
                  <StructuredListCell>{familiar(flag)}</StructuredListCell>
                </StructuredListRow>
              ))}
            </StructuredListBody>
          </StructuredListWrapper>
        )}
        {features && (
          <p className="rk-secondary rk-history">
            {fmt.count(features.user_login_count)} inicios previos
            {features.seconds_since_last_login > 0 &&
              ` · el anterior ${fmt.ago(new Date(Date.parse(item.occurred_at) - features.seconds_since_last_login * 1000).toISOString())}`}
            {features.failed_logins_last_24h > 0 &&
              ` · ${features.failed_logins_last_24h} contraseñas incorrectas en 24 h`}
          </p>
        )}
      </section>

      <Accordion size="sm" className="rk-tech">
        <AccordionItem title="Detalles técnicos">
          <dl className="rk-defs">
            <dt>Evento</dt>
            <dd className="rk-mono">{item.event_id}</dd>
            <dt>Modo del motor</dt>
            <dd>{label(MODE_LABEL, item.engine_mode)}</dd>
            <dt>Veredicto del motor</dt>
            <dd className="rk-mono">{item.action}</dd>
            <dt>Aplicado</dt>
            <dd className="rk-mono">{item.enforced_action}</dd>
            {STEP_UP.has(item.enforced_action) && (
              <>
                <dt>Passkey</dt>
                <dd>{item.step_up_passed_at ? `completada ${fmt.ago(item.step_up_passed_at)}` : "sin completar"}</dd>
              </>
            )}
            <dt>Modelo</dt>
            <dd className="rk-mono">{item.model_version}</dd>
            <dt>Política</dt>
            <dd className="rk-mono">{item.policy_version}</dd>
            <dt>Esquema de señales</dt>
            <dd className="rk-mono">{item.feature_schema_version}</dd>
            {item.fallback && (
              <>
                <dt>Respaldo</dt>
                <dd>El motor no respondió; se aplicó la decisión de respaldo.</dd>
              </>
            )}
            {item.simulated && (
              <>
                <dt>Simulado</dt>
                <dd>País y red vinieron del panel del presentador.</dd>
              </>
            )}
          </dl>
        </AccordionItem>
      </Accordion>
    </div>
  );
}

function DecisionPage({ eventId, lookup }: { eventId: string; lookup: Lookup }) {
  const [item, , loading] = useLoad(
    () => api<Decision>(`/admin/api/decisions/${eventId}`).catch(() => null),
    null as Decision | null,
  );
  return (
    <>
      <Breadcrumb noTrailingSlash className="rk-breadcrumb">
        <BreadcrumbItem
          href={hrefOf("events")}
          onClick={(event: React.MouseEvent) => {
            event.preventDefault();
            navigate("events");
          }}
        >
          Eventos
        </BreadcrumbItem>
        <BreadcrumbItem isCurrentPage>{item ? fmt.dateTime(item.occurred_at) : "…"}</BreadcrumbItem>
      </Breadcrumb>
      {loading && !item ? null : !item ? (
        <InlineNotification kind="error" hideCloseButton title="No encontramos este evento." subtitle="Puede ser de otra organización o el enlace está incompleto." />
      ) : (
        <>
          <div className="rk-page-head">
            <div className="rk-cell">
              <Avatar email={lookup.email(item.user_id)} />
              <div>
                <h1>{lookup.email(item.user_id)}</h1>
                <p>
                  {lookup.app(item.application_id)} · {fmt.dateTime(item.occurred_at)} ({fmt.ago(item.occurred_at)})
                </p>
              </div>
            </div>
            <div className="rk-head-facts">
              <Risk item={item} />
              <Outcome item={item} />
            </div>
          </div>
          <div className="rk-panel">
            <Explanation item={item} />
          </div>
        </>
      )}
    </>
  );
}

// Carbon reads an empty value as "nothing selected", so "all" has a name.
const ALL = "ALL";
const OUTCOME_FILTER = [ALL, "ALLOW", "REQUIRE_MFA", "REAUTHENTICATE", "BLOCK"];

export function Events({ itemId }: { itemId: string | null }) {
  const { fail } = useConsole();
  const lookup = useLookup();
  const [items, reload, loading] = useLoad(
    () => api<{ items: Decision[] }>("/admin/api/decisions?limit=200").then((body) => body.items || []),
    [] as Decision[],
  );
  const [updated, setUpdated] = useState(() => new Date());
  const [query, setQuery] = useState("");
  const [outcome, setOutcome] = useState(ALL);
  const [app, setApp] = useState(ALL);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // The list follows new logins on its own; an operator watching an attack
  // should not have to reload.
  useEffect(() => {
    if (itemId) return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") reload().then(() => setUpdated(new Date())).catch(fail);
    }, REFRESH_MS);
    return () => clearInterval(timer);
  }, [itemId, reload, fail]);

  if (itemId) return <DecisionPage eventId={itemId} lookup={lookup} />;

  const apps = [...new Set(items.map((item) => item.application_id))];
  const needle = query.trim().toLowerCase();
  const matching = items.filter(
    (item) =>
      (outcome === ALL || item.enforced_action === outcome) &&
      (app === ALL || item.application_id === app) &&
      (!needle ||
        lookup.email(item.user_id).toLowerCase().includes(needle) ||
        (item.login?.ip_address ?? "").includes(needle) ||
        countryName(item.login?.country).toLowerCase().includes(needle)),
  );
  const shown = matching.slice((page - 1) * pageSize, page * pageSize);
  const byId = new Map(items.map((item) => [item.event_id, item]));
  const rows = shown.map((item) => ({
    id: item.event_id,
    when: item.occurred_at,
    who: lookup.email(item.user_id),
    origin: countryName(item.login?.country),
    device: item.login?.browser ?? "",
    risk: item.risk_score,
    outcome: item.enforced_action,
  }));

  return (
    <>
      <PageHead
        title="Eventos"
        info="Cada inicio de sesión que evaluó el motor: de dónde vino, qué tan riesgoso era y qué se hizo. Abrí una fila para ver por qué."
      >
        <div className="rk-refresh">
          <span className="rk-secondary">{fmt.time(updated.toISOString())}</span>
          <IconButton
            kind="ghost"
            size="sm"
            label="Actualizar ahora"
            onClick={() => reload().then(() => setUpdated(new Date())).catch(fail)}
          >
            <Renew />
          </IconButton>
        </div>
      </PageHead>

      {loading && items.length === 0 ? (
        <DataTableSkeleton headers={HEADERS} columnCount={HEADERS.length + 1} rowCount={8} showHeader={false} />
      ) : (
        <DataTable rows={rows} headers={HEADERS} isSortable>
          {({ rows: tableRows, headers, getHeaderProps, getRowProps, getTableProps, getExpandHeaderProps }) => (
            <TableContainer>
              <TableToolbar aria-label="Filtros">
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    labelText="Buscar eventos"
                    placeholder="Buscar por usuario, IP o país"
                    onChange={(event: "" | React.ChangeEvent<HTMLInputElement>) => {
                      setQuery(event ? event.target.value : "");
                      setPage(1);
                    }}
                  />
                  <Dropdown
                    id="filter-outcome"
                    type="inline"
                    titleText="Resultado"
                    label="Resultado"
                    items={OUTCOME_FILTER}
                    itemToString={(value: string | null) => (value && value !== ALL ? label(OUTCOME_LABEL, value) : "Todos")}
                    selectedItem={outcome}
                    onChange={({ selectedItem }: { selectedItem: string | null }) => {
                      setOutcome(selectedItem ?? ALL);
                      setPage(1);
                    }}
                  />
                  <Dropdown
                    id="filter-app"
                    type="inline"
                    titleText="Aplicación"
                    label="Aplicación"
                    items={[ALL, ...apps]}
                    itemToString={(value: string | null) => (value && value !== ALL ? lookup.app(value) : "Todas")}
                    selectedItem={app}
                    onChange={({ selectedItem }: { selectedItem: string | null }) => {
                      setApp(selectedItem ?? ALL);
                      setPage(1);
                    }}
                  />
                </TableToolbarContent>
              </TableToolbar>
              <Table {...getTableProps()}>
                <TableHead>
                  <TableRow>
                    <TableExpandHeader {...getExpandHeaderProps()} />
                    {headers.map((header) => {
                      const { key, ...props } = getHeaderProps({ header });
                      return (
                        <TableHeader key={key} {...props}>
                          {header.header}
                        </TableHeader>
                      );
                    })}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tableRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={HEADERS.length + 1}>
                        <span className="rk-secondary">
                          {items.length === 0
                            ? "Todavía no hay inicios de sesión evaluados en esta organización."
                            : "Ningún evento coincide con los filtros."}
                        </span>
                      </TableCell>
                    </TableRow>
                  )}
                  {tableRows.map((row) => {
                    const item = byId.get(row.id)!;
                    const { key, ...props } = getRowProps({ row });
                    return [
                      <TableExpandRow key={key} {...props} expandIconDescription="Ver por qué" aria-label="Ver por qué">
                        <TableCell>
                          <TwoLines primary={fmt.ago(item.occurred_at)} secondary={fmt.dateTime(item.occurred_at)} />
                        </TableCell>
                        <TableCell>
                          <div className="rk-cell">
                            <Avatar email={lookup.email(item.user_id)} />
                            <TwoLines primary={lookup.email(item.user_id)} secondary={lookup.app(item.application_id)} />
                          </div>
                        </TableCell>
                        <TableCell>
                          <Origin item={item} />
                        </TableCell>
                        <TableCell>
                          <Device item={item} />
                        </TableCell>
                        <TableCell>
                          <Risk item={item} />
                        </TableCell>
                        <TableCell>
                          <Outcome item={item} />
                        </TableCell>
                      </TableExpandRow>,
                      row.isExpanded ? (
                        <TableExpandedRow key={`${key}-explain`} colSpan={HEADERS.length + 1}>
                          <Explanation item={item} />
                          <Link
                            className="rk-open"
                            href={hrefOf("events", item.event_id)}
                            onClick={(event: React.MouseEvent) => {
                              event.preventDefault();
                              navigate("events", item.event_id);
                            }}
                          >
                            Abrir
                          </Link>
                        </TableExpandedRow>
                      ) : null,
                    ];
                  })}
                </TableBody>
              </Table>
              {matching.length > pageSize && (
                <Pagination
                  page={page}
                  pageSize={pageSize}
                  pageSizes={[25, 50, 100]}
                  totalItems={matching.length}
                  itemsPerPageText="Por página:"
                  backwardText="Página anterior"
                  forwardText="Página siguiente"
                  itemRangeText={(min: number, max: number, total: number) => `${min}–${max} de ${total}`}
                  pageRangeText={(_: number, total: number) => `de ${total}`}
                  onChange={({ page: next, pageSize: size }: { page: number; pageSize: number }) => {
                    setPage(next);
                    setPageSize(size);
                  }}
                />
              )}
            </TableContainer>
          )}
        </DataTable>
      )}
    </>
  );
}

