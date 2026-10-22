import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  DataTable,
  DataTableSkeleton,
  InlineNotification,
  Modal,
  OverflowMenu,
  OverflowMenuItem,
  RadioButton,
  RadioButtonGroup,
  Stack,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableHeader,
  TableRow,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  Tag,
  TextInput,
} from "@carbon/react";
import { Add } from "@carbon/icons-react";
import { FormEvent, useEffect, useState } from "react";
import { api, type Tenant } from "../api";
import { Hint, PageHead, TwoLines } from "../components";
import { useConsole } from "../console";
import { hrefOf, navigate } from "../router";
import { useLoad } from "./load";
import { groupTag } from "./Groups";

const HEADERS = [
  { key: "name", header: "Organización" },
  { key: "domains", header: "Dominios" },
  { key: "login", header: "Login" },
];

const HEX = /^#[0-9a-fA-F]{6}$/;
const domainsOf = (text: string) =>
  text
    .split(/[\s,]+/)
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);

function LoginStyle({ tenant }: { tenant: Tenant }) {
  return tenant.branding.login_style === "tenant" ? (
    <Hint text="El login muestra el nombre, logo y colores de la organización, con el sello «Protegido por RokuSec».">
      <Tag size="sm" type="purple">
        Propio
      </Tag>
    </Hint>
  ) : (
    <Hint text="El login es el de RokuSec: «Continuá a …».">
      <Tag size="sm" type="blue">
        RokuSec
      </Tag>
    </Hint>
  );
}

/** A small, light login card: how the tenant's users will see the page. */
function LoginPreview({ branding }: { branding: Tenant["branding"] }) {
  const own = branding.login_style === "tenant";
  return (
    <div className="rk-login-preview" aria-hidden="true">
      <div className="rk-lp-brand">
        {own ? (
          branding.logo_url ? (
            <img src={branding.logo_url} alt="" />
          ) : (
            <span className="rk-lp-mono" style={{ background: branding.primary_colour }}>
              {branding.display_name[0]?.toUpperCase()}
            </span>
          )
        ) : (
          <img src="/static/brand/rokusec-logo-horizontal.svg" alt="" />
        )}
        {own && <span className="rk-lp-name" style={{ color: branding.accent_colour }}>{branding.display_name}</span>}
      </div>
      <div className="rk-lp-title">{own ? "Iniciá sesión" : `Continuá a ${branding.display_name}`}</div>
      <div className="rk-lp-field" />
      <div className="rk-lp-field" />
      <div className="rk-lp-button" style={{ background: own ? branding.primary_colour : "#1466e5" }}>
        Continuar
      </div>
      {own && <div className="rk-lp-seal">Protegido por RokuSec</div>}
    </div>
  );
}

function OrgPage({ tenantId }: { tenantId: string }) {
  const { ok, fail, can, actAs } = useConsole();
  const canWrite = can("tenants:write");
  const [tenants, reload, loading] = useLoad(() => api<Tenant[]>("/admin/api/tenants").catch(() => []), [] as Tenant[]);
  const tenant = tenants.find((item) => item.tenant_id === tenantId) ?? null;
  const [branding, setBranding] = useState<Tenant["branding"] | null>(null);
  useEffect(() => setBranding(tenant?.branding ?? null), [tenant]);

  const patch = (body: object, message: string) =>
    api<Tenant>(`/admin/api/tenants/${tenantId}`, { method: "PATCH", body: JSON.stringify(body) })
      .then(() => {
        ok(message);
        return reload();
      })
      .catch(fail);

  const crumbs = (
    <Breadcrumb noTrailingSlash className="rk-breadcrumb">
      <BreadcrumbItem
        href={hrefOf("orgs")}
        onClick={(event: React.MouseEvent) => {
          event.preventDefault();
          navigate("orgs");
        }}
      >
        Organizaciones
      </BreadcrumbItem>
      <BreadcrumbItem isCurrentPage>{tenant?.name ?? "…"}</BreadcrumbItem>
    </Breadcrumb>
  );
  if (loading && !tenant) return crumbs;
  if (!tenant || !branding) {
    return (
      <>
        {crumbs}
        <InlineNotification kind="error" hideCloseButton title="No encontramos esta organización." />
      </>
    );
  }

  const brandingDirty = JSON.stringify(branding) !== JSON.stringify(tenant.branding);
  const brandingValid = HEX.test(branding.primary_colour) && HEX.test(branding.accent_colour) && branding.display_name.trim() !== "";

  return (
    <>
      {crumbs}
      <PageHead
        title={tenant.name}
        sub={<span className="rk-mono">{tenant.tenant_id}</span>}
        lead={
          <span className="rk-group-mark" data-tag={groupTag(tenant.name)}>
            {tenant.name[0].toUpperCase()}
          </span>
        }
      >
        <div className="rk-actions">
          {tenant.is_platform && (
            <Tag type="cool-gray">
              <Hint text="La organización de RokuSec: sus operadores administran las demás.">Plataforma</Hint>
            </Tag>
          )}
          <Button kind="secondary" onClick={() => actAs(tenant.tenant_id)}>
            Abrir su consola
          </Button>
        </div>
      </PageHead>

      <Tabs>
        <TabList aria-label="Secciones de la organización">
          <Tab>General</Tab>
          <Tab>Marca</Tab>
        </TabList>
        <TabPanels>
          <TabPanel className="rk-tabpanel">
            <form
              className="rk-card rk-form-card"
              onSubmit={(event: FormEvent<HTMLFormElement>) => {
                event.preventDefault();
                const data = new FormData(event.currentTarget);
                void patch(
                  { name: data.get("name"), operator_domains: domainsOf(String(data.get("domains") ?? "")) },
                  "Organización actualizada.",
                );
              }}
            >
              <Stack gap={6}>
                <TextInput id="o-name" name="name" labelText="Nombre" defaultValue={tenant.name} disabled={!canWrite} required />
                <TextInput
                  id="o-domains"
                  name="domains"
                  labelText={
                    <Hint text="Los operadores entran a la consola con un email de estos dominios; así se sabe a qué organización pertenecen.">
                      Dominios de operadores
                    </Hint>
                  }
                  defaultValue={tenant.operator_domains.join(", ")}
                  disabled={!canWrite}
                />
                <div>
                  <Button type="submit" disabled={!canWrite}>
                    Guardar
                  </Button>
                </div>
              </Stack>
            </form>
          </TabPanel>
          <TabPanel className="rk-tabpanel">
            <div className="rk-brand">
              <div className="rk-card rk-form-card">
                <Stack gap={6}>
                  <TextInput
                    id="b-name"
                    labelText="Nombre visible"
                    value={branding.display_name}
                    disabled={!canWrite}
                    onChange={(event: React.ChangeEvent<HTMLInputElement>) => setBranding({ ...branding, display_name: event.target.value })}
                  />
                  <RadioButtonGroup
                    name="login-style"
                    legendText="Login"
                    valueSelected={branding.login_style}
                    disabled={!canWrite}
                    onChange={(value: string | number | undefined) =>
                      setBranding({ ...branding, login_style: value as Tenant["branding"]["login_style"] })
                    }
                  >
                    <RadioButton id="ls-rokusec" value="rokusec" labelText="RokuSec" />
                    <RadioButton id="ls-tenant" value="tenant" labelText="Propio" />
                  </RadioButtonGroup>
                  <TextInput
                    id="b-logo"
                    labelText="Logo (URL)"
                    placeholder="https://…/logo.svg"
                    value={branding.logo_url ?? ""}
                    disabled={!canWrite || branding.login_style !== "tenant"}
                    onChange={(event: React.ChangeEvent<HTMLInputElement>) => setBranding({ ...branding, logo_url: event.target.value || null })}
                  />
                  <div className="rk-colours">
                    {(["primary_colour", "accent_colour"] as const).map((key) => (
                      <div key={key} className="rk-colour">
                        <input
                          type="color"
                          aria-label={key === "primary_colour" ? "Elegir color principal" : "Elegir color de acento"}
                          value={HEX.test(branding[key]) ? branding[key] : "#000000"}
                          disabled={!canWrite || branding.login_style !== "tenant"}
                          onChange={(event) => setBranding({ ...branding, [key]: event.target.value.toUpperCase() })}
                        />
                        <TextInput
                          id={`b-${key}`}
                          labelText={key === "primary_colour" ? "Color principal" : "Color de acento"}
                          value={branding[key]}
                          invalid={!HEX.test(branding[key])}
                          invalidText="#RRGGBB"
                          disabled={!canWrite || branding.login_style !== "tenant"}
                          onChange={(event: React.ChangeEvent<HTMLInputElement>) => setBranding({ ...branding, [key]: event.target.value })}
                        />
                      </div>
                    ))}
                  </div>
                  <div className="rk-actions">
                    <Button kind="ghost" disabled={!brandingDirty} onClick={() => setBranding(tenant.branding)}>
                      Descartar
                    </Button>
                    <Button
                      disabled={!canWrite || !brandingDirty || !brandingValid}
                      onClick={() => patch({ branding }, "Marca guardada.")}
                    >
                      Guardar
                    </Button>
                  </div>
                </Stack>
              </div>
              <div>
                <div className="rk-preview-label rk-secondary">Vista previa</div>
                <LoginPreview branding={branding} />
              </div>
            </div>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </>
  );
}

export function Orgs({ itemId }: { itemId: string | null }) {
  const { can, ok, fail, actAs } = useConsole();
  const [tenants, , loading] = useLoad(() => api<Tenant[]>("/admin/api/tenants"), [] as Tenant[]);
  const [creating, setCreating] = useState(false);

  if (itemId) return <OrgPage tenantId={itemId} />;

  const byId = new Map(tenants.map((tenant) => [tenant.tenant_id, tenant]));
  const rows = tenants.map((tenant) => ({
    id: tenant.tenant_id,
    name: tenant.name,
    domains: tenant.operator_domains.join(" "),
    login: tenant.branding.login_style,
  }));
  const open = (id: string) => navigate("orgs", id);

  const create = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    api<Tenant>("/admin/api/tenants", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: data.get("tenant_id"),
        name: data.get("name"),
        operator_domains: domainsOf(String(data.get("domains") ?? "")),
      }),
    })
      .then((created) => {
        ok(`${created.name} creada.`);
        setCreating(false);
        navigate("orgs", created.tenant_id);
      })
      .catch(fail);
  };

  return (
    <>
      <PageHead
        title="Organizaciones"
        info="Los clientes de RokuSec. Cada una tiene sus usuarios, aplicaciones y política, y no ve a las demás."
      >
        <Button renderIcon={Add} disabled={!can("tenants:write")} onClick={() => setCreating(true)}>
          Nueva organización
        </Button>
      </PageHead>
      {loading && tenants.length === 0 ? (
        <DataTableSkeleton headers={HEADERS} columnCount={HEADERS.length + 1} rowCount={3} showHeader={false} />
      ) : (
        <DataTable rows={rows} headers={HEADERS} isSortable>
          {({ rows: tableRows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer>
              <Table {...getTableProps()}>
                <TableHead>
                  <TableRow>
                    {headers.map((header) => {
                      const { key, ...props } = getHeaderProps({ header });
                      return (
                        <TableHeader key={key} {...props}>
                          {header.header}
                        </TableHeader>
                      );
                    })}
                    <TableHeader aria-label="Acciones" />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tableRows.map((row) => {
                    const tenant = byId.get(row.id)!;
                    const { key, ...props } = getRowProps({ row });
                    return (
                      <TableRow
                        key={key}
                        {...props}
                        className="rk-clickable"
                        tabIndex={0}
                        onClick={() => open(tenant.tenant_id)}
                        onKeyDown={(event: React.KeyboardEvent) => event.key === "Enter" && open(tenant.tenant_id)}
                      >
                        <TableCell>
                          <div className="rk-cell">
                            <span className="rk-group-mark" data-tag={groupTag(tenant.name)}>
                              {tenant.name[0].toUpperCase()}
                            </span>
                            <TwoLines
                              primary={
                                <>
                                  {tenant.name}
                                  {tenant.is_platform && (
                                    <Tag size="sm" type="cool-gray" className="rk-inline-tag">
                                      Plataforma
                                    </Tag>
                                  )}
                                </>
                              }
                              secondary={<span className="rk-mono">{tenant.tenant_id}</span>}
                            />
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="rk-tags">
                            {tenant.operator_domains.map((domain) => (
                              <Tag key={domain} size="sm" type="outline" className="rk-mono">
                                {domain}
                              </Tag>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>
                          <LoginStyle tenant={tenant} />
                        </TableCell>
                        <TableCell className="cds--table-column-menu" onClick={(event: React.MouseEvent) => event.stopPropagation()}>
                          <OverflowMenu size="sm" flipped iconDescription="Acciones" aria-label={`Acciones para ${tenant.name}`}>
                            <OverflowMenuItem itemText="Abrir su consola" onClick={() => actAs(tenant.tenant_id)} />
                          </OverflowMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DataTable>
      )}
      <Modal
        open={creating}
        modalHeading="Nueva organización"
        primaryButtonText="Crear"
        secondaryButtonText="Cancelar"
        closeButtonLabel="Cerrar"
        onRequestClose={() => setCreating(false)}
        onRequestSubmit={() => (document.getElementById("org-form") as HTMLFormElement | null)?.requestSubmit()}
      >
        {creating && (
          <form id="org-form" onSubmit={create}>
            <Stack gap={6}>
              <TextInput id="n-id" name="tenant_id" labelText="ID" placeholder="acme" helperText="Minúsculas y guiones. No se puede cambiar." required />
              <TextInput id="n-name" name="name" labelText="Nombre" placeholder="Acme" required />
              <TextInput id="n-domains" name="domains" labelText="Dominios de operadores" placeholder="acme.example" />
            </Stack>
          </form>
        )}
      </Modal>
    </>
  );
}
