import {
  Button,
  Content,
  Dropdown,
  Header,
  HeaderContainer,
  HeaderGlobalAction,
  HeaderGlobalBar,
  HeaderMenuButton,
  HeaderName,
  HeaderPanel,
  InlineNotification,
  SideNav,
  SideNavItems,
  SideNavMenu,
  SideNavMenuItem,
  SkipToContent,
  Tag,
} from "@carbon/react";
import { Activity, Enterprise, Security, UserAvatar, UserMultiple } from "@carbon/icons-react";
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
import { hrefOf, navigate, PAGES, SECTIONS, useRoute, type Page, type Section } from "./router";

const PAGE_VIEW: Record<Page, (props: { itemId: string | null }) => JSX.Element> = {
  decisions: Decisions,
  policy: Policy,
  users: Users,
  groups: Groups,
  roles: Roles,
  apps: Apps,
};

// Pages already rebuilt on Carbon; the rest keep their old look (U-2).
const CARBON_PAGES = new Set<Page>(["users", "decisions"]);

const SECTION_ICON: Record<Section, typeof Activity> = {
  activity: Activity,
  directory: UserMultiple,
  access: Security,
};

/** The session's standing in one phrase; the scopes themselves are listed below it. */
function standing(granted: string[]): string {
  if (granted.includes("tenants:read")) return "Operador de la plataforma";
  if (granted.includes("admin:write")) return "Administrador";
  return "Soporte · solo lectura";
}

const LOGO = "/static/brand/rokusec-logo-horizontal-inverse.svg";
const MARK = "/static/brand/rokusec-mark-inverse.svg";

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
  const [accountOpen, setAccountOpen] = useState(false);
  const { page, id: itemId } = useRoute();

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
      <Content className="rk-content" style={{ maxWidth: "36rem", margin: "10vh auto 0" }}>
        <img className="rk-header-logo" src={LOGO} alt="RokuSec" style={{ height: 32, marginBottom: "2rem" }} />
        <InlineNotification
          kind={forbidden ? "warning" : "error"}
          hideCloseButton
          title={forbidden ? "Esta sesión no es de la consola." : "La consola no está disponible."}
          subtitle={forbidden ? "Iniciá sesión con una cuenta de operador de tu organización." : bootError}
        />
        <Button href="/console/login?next=/admin">Ir al inicio de sesión</Button>
      </Content>
    );
  }
  if (!user) return null;

  const scopeId = scope ?? user.tenant_id;
  const View = PAGE_VIEW[page];
  const go = (target: Page) => (event: React.MouseEvent) => {
    event.preventDefault();
    navigate(target);
  };

  return (
    <ConsoleProvider value={{ user, tenant, scope: scopeId, can: (permission) => granted.includes(permission) }}>
      <HeaderContainer
        render={({ isSideNavExpanded, onClickSideNavExpand }: { isSideNavExpanded: boolean; onClickSideNavExpand: () => void }) => (
          <>
            <Header aria-label="RokuSec">
              <SkipToContent>Saltar al contenido</SkipToContent>
              <HeaderMenuButton
                aria-label={isSideNavExpanded ? "Cerrar menú" : "Abrir menú"}
                onClick={onClickSideNavExpand}
                isActive={isSideNavExpanded}
                aria-expanded={isSideNavExpanded}
              />
              <HeaderName className="rk-header-name" href={hrefOf("decisions")} prefix="" onClick={go("decisions")}>
                <img className="rk-header-mark" src={MARK} alt="" width={15} height={22} />
                <span className="cds--header__name--prefix">RokuSec</span>&nbsp;Consola
              </HeaderName>
              <HeaderGlobalBar>
                <HeaderGlobalAction
                  aria-label="Cuenta"
                  isActive={accountOpen}
                  onClick={() => setAccountOpen((open) => !open)}
                  tooltipAlignment="end"
                >
                  <UserAvatar size={20} />
                </HeaderGlobalAction>
              </HeaderGlobalBar>
              <HeaderPanel expanded={accountOpen} aria-label="Cuenta">
                <div className="rk-account">
                  <div className="rk-account-email">{user.email}</div>
                  <div className="rk-account-role">{standing(granted)}</div>
                  {/* What this session actually holds: the answer to "why can I
                      see this button and my colleague cannot". */}
                  <div className="rk-org-label">Permisos de esta sesión</div>
                  <div className="rk-account-scopes">
                    {granted.map((item) => (
                      <Tag key={item} type="cool-gray" size="sm" className="rk-mono">
                        {item}
                      </Tag>
                    ))}
                  </div>
                  <Button kind="secondary" size="md" onClick={() => void logout()}>
                    Cerrar sesión
                  </Button>
                </div>
              </HeaderPanel>

              <SideNav aria-label="Secciones" expanded={isSideNavExpanded} onSideNavBlur={onClickSideNavExpand} href="#main-content">
                <div className="rk-org">
                  <div className="rk-org-label">Organización</div>
                  {tenants.length > 0 ? (
                    <Dropdown
                      id="tenant"
                      size="sm"
                      label="Organización"
                      titleText=""
                      hideLabel
                      items={tenants}
                      itemToString={(item: Tenant | null) => item?.name ?? ""}
                      selectedItem={tenants.find((item) => item.tenant_id === scopeId) ?? null}
                      onChange={({ selectedItem }: { selectedItem: Tenant | null }) => {
                        if (!selectedItem) return;
                        const next = selectedItem.tenant_id === user.tenant_id ? null : selectedItem.tenant_id;
                        switchTenant(next);
                        setScope(next);
                      }}
                    />
                  ) : (
                    <div className="rk-org-name">{tenant?.name ?? " "}</div>
                  )}
                  {scope && scope !== user.tenant_id && (
                    <div className="rk-acting">Estás actuando sobre otra organización.</div>
                  )}
                </div>
                <SideNavItems>
                  {SECTIONS.map((section) => {
                    const items = PAGES.filter((item) => item.section === section.id);
                    return (
                      <SideNavMenu
                        key={section.id}
                        title={section.label}
                        renderIcon={SECTION_ICON[section.id]}
                        defaultExpanded
                        isActive={items.some((item) => item.id === page)}
                      >
                        {items.map((item) => (
                          <SideNavMenuItem
                            key={item.id}
                            href={hrefOf(item.id)}
                            isActive={page === item.id}
                            aria-current={page === item.id ? "page" : undefined}
                            onClick={go(item.id)}
                          >
                            {item.label}
                          </SideNavMenuItem>
                        ))}
                      </SideNavMenu>
                    );
                  })}
                  {tenants.length > 0 && (
                    <SideNavMenu title="Plataforma" renderIcon={Enterprise} defaultExpanded>
                      <SideNavMenuItem href="#" aria-disabled="true" onClick={(e: React.MouseEvent) => e.preventDefault()}>
                        Organizaciones (próximamente)
                      </SideNavMenuItem>
                    </SideNavMenu>
                  )}
                </SideNavItems>
              </SideNav>
            </Header>
          </>
        )}
      />

      <Content id="main-content" className={`rk-content${CARBON_PAGES.has(page) ? "" : " legacy"}`}>
        {/* Remounted per tenant, so no page shows the previous tenant's rows. */}
        <View key={scopeId} itemId={itemId} />
        {/* CC BY 4.0 attribution for the IP → country/ASN data (ADR-0032). */}
        <p className="rk-secondary" style={{ marginTop: "3rem" }}>
          <a className="cds--link" href="https://db-ip.com" rel="noopener">
            Geolocalización IP por DB-IP
          </a>
        </p>
      </Content>
    </ConsoleProvider>
  );
}
