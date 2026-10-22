import { Button, StructuredListBody, StructuredListCell, StructuredListRow, StructuredListWrapper, Tag } from "@carbon/react";
import { logout } from "../api";
import { Avatar } from "../components";
import { useConsole } from "../console";
import { fmt } from "../i18n";

/** What each permission lets an operator do here, in words (ADR-0029). */
const PERMISSION_TEXT: Record<string, string> = {
  "admin:read": "Ver usuarios, grupos, roles y aplicaciones",
  "admin:write": "Crearlos, cambiarlos y generar códigos de activación",
  "decisions:read": "Ver los eventos y por qué se decidió cada uno",
  "policy:write": "Cambiar la política de riesgo",
  "tenants:read": "Ver todas las organizaciones y actuar sobre ellas",
  "tenants:write": "Crear organizaciones y cambiar su configuración",
};

export function standing(granted: string[]): string {
  if (granted.includes("tenants:read")) return "Operador de la plataforma";
  if (granted.includes("admin:write")) return "Administrador";
  return "Soporte · solo lectura";
}

export function Account() {
  const { user, tenant, permissions, expiresAt } = useConsole();
  return (
    <>
      <div className="rk-page-head">
        <div className="rk-cell">
          <Avatar email={user.email} />
          <div>
            <h1>Mi cuenta</h1>
            <p>
              {user.email} · {tenant?.name ?? user.tenant_id}
            </p>
          </div>
        </div>
      </div>

      <section className="rk-card rk-account-page">
        <h2 className="rk-card-title">Lo que podés hacer en esta consola</h2>
        <p className="rk-card-text">
          Como <strong>{standing(permissions).toLowerCase()}</strong>, tu sesión tiene estos permisos. Vienen de
          los roles de tus grupos; si te falta alguno, pedíselo a un administrador.
        </p>
        <StructuredListWrapper isCondensed aria-label="Permisos de esta sesión">
          <StructuredListBody>
            {permissions.map((scope) => (
              <StructuredListRow key={scope}>
                <StructuredListCell>{PERMISSION_TEXT[scope] ?? scope}</StructuredListCell>
                <StructuredListCell>
                  <Tag size="sm" type="cool-gray" className="rk-mono">
                    {scope}
                  </Tag>
                </StructuredListCell>
              </StructuredListRow>
            ))}
          </StructuredListBody>
        </StructuredListWrapper>
      </section>

      <section className="rk-card rk-account-page">
        <h2 className="rk-card-title">Sesión</h2>
        <p className="rk-card-text">
          {expiresAt ? `Tu sesión vence ${fmt.ago(expiresAt)} (${fmt.dateTime(expiresAt)}).` : "Sesión activa."}
        </p>
        <Button kind="secondary" size="md" onClick={() => void logout()}>
          Cerrar sesión
        </Button>
      </section>
    </>
  );
}
