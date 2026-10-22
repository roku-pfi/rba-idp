"""Idempotent seed: three tenants with their applications, roles, groups, users.

Tenancy (ADR-0033) on top of RBAC (ADR-0029). Each tenant is self-contained:
its own applications, permissions, roles, groups and users. The worked example
is the demo cast (ADR-0035):

| Tenant      | User                       | Group           | Role (application)              |
|-------------|----------------------------|-----------------|---------------------------------|
| `roku-bank` | `martin@correo.example`    | Clientes        | `customer` (roku-bank-web)      |
| `roku-bank` | `sofia@correo.example`     | Solo consulta   | `viewer` (roku-bank-web)        |
| `roku-bank` | `diego@rokubank.example`   | Administradores | `tenant-admin` (console)        |
| `roku-bank` | `ana@rokubank.example`     | Soporte         | `support` (console)             |
| `kaze-labs` | `lucas@kazelabs.example`   | Administradores | `tenant-admin` + portal `admin` |
| `kaze-labs` | `martin@kazelabs.example`  | Equipo          | `member` (kaze-portal)          |
| `kaze-labs` | `valen@kazelabs.example`   | Invitados       | `viewer` (kaze-portal)          |
| `rokusec`   | `juan@rokusec.example`     | Operadores      | `platform-operator` (console)   |

Customers (Martín, Sofía) log in with any address; their tenant comes from the
application. Operators' addresses use the tenant's registered domain, which is
how the console finds their tenant. All domains use the reserved `.example`
TLD so they cannot collide with real organisations.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.client_ids import SEEDED as SEEDED_CLIENT_IDS
from rba_idp.client_ids import new_client_id
from rba_idp.config import Settings
from rba_idp.db.models import (
    Application,
    Group,
    GroupMembership,
    GroupRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantDomain,
    User,
)
from rba_idp.passwords import hash_password

PLATFORM_TENANT_ID = "rokusec"

# Console permissions, the same on every tenant's console (ADR-0029). The
# support role holds the read pair and stops there (HU-10).
CONSOLE_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("admin", "read", "Abrir la consola y leer el directorio"),
    ("admin", "write", "Crear y modificar usuarios, grupos, roles y aplicaciones"),
    ("decisions", "read", "Leer las decisiones y sus motivos por señal"),
    ("policy", "write", "Cambiar umbrales, acciones, política base y modo del motor"),
)
# Only on the platform tenant's console, and only effective there: the IdP
# also requires the operator's tenant to be the platform tenant.
PLATFORM_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("tenants", "read", "Ver todas las organizaciones y cambiar entre ellas"),
    ("tenants", "write", "Crear organizaciones y editar su marca y dominios"),
)
TENANT_ADMIN_SCOPES = tuple((r, o) for r, o, _ in CONSOLE_PERMISSIONS)
SUPPORT_SCOPES = (("admin", "read"), ("decisions", "read"))


def permission_id(application_id: str, resource: str, operation: str) -> str:
    return f"perm_{application_id}_{resource}_{operation}".replace("-", "_")


def console_application_id(tenant_id: str) -> str:
    return f"{tenant_id}-console"


def admin_group_id(tenant_id: str) -> str:
    return f"grp_{tenant_id}_admins".replace("-", "_")


# ---------------------------------------------------------------- primitives


def _ensure_tenant(
    session: Session,
    tenant_id: str,
    name: str,
    *,
    is_platform: bool = False,
    login_style: str = "rokusec",
    primary_colour: str = "#1466E5",
    accent_colour: str = "#152953",
) -> Tenant:
    row = session.get(Tenant, tenant_id)
    if row is None:
        row = Tenant(
            tenant_id=tenant_id,
            name=name,
            is_platform=is_platform,
            display_name=name,
            login_style=login_style,
            primary_colour=primary_colour,
            accent_colour=accent_colour,
        )
        session.add(row)
        session.flush()
    return row


def _ensure_domain(session: Session, tenant_id: str, domain: str) -> None:
    if session.get(TenantDomain, domain) is None:
        session.add(TenantDomain(domain=domain, tenant_id=tenant_id))


def _ensure_application(
    session: Session,
    tenant_id: str,
    application_id: str,
    name: str,
    *,
    redirect_uri: str | None = None,
) -> None:
    row = session.get(Application, application_id)
    if row is None:
        session.add(
            Application(
                application_id=application_id,
                client_id=SEEDED_CLIENT_IDS.get(application_id) or new_client_id(),
                tenant_id=tenant_id,
                name=name,
                enabled=True,
                redirect_uri=redirect_uri,
            )
        )
        return
    if row.client_id is None:
        row.client_id = SEEDED_CLIENT_IDS.get(application_id) or new_client_id()
    if redirect_uri is not None:
        row.redirect_uri = redirect_uri


def _ensure_permissions(
    session: Session,
    application_id: str,
    rows: tuple[tuple[str, str, str], ...],
) -> None:
    for resource, operation, description in rows:
        pid = permission_id(application_id, resource, operation)
        if session.get(Permission, pid) is None:
            session.add(
                Permission(
                    permission_id=pid,
                    application_id=application_id,
                    resource=resource,
                    operation=operation,
                    description=description,
                )
            )


def _ensure_role(
    session: Session,
    tenant_id: str,
    role_id: str,
    application_id: str,
    name: str,
    description: str,
    scopes: tuple[tuple[str, str], ...],
) -> None:
    if session.get(Role, role_id) is None:
        session.add(
            Role(
                role_id=role_id,
                tenant_id=tenant_id,
                application_id=application_id,
                name=name,
                description=description,
            )
        )
        session.flush()
    for resource, operation in scopes:
        pid = permission_id(application_id, resource, operation)
        if session.get(RolePermission, (role_id, pid)) is None:
            session.add(RolePermission(role_id=role_id, permission_id=pid))


def _ensure_group(
    session: Session,
    tenant_id: str,
    group_id: str,
    name: str,
    description: str,
    role_ids: tuple[str, ...],
) -> None:
    if session.get(Group, group_id) is None:
        session.add(
            Group(group_id=group_id, tenant_id=tenant_id, name=name, description=description)
        )
        session.flush()
    for role_id in role_ids:
        if session.get(GroupRole, (group_id, role_id)) is None:
            session.add(GroupRole(group_id=group_id, role_id=role_id))


def _ensure_user(
    session: Session,
    tenant_id: str,
    user_id: str,
    email: str,
    password: str,
    group_ids: tuple[str, ...],
    *,
    is_admin: bool = False,
) -> None:
    email = email.strip().lower()
    exists = session.scalar(
        select(User).where(User.tenant_id == tenant_id, User.email == email)
    )
    if exists is None:
        session.add(
            User(
                user_id=user_id,
                tenant_id=tenant_id,
                email=email,
                password_hash=hash_password(password),
                enabled=True,
                is_admin=is_admin,
            )
        )
        session.flush()
    elif exists.user_id != user_id:
        return  # someone else's row under that address; leave it alone
    for group_id in group_ids:
        if session.get(GroupMembership, (group_id, user_id)) is None:
            session.add(GroupMembership(group_id=group_id, user_id=user_id))


# ---------------------------------------------------------------- consoles


def bootstrap_console(session: Session, tenant: Tenant) -> None:
    """Give a tenant its console: application, roles, and an admin group.

    Used by the seed and by tenant creation, so every tenant's console has the
    same shape. The admin group starts empty except in the seed.
    """
    tid = tenant.tenant_id
    console = console_application_id(tid)
    _ensure_application(session, tid, console, f"Consola {tenant.name}")
    session.flush()
    _ensure_permissions(session, console, CONSOLE_PERMISSIONS)
    admin_role = f"role_{tid}_tenant_admin".replace("-", "_")
    support_role = f"role_{tid}_support".replace("-", "_")
    _ensure_role(
        session, tid, admin_role, console, "tenant-admin",
        "Administrar la organización: directorio, aplicaciones y política de riesgo",
        TENANT_ADMIN_SCOPES,
    )
    _ensure_role(
        session, tid, support_role, console, "support",
        "Explicar un inicio de sesión: leer decisiones y motivos, sin cambiar nada",
        SUPPORT_SCOPES,
    )
    _ensure_group(
        session, tid, admin_group_id(tid), "Administradores",
        "Administran la organización en la consola", (admin_role,),
    )
    tenant.console_application_id = console
    tenant.admin_group_id = admin_group_id(tid)
    session.flush()


# ---------------------------------------------------------------- the seed


@dataclass(frozen=True)
class _SeedUser:
    user_id: str
    email: str
    groups: tuple[str, ...]
    is_admin: bool = False


@dataclass(frozen=True)
class _SeedTenant:
    tenant_id: str
    name: str
    domains: tuple[str, ...]
    is_platform: bool = False
    login_style: str = "rokusec"
    primary_colour: str = "#1466E5"
    accent_colour: str = "#152953"
    # Logo served by the tenant's own application, as a path on the origin of
    # this redirect setting's URL (the app knows its brand; the IdP links it).
    logo: tuple[str, str] | None = None
    # (application_id, name, redirect setting name or None)
    apps: tuple[tuple[str, str, str | None], ...] = ()
    # application_id → permissions
    permissions: dict[str, tuple[tuple[str, str, str], ...]] = field(default_factory=dict)
    # (role_id, application_id, name, description, scopes)
    roles: tuple[tuple[str, str, str, str, tuple[tuple[str, str], ...]], ...] = ()
    # (group_id, name, description, role_ids)
    groups: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()
    users: tuple[_SeedUser, ...] = ()


BANK_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("account", "read", "Ver saldos y datos de la cuenta"),
    ("transaction", "read", "Ver los movimientos"),
    ("transfer", "create", "Transferir dinero desde una cuenta"),
)
PORTAL_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("portal", "read", "Entrar al portal y leer su contenido"),
    ("projects", "write", "Crear y editar proyectos"),
    ("settings", "manage", "Administrar la configuración del portal"),
)

SEED_TENANTS: tuple[_SeedTenant, ...] = (
    _SeedTenant(
        tenant_id=PLATFORM_TENANT_ID,
        name="RokuSec",
        domains=("rokusec.example",),
        is_platform=True,
        permissions={"rokusec-console": PLATFORM_PERMISSIONS},
        roles=(
            (
                "role_rokusec_platform_operator", "rokusec-console", "platform-operator",
                "Operar la plataforma: todas las organizaciones",
                TENANT_ADMIN_SCOPES + (("tenants", "read"), ("tenants", "write")),
            ),
        ),
        groups=(
            ("grp_rokusec_operators", "Operadores", "Operadores de la plataforma",
             ("role_rokusec_platform_operator",)),
        ),
        users=(
            _SeedUser("usr_rs_juan", "juan@rokusec.example",
                      ("grp_rokusec_operators", "grp_rokusec_admins"), is_admin=True),
        ),
    ),
    _SeedTenant(
        tenant_id="roku-bank",
        name="Roku Bank",
        domains=("rokubank.example",),
        login_style="tenant",
        primary_colour="#0B6E4F",
        accent_colour="#073B2A",
        logo=("seed_bank_redirect_uri", "/static/brand/roku-bank-mark.svg"),
        apps=(("roku-bank-web", "Roku Bank", "seed_bank_redirect_uri"),),
        permissions={"roku-bank-web": BANK_PERMISSIONS},
        roles=(
            ("role_rb_customer", "roku-bank-web", "customer",
             "Banca completa: ver cuentas y transferir",
             (("account", "read"), ("transaction", "read"), ("transfer", "create"))),
            # Same app, one permission short: RF-21 authorizes operations.
            ("role_rb_viewer", "roku-bank-web", "viewer",
             "Solo consulta: ve saldos, no transfiere",
             (("account", "read"), ("transaction", "read"))),
        ),
        groups=(
            ("grp_rb_customers", "Clientes", "Clientes de banca minorista", ("role_rb_customer",)),
            ("grp_rb_viewers", "Solo consulta", "Acceso de solo lectura", ("role_rb_viewer",)),
            ("grp_rb_support", "Soporte", "Explican una decisión; no cambian nada",
             ("role_roku_bank_support",)),
        ),
        users=(
            _SeedUser("usr_rb_martin", "martin@correo.example", ("grp_rb_customers",)),
            _SeedUser("usr_rb_sofia", "sofia@correo.example", ("grp_rb_viewers",)),
            _SeedUser("usr_rb_diego", "diego@rokubank.example", ("grp_roku_bank_admins",),
                      is_admin=True),
            _SeedUser("usr_rb_ana", "ana@rokubank.example", ("grp_rb_support",)),
        ),
    ),
    _SeedTenant(
        tenant_id="kaze-labs",
        name="Kaze Labs",
        domains=("kazelabs.example",),
        apps=(("kaze-portal", "Kaze Portal", "seed_kaze_redirect_uri"),),
        permissions={"kaze-portal": PORTAL_PERMISSIONS},
        roles=(
            ("role_kz_admin", "kaze-portal", "admin", "Todo el portal, configuración incluida",
             (("portal", "read"), ("projects", "write"), ("settings", "manage"))),
            ("role_kz_member", "kaze-portal", "member", "Lee el portal y edita proyectos",
             (("portal", "read"), ("projects", "write"))),
            ("role_kz_viewer", "kaze-portal", "viewer", "Solo lectura",
             (("portal", "read"),)),
        ),
        groups=(
            ("grp_kz_team", "Equipo", "Empleados de Kaze Labs", ("role_kz_member",)),
            ("grp_kz_guests", "Invitados", "Acceso de solo lectura", ("role_kz_viewer",)),
            ("grp_kz_portal_admins", "Administradores del portal",
             "Configuran el portal", ("role_kz_admin",)),
        ),
        users=(
            _SeedUser("usr_kz_lucas", "lucas@kazelabs.example",
                      ("grp_kaze_labs_admins", "grp_kz_portal_admins"), is_admin=True),
            _SeedUser("usr_kz_martin", "martin@kazelabs.example", ("grp_kz_team",)),
            _SeedUser("usr_kz_valen", "valen@kazelabs.example", ("grp_kz_guests",)),
        ),
    ),
)


def seed_password(email: str, settings: Settings) -> str:
    """``martin@correo.example`` → ``martin-demo`` (suffix from settings)."""
    return f"{email.split('@', 1)[0]}-{settings.seed_password_suffix}"


def seed_identity(session: Session, settings: Settings) -> None:
    for spec in SEED_TENANTS:
        tenant = _ensure_tenant(
            session,
            spec.tenant_id,
            spec.name,
            is_platform=spec.is_platform,
            login_style=spec.login_style,
            primary_colour=spec.primary_colour,
            accent_colour=spec.accent_colour,
        )
        if spec.logo and tenant.logo_url is None:
            setting, path = spec.logo
            origin = urlsplit(getattr(settings, setting))
            tenant.logo_url = f"{origin.scheme}://{origin.netloc}{path}"
        for domain in spec.domains:
            _ensure_domain(session, spec.tenant_id, domain)
        bootstrap_console(session, tenant)
        for application_id, name, redirect_setting in spec.apps:
            redirect = getattr(settings, redirect_setting) if redirect_setting else None
            _ensure_application(
                session, spec.tenant_id, application_id, name, redirect_uri=redirect or None
            )
        session.flush()
        for application_id, rows in spec.permissions.items():
            _ensure_permissions(session, application_id, rows)
        session.flush()
        for role_id, application_id, name, description, scopes in spec.roles:
            _ensure_role(session, spec.tenant_id, role_id, application_id, name, description, scopes)
        for group_id, name, description, role_ids in spec.groups:
            _ensure_group(session, spec.tenant_id, group_id, name, description, role_ids)
        session.flush()
        for user in spec.users:
            _ensure_user(
                session,
                spec.tenant_id,
                user.user_id,
                user.email,
                seed_password(user.email, settings),
                user.groups,
                is_admin=user.is_admin,
            )
    # Applications created before client ids existed (consoles, ones an
    # operator registered on a kept database) get one too.
    for app in session.scalars(select(Application).where(Application.client_id.is_(None))).all():
        app.client_id = SEEDED_CLIENT_IDS.get(app.application_id) or new_client_id()
    session.commit()
