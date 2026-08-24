"""SQLAlchemy models: applications, users, groups, roles, sessions, MFA challenges.

Authorization is RBAC (ADR-0029): ``user → group → role → permission``, with
every role scoped to one application. Groups say *who*; roles say *what you
may do*. Holding any role on an application is what grants sign-in to it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Application(Base):
    """Registered client of the IdP (Auth0 'application' / Authentik app, simplified)."""

    __tablename__ = "applications"

    application_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    redirect_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Directory label only — **not** an authorization input (ADR-0029).
    # Authorization is the RBAC chain below. Setting this through the admin API
    # adds or removes the platform-admin role, so the flag can never disagree
    # with what the user can actually do.
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Group(Base):
    """Named collection of users. Grants (not is_admin) decide which apps they may log into."""

    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("name", name="uq_groups_name"),)

    group_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class GroupMembership(Base):
    __tablename__ = "group_memberships"

    group_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("groups.group_id"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.user_id"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Permission(Base):
    """One operation on one resource, scoped to one application.

    The wire form clients check is ``f"{resource}:{operation}"`` — e.g.
    ``transfer:create``. It is derived on serialisation, never stored twice.
    """

    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint(
            "application_id", "resource", "operation", name="uq_permissions_scope"
        ),
    )

    permission_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("applications.application_id"), nullable=False, index=True
    )
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Role(Base):
    """Named bundle of permissions on one application.

    Roles are application-scoped on purpose: ``viewer`` on the bank and
    ``viewer`` on the admin console are different things, and a role that could
    span applications would let one tenant's admin grant rights on another's.
    """

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("application_id", "name", name="uq_roles_app_name"),
    )

    role_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    application_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("applications.application_id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("roles.role_id"), primary_key=True
    )
    permission_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("permissions.permission_id"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class GroupRole(Base):
    """Role assignment. Users get roles by belonging to a group, never directly —
    one place to look when asking why someone can do something."""

    __tablename__ = "group_roles"

    group_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("groups.group_id"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("roles.role_id"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IdpSession(Base):
    """Opaque bearer session. Lookup key is sha256(token), never the raw token."""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.user_id"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class MfaChallenge(Base):
    """Pending MFA / reauth after the PDP asked for a step-up.

    Live path is WebAuthn (Demo-4). Mock OTP on ``POST /mfa/verify`` stays for tests.
    """

    __tablename__ = "mfa_challenges"

    challenge_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.user_id"), nullable=False, index=True
    )
    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    reasons: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    webauthn_challenge: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    webauthn_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class WebAuthnCredential(Base):
    """Platform passkey bound to a user. Credential id is base64url."""

    __tablename__ = "webauthn_credentials"

    credential_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.user_id"), nullable=False, index=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuthCode(Base):
    """One-time callback code bound to an issued session (Demo-2, not OIDC)."""

    __tablename__ = "auth_codes"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_token: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    application_id: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
