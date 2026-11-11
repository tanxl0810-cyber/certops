import os
import uuid
from datetime import datetime, timezone
from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, JSON, String, Text,
                        UniqueConstraint, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now():
    return datetime.now(timezone.utc)


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    must_change: Mapped[bool] = mapped_column(Boolean, default=True)


class LoginSession(Base):
    __tablename__ = 'login_sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    csrf: Mapped[str] = mapped_column(String(80))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FeishuIdentity(Base):
    __tablename__ = 'feishu_identities'
    __table_args__ = (UniqueConstraint('app_id', 'open_id'),)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    app_id: Mapped[str] = mapped_column(String(128))
    open_id: Mapped[str] = mapped_column(String(128))
    tenant_key: Mapped[str] = mapped_column(String(128))
    display_name: Mapped[str] = mapped_column(String(128))


class FeishuLoginAttempt(Base):
    __tablename__ = 'feishu_login_attempts'
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_hash: Mapped[str] = mapped_column(String(64))
    verifier_encrypted: Mapped[str] = mapped_column(Text)
    config_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Credential(Base):
    __tablename__ = 'credentials'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(30))
    encrypted: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Certificate(Base):
    __tablename__ = 'certificates'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160))
    domains: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(30), default='upload')
    credential_id: Mapped[str | None] = mapped_column(ForeignKey('credentials.id'), nullable=True)
    issuer_config: Mapped[dict] = mapped_column(JSON, default=dict)
    latest_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_deploy: Mapped[bool] = mapped_column(Boolean, default=False)
    renew_before_days: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    state: Mapped[str] = mapped_column(String(40), default='pending')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Version(Base):
    __tablename__ = 'certificate_versions'
    __table_args__ = (UniqueConstraint('certificate_id', 'fingerprint'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    certificate_id: Mapped[str] = mapped_column(ForeignKey('certificates.id'))
    fingerprint: Mapped[str] = mapped_column(String(64))
    cert_pem: Mapped[str] = mapped_column(Text)
    key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    domains: Mapped[list] = mapped_column(JSON)
    issuer: Mapped[str] = mapped_column(Text)
    serial: Mapped[str] = mapped_column(String(100))
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Target(Base):
    __tablename__ = 'targets'
    __table_args__ = (UniqueConstraint('kind', 'credential_id', 'resource_key'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(180))
    kind: Mapped[str] = mapped_column(String(30))
    domain: Mapped[str] = mapped_column(String(253))
    region: Mapped[str] = mapped_column(String(50), default='cn-shenzhen')
    resource_key: Mapped[str] = mapped_column(String(500))
    credential_id: Mapped[str | None] = mapped_column(ForeignKey('credentials.id'), nullable=True)
    certificate_id: Mapped[str | None] = mapped_column(ForeignKey('certificates.id'), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_deploy: Mapped[bool] = mapped_column(Boolean, default=False)
    deployed_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    previous_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    observed: Mapped[dict] = mapped_column(JSON, default=dict)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class TargetExclusion(Base):
    __tablename__ = 'target_exclusions'
    target_id: Mapped[str] = mapped_column(ForeignKey('targets.id'), primary_key=True)
    reason: Mapped[str] = mapped_column(String(400))
    excluded_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Job(Base):
    __tablename__ = 'jobs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    certificate_id: Mapped[str | None] = mapped_column(ForeignKey('certificates.id'), nullable=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey('targets.id'), nullable=True)
    version_id: Mapped[str | None] = mapped_column(ForeignKey('certificate_versions.id'), nullable=True)
    args: Mapped[dict] = mapped_column(JSON, default=dict)
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(30), default='queued', index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Setting(Base):
    __tablename__ = 'settings'
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class ResourceArchive(Base):
    __tablename__ = 'resource_archives'
    kind: Mapped[str] = mapped_column(String(30), primary_key=True)
    resource_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    deleted_by: Mapped[str] = mapped_column(String(80))
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PipelineRunner(Base):
    __tablename__ = 'pipeline_runners'
    target_id: Mapped[str] = mapped_column(ForeignKey('targets.id'), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PipelineExecution(Base):
    __tablename__ = 'pipeline_executions'
    job_id: Mapped[str] = mapped_column(ForeignKey('jobs.id'), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey('targets.id'), index=True)
    attempt_id: Mapped[str] = mapped_column(String(36), default=uid)
    state: Mapped[str] = mapped_column(String(30), default='ready')
    pipeline_run_id: Mapped[str] = mapped_column(String(30), default='')
    remote_status: Mapped[str] = mapped_column(String(30), default='')
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    report_hash: Mapped[str] = mapped_column(String(64), default='')
    dispatch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Audit(Base):
    __tablename__ = 'audit_log'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(100), default='')
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Alert(Base):
    __tablename__ = 'alerts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dedupe_key: Mapped[str] = mapped_column(String(400), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default='pending')
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default='')
    next_attempt: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


url = os.getenv('DATABASE_URL', 'sqlite:///./certops-dev.db')
engine = create_engine(url, pool_pre_ping=True,
                       **({'pool_size': 4, 'max_overflow': 2} if not url.startswith('sqlite') else {}))
if url.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def sqlite_pragmas(conn, _):
        conn.execute('PRAGMA foreign_keys=ON')
Session = sessionmaker(engine, expire_on_commit=False)


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def init_db():
    Base.metadata.create_all(engine)


def get_db():
    with Session() as db:
        yield db


def setting(db, key, default=None):
    item = db.get(Setting, key)
    return item.value if item else (default or {})


def set_setting(db, key, value):
    item = db.get(Setting, key)
    if item:
        item.value = value
    else:
        db.add(Setting(key=key, value=value))
