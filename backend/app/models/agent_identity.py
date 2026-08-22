from sqlalchemy import JSON, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AgentIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A non-human principal. AI agents are never User rows, never get a JWT,
    and never call authenticated HTTP endpoints directly — they run
    server-side, inside the request context of the analyst who triggered an
    investigation, and every tool call they make is checked against *this*
    identity's allowlist, not the invoking analyst's permissions.

    This is what makes 'the AI agent never inherits admin privileges' a
    structural property rather than a prompt instruction: even a fully
    compromised/jailbroken LLM can only reach functions listed in
    `allowed_tools`, and `max_effect` caps those tools to read_only or
    propose_only — 'privileged_action' tools are never even registered for
    any agent (see app/ai/tools/registry.py and
    app/ai/agents/permissions.py).
    """
    __tablename__ = "agent_identities"

    agent_type: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)  # AgentType
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)

    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_effect: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")  # ActionEffect ceiling

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
