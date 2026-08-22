import uuid

from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPrimaryKeyMixin

# DetectionRule <-> MitreTechnique (Phase 6). DetectionRule also keeps its
# own `mitre_technique_ids` JSON list (Phase 1/4) for cheap access without
# a join; this table is the *relational* source of truth used for
# coverage queries (app/api/v1/mitre.py's matrix/coverage endpoints) and
# is kept in sync with the JSON list by app/mitre/seed.py::link_detection_rules_to_techniques.
detection_rule_mitre_techniques = Table(
    "detection_rule_mitre_techniques",
    Base.metadata,
    Column("detection_rule_id", UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", UUID(as_uuid=True), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True),
)


class MitreTactic(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "mitre_tactics"

    tactic_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)  # e.g. TA0002
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    # ATT&CK's own ordering (Recon/Resource Dev first, then the kill-chain
    # tactics) — used to render the matrix in the conventional left-to-right
    # order rather than alphabetically or by insertion order.
    matrix_order: Mapped[int] = mapped_column(default=0, nullable=False)

    techniques: Mapped[list["MitreTechnique"]] = relationship(back_populates="tactic")


class MitreTechnique(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One ATT&CK technique or sub-technique. Sub-techniques (e.g.
    T1059.001) are their own row with their own `technique_id` — same
    convention Sigma's `attack.txxxx.yyy` tags and this platform's
    DetectionRule.mitre_technique_ids already use — linked to their
    parent via `parent_technique_id` rather than a separate boolean
    column (a technique is a sub-technique iff it has a parent).

    Note on scope: real ATT&CK techniques can map to *multiple* tactics
    (e.g. T1078 Valid Accounts spans Initial Access, Persistence,
    Privilege Escalation, and Defense Evasion). This schema's `tactic_id`
    is a single FK, so the seed data (app/mitre/data.py) picks one
    primary tactic per technique — documented there, not hidden — rather
    than modeling the full many-to-many ATT&CK relationship, which would
    need its own join table for marginal benefit at this project's scale.
    """
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)  # e.g. T1059.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)

    tactic_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mitre_tactics.id"), nullable=True, index=True
    )
    tactic: Mapped["MitreTactic | None"] = relationship(back_populates="techniques")

    parent_technique_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mitre_techniques.id", ondelete="SET NULL"), nullable=True, index=True
    )
    parent: Mapped["MitreTechnique | None"] = relationship(remote_side="MitreTechnique.id", back_populates="subtechniques")
    subtechniques: Mapped[list["MitreTechnique"]] = relationship(back_populates="parent")

    detection_rules: Mapped[list["DetectionRule"]] = relationship(  # noqa: F821
        secondary=detection_rule_mitre_techniques, back_populates="mitre_techniques"
    )

    @property
    def is_subtechnique(self) -> bool:
        return self.parent_technique_id is not None
