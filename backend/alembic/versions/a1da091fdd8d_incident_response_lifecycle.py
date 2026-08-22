"""incident_response_lifecycle

Phase 9. Extends the incident tables Phase 1 created with the lifecycle
state the response engine needs: per-tenant case numbering, the derived
milestone timestamps the IR metrics are computed from, a mandatory
closure verdict, and the checklist fields on incident_tasks.

Three departures from what `--autogenerate` produced, each deliberate:

1. **The four new NOT NULL columns on `incident_tasks` are added with a
   `server_default`, which is then dropped.** Autogenerate emitted them
   bare, which fails outright on any table that already has rows. Adding
   the default backfills existing rows in the same statement; dropping it
   afterwards hands responsibility for new rows back to the ORM defaults,
   so the schema does not quietly acquire a second source of truth for
   what a new task looks like.

2. **The `completed_by_id` foreign key is named.** Autogenerate emitted
   `create_foreign_key(None, ...)` / `drop_constraint(None, ...)`; the
   latter cannot execute, so the downgrade path was broken as generated.

3. **`incident_number` and `detected_at` are backfilled.** A case with no
   reference number is not a case an analyst can talk about in a
   handover, and metrics measured from a null `detected_at` are null.
   `detected_at` is backfilled from the earliest linked alert's *own*
   timestamp where one exists, falling back to `created_at` — matching
   what app/services/incidents.py::_refresh_detected_at does going
   forward, rather than inventing a different rule for historical rows.

`closure_classification` is deliberately *not* backfilled for incidents
already sitting in status `closed`. There is no honest value to invent —
nobody recorded a verdict, because there was nowhere to record one — and
guessing `true_positive` would silently corrupt the false-positive rate
this column exists to make measurable. Those rows stay null and are
visibly pre-Phase-9; the requirement binds every closure from here on.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1da091fdd8d'
down_revision: Union[str, None] = '8634b26c3ee1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- incident_tasks: checklist fields -------------------------------
    op.add_column(
        'incident_tasks',
        sa.Column('description', sa.String(), nullable=False, server_default=''),
    )
    op.add_column(
        'incident_tasks',
        sa.Column('category', sa.String(length=32), nullable=False, server_default='detection_analysis'),
    )
    op.add_column(
        'incident_tasks',
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column(
        'incident_tasks',
        sa.Column('is_from_template', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column('incident_tasks', sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incident_tasks', sa.Column('completed_by_id', sa.UUID(), nullable=True))

    # Defaults were only needed to backfill the existing rows above.
    for column in ('description', 'category', 'sort_order', 'is_from_template'):
        op.alter_column('incident_tasks', column, server_default=None)

    op.create_index(op.f('ix_incident_tasks_category'), 'incident_tasks', ['category'], unique=False)
    op.create_foreign_key(
        'fk_incident_tasks_completed_by_id_users', 'incident_tasks', 'users', ['completed_by_id'], ['id']
    )

    # --- incidents: case number, milestones, closure verdict ------------
    op.add_column('incidents', sa.Column('incident_number', sa.Integer(), nullable=True))
    op.add_column('incidents', sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('triaged_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('contained_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('closure_classification', sa.String(length=32), nullable=True))
    op.add_column('incidents', sa.Column('closure_summary', sa.String(), nullable=True))

    # Backfill per-tenant case numbers in creation order, so the oldest
    # incident in each organization becomes INC-000001. Partitioning by
    # organization_id groups the NULL-org rows of a single-tenant install
    # together, which is the intended behaviour rather than an accident.
    op.execute(
        """
        WITH numbered AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY organization_id ORDER BY created_at, id
                   ) AS rn
            FROM incidents
        )
        UPDATE incidents
        SET incident_number = numbered.rn
        FROM numbered
        WHERE incidents.id = numbered.id
        """
    )

    op.execute(
        """
        UPDATE incidents i
        SET detected_at = COALESCE(
            (
                SELECT MIN(a.alert_timestamp)
                FROM incident_alerts ia
                JOIN alerts a ON a.id = ia.alert_id
                WHERE ia.incident_id = i.id
            ),
            i.created_at
        )
        WHERE i.detected_at IS NULL
        """
    )

    # An incident already sitting in `closed` was closed at some point;
    # `updated_at` is the best available approximation and is better than
    # leaving the case looking permanently open to the metrics.
    op.execute(
        "UPDATE incidents SET closed_at = updated_at WHERE status = 'closed' AND closed_at IS NULL"
    )

    op.create_index(
        op.f('ix_incidents_closure_classification'), 'incidents', ['closure_classification'], unique=False
    )
    op.create_index(op.f('ix_incidents_incident_number'), 'incidents', ['incident_number'], unique=False)
    op.create_unique_constraint('uq_incidents_org_number', 'incidents', ['organization_id', 'incident_number'])


def downgrade() -> None:
    op.drop_constraint('uq_incidents_org_number', 'incidents', type_='unique')
    op.drop_index(op.f('ix_incidents_incident_number'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_closure_classification'), table_name='incidents')
    op.drop_column('incidents', 'closure_summary')
    op.drop_column('incidents', 'closure_classification')
    op.drop_column('incidents', 'closed_at')
    op.drop_column('incidents', 'contained_at')
    op.drop_column('incidents', 'triaged_at')
    op.drop_column('incidents', 'detected_at')
    op.drop_column('incidents', 'incident_number')
    op.drop_constraint('fk_incident_tasks_completed_by_id_users', 'incident_tasks', type_='foreignkey')
    op.drop_index(op.f('ix_incident_tasks_category'), table_name='incident_tasks')
    op.drop_column('incident_tasks', 'completed_by_id')
    op.drop_column('incident_tasks', 'completed_at')
    op.drop_column('incident_tasks', 'is_from_template')
    op.drop_column('incident_tasks', 'sort_order')
    op.drop_column('incident_tasks', 'category')
    op.drop_column('incident_tasks', 'description')
