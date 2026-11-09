## Summary

<!-- One paragraph: what this PR changes and why. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / capability
- [ ] Detection rule (new or updated)
- [ ] Refactor / quality improvement
- [ ] Documentation
- [ ] CI / infrastructure

## Testing

- [ ] All backend tests pass (`pytest --tb=short -q`)
- [ ] `alembic check` reports zero drift
- [ ] `ruff check .` passes
- [ ] TypeScript type-check passes (`tsc --noEmit`)
- [ ] Frontend builds (`npm run build`)
- [ ] New behavior is covered by tests

## Security checklist

- [ ] No new privileged actions added to `TOOL_REGISTRY`
- [ ] Tenant isolation maintained (no unscoped queries for tenant-scoped resources)
- [ ] No secrets or credentials committed
- [ ] Evidence validation gate not weakened
- [ ] Human approval requirement not bypassed

## Migration

- [ ] No schema change
- [ ] Schema change — new Alembic migration included, `alembic check` passes

## Screenshots (frontend changes only)

<!-- Paste before/after screenshots if the UI changed. -->
