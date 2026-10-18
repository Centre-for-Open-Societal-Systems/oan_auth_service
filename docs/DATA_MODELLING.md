# Data Modelling

Rules for deciding where data lives. They apply to every OAN Frappe app.

## Rules of Thumb

- **One current value is a field. A history of events is its own DocType.**
- **1:1 with the same lifetime: one DocType with optional fields.** Different count or
  lifetime: separate DocTypes.
- **A child table is saved with its parent.** If one row must be updated, permissioned or
  listed on its own, or two users edit different rows at once, it is a linked DocType,
  not a child table.
- **Copy a hot field with a sync hook instead of reshaping the schema.** The copy can
  always be recomputed from its source.
- **Snapshot what a decision was based on.** A submitted record copies the data it was
  decided on (linked values copied as text), so a later edit or archive of the source
  does not rewrite history.
- **Archive, do not delete,** records that other records point at.
- **Denormalised lookup tables only for a measured slow query.** Keep them in sync through
  `doc_events`, never write them directly, and provide a rebuild job.
- **Split systems by the data they share, not by who uses them.** Two user groups that
  read and write the same records stay in one app.
- **Record the decision.** For a non-obvious design choice, add an entry to the app's
  `docs/design_decisions.md` with **Decision**, **Why** and **Considered**, so the
  trade-off is not argued again.
