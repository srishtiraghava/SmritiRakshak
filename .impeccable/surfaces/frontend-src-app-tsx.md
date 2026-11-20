---
version: 1
slug: "frontend-src-app-tsx"
primary_target: "frontend/src/App.tsx"
related_targets: []
---

# SmritiRakshak dashboard

Scope: entire web application shell and all six in-app views. Mode: Operate.

Audience: developers building AI agents. They need to inspect memory candidates, understand security decisions, investigate findings, and review quarantined records.

Task and success: move from live system health to the right memory, threat, quarantine, audit, or simulation workflow without losing the meaning of risk and disposition. All existing API-backed data and actions remain functional.

## Direction contract

### THESIS

Treat each memory as an evidence record whose risk, findings, and current disposition are legible at a glance. Refuse the interchangeable dashboard of oversized metric cards and decorative threat charts.

### OWN-WORLD

An evidence docket expressed through a graphite and deep-teal workspace, warm off-white text, muted emerald as the primary accent, restrained cyan for selection, and amber/red only for meaningful risk states. System sans carries prose; tabular numerals and mono are reserved for scores, IDs, hashes, and timestamps. Fine rules and measured negative space keep evidence scannable. Raise from the character catalog: every record keeps a consistent decision and risk hierarchy. Raise from the star atlas: scores and severity use a fixed, labeled scale. Raise from the coded catalog sleeve: a unified dark shell still gives every state a readable name. Raise from the reference rail: supporting evidence stays distinct from disposition. Raise from the departure board: updates and degraded states remain explicit and easy to spot.

### STORY

The developer first sees whether the firewall and database are reachable, then the real disposition counts and recent decisions. They can inspect evidence, move to the queue needing attention, trace blocked activity, or simulate a candidate. A decision spine ties a record's actual score, findings, and current tier together without inventing an event history.

### FIRST VIEWPORT

At desktop widths, a compact status header spans the top and a named six-item navigation rail anchors the left. The overview work area begins with its title and refresh/simulator actions, then presents API-backed disposition counts in a ruled summary row. Below, a real risk-distribution chart and recent-decision table share the workspace; row selection opens the evidence detail. At narrow widths, the rail becomes a menu and content stacks in task order without horizontal page overflow.

### FORM

The chosen direction is the Evidence docket, the assigned third candidate in the ordered grounded list. Seven considered systems: standards registry, technical field manual, evidence docket (assigned), geospatial survey, service reliability report, transit timetable, and scientific appendix. seed:3b0e2b266e04178d. The signature move is a quiet decision spine: risk score and findings resolve into the current disposition wherever a record is inspected. Tables, forms, filters, familiar buttons, dialogs, and charts remain ordinary accessible web controls.

### FINISH

unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Direction selection

- Competitive: Dark-first developer console, for audience identification and product clarity. Its focused state accents remain a useful calibration, while the chosen docket keeps stronger product-specific hierarchy.
- Competitive: Centre-rail reference setting, for dense evidence legibility. The chosen system uses a restrained evidence detail area without letting annotation become navigation.
- Declined, raise retained: Character catalog loses audience identification and product clarity; retain consistent item-level decision hierarchy.
- Declined, raise retained: Star atlas loses audience identification and weakens exact risk reading; retain a fixed labeled scale for scores and severity.
- Declined, raise retained: Saville catalog sleeve obscures explicit state labels; retain a unified dark shell while keeping all state names readable.
- Declined, raise retained: Split-flap concourse adds motion without serving the review task; retain visible refresh, loading, and degraded states.
