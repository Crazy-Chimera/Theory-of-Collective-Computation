# Theory of Collective Computation

A protocol and reference implementation for identity-bound agents, authorized memory, distributed computation, verified knowledge contributions, and transparent rewards.

## Current milestone: Identity & Authorization v0.1.0

This repository begins with a deliberately small, testable foundation:
- explicit participant identities and agent registration;
- deny-by-default authorization grants;
- a minimal health endpoint for Render;
- tests and CI checks.

The current identity registry and authorization policy are **in-memory reference components**, not production authentication, durable storage, or a complete distributed protocol. Do not use them to protect sensitive data or funds.

## Development

Requires Python 3.11+.

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src
pytest
```

Run the health service:

```bash
python -m collective_computation.server
```

The service listens on `0.0.0.0:10000` by default. Configure `PORT` to override it. `GET /health` returns a small JSON health response.

## Evolution protocol

Work proceeds context → contract → implementation → tests → integration → verification → deployment → learning. A generated implementation is not considered verified until the relevant checks have actually run and their results have been inspected.

The Φ–Ω–Ω²–ΦΩ²–Γ–Π–Ψ–Θ–Ρ–Σ–ΙΩΤΑ framework is used as a conceptual architecture. Its equations are not represented here as experimentally established physical laws.
