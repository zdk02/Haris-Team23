# Haris - Phase 0 scaffold

Do-nothing skeleton + frozen contracts. Goal of Phase 0: prove the plumbing and
freeze the interfaces so two people can build in parallel tomorrow.

## Frozen contracts (do not change without telling your teammate)
- `haris/schemas/message.py`  - Message
- `haris/schemas/verdict.py`  - Verdict + Label
- `haris/schemas/policy.py`   - Policy + PolicyRule + Mode (incl. data_subject)
- `haris/agents/base.py`      - SecurityAgent.check(message, context) -> Verdict
- `haris/state/base.py`       - StateStore (get_context / record_flow / get_lineage)

## Skeleton
- `haris/state/memory.py`              - throwaway in-memory StateStore
- `haris/orchestrator/orchestrator.py` - calls ZERO agents, logs, passes through
- `demo_app/interception.py`           - interception adapter (the seam)
- `demo_app/run_demo.py`               - one message end-to-end (the milestone)

## Run
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python -m demo_app.run_demo
    pytest
