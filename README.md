# Haris-Team23

A monitoring layer for multi-agent LLM apps. Haris sits between agents,
inspects every inter-agent message, and flags secrets/PII, authorization,
and information-flow problems before they cause harm.

## Scope decisions 

- **Framework:** LangGraph only.
- **Demo scenario:** hospital app — reads a patient record, summarizes it, emails the summary.
- **Mode:** monitor first. Haris logs and flags but does **not** block yet, so a
  false positive can never break the app during development. Enforce mode is turned on later.
- **MVP agents:** Secrets & PII, Authorization, Information-flow.
  Injection and Semantic are explicitly roadmap, not MVP.

## Project structure

    haris/
      schemas/       # frozen contracts: Message, Verdict, Policy
      agents/        # SecurityAgent interface + the MVP agents
      state/         # StateStore interface + in-memory implementation
      orchestrator/  # routes a message through Haris
      policy/        # policy engine
    demo_app/        # hospital demo + interception adapter
    tests/

## Getting started

    python -m venv .venv
    source .venv/bin/activate        # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python -m demo_app.run_demo      # one message end-to-end through Haris
    pytest
