# §5 Deployment — working notes

**Owner:** Batoul · **Written:** 23 Aug 2026, while the work was fresh (task J8)
**Status:** notes and evidence pointers, not prose. Turn into §5 on Fri 28.

Every claim below has evidence. `[check N]` refers to a numbered section of
`report/appendix/deployment-verification.txt`, produced by `verify-deployment.ps1`.

---

## 5.1 What was built

One Fargate task behind an internet-facing ALB across two availability zones, fronted by
Route 53 and TLS, defined entirely in one CloudFormation template.

```
Internet → Route 53 (haris-monitor.com, A/alias)
         → ALB  :443 HTTPS (ACM cert, TLS 1.3 policy) · :80 → 301 → :443
         → Target group :8501, health check /_stcore/health
         → Fargate task ×1 (1 vCPU / 2 GB), image from ECR
         → CloudWatch Logs
```

23 resources, one `aws cloudformation deploy`. Template is Appendix B. `[check 7]`

**Deliberately not in the stack:** the ECR repository and the Secrets Manager secret. They
hold state that should outlive the stack, so `delete-stack` cannot destroy the image or
the operator token.

## 5.2 The reproducible artefact

- Base `python:3.11-slim`; pin by digest before the submission build
- **No compiler in the image.** `build-essential` removed — numpy/blis/thinc/spaCy all
  publish cp311 manylinux wheels. ~250 MB and a whole toolchain off the attack surface
- **Runs as uid 10001**, not root. Proven with `whoami` / `id`, not asserted
- **Installed from `requirements.lock.txt`**, and the spaCy model is pinned by **SHA-256**,
  not just version. `requirements.txt` documents intent; the lockfile pins reality
- Language model baked at **build** time, so a task start never depends on reaching a
  model host over the network
- Container `HEALTHCHECK` hits the same endpoint the ALB target group polls, so a health
  failure looks identical locally and in production

| Measurement | Value |
|---|---|
| Build time | 6m13s |
| Image, uncompressed on disk | 1.32 GB |
| Image, compressed in ECR (what Fargate pulls) | 281 MB |
| Push to ECR | 4m59s |
| Peak working set, all pages exercised, Presidio loaded | 198 MB |
| First render after sign-in (local) | ~2 s |
| Container healthcheck passes at | ~56 s |

Measured against commit `18d41ef`.

**Sizing rationale:** 1 vCPU / 2048 MB against a 198 MB working set is a deliberate ~10×
margin. A Fargate OOM kill surfaces as an unexplained task restart loop, not a diagnosable
error, so the headroom buys diagnosability rather than performance.

## 5.3 Security boundaries — the part that carries the section

**Network.** The task's security group admits port 8501 **from the load balancer's security
group**, not from a CIDR range. There is no address anyone can route from to reach the
container. `[check 16]` — exactly one inbound rule, `FromGroup` set, `FromCidr: null`.

**Identity — and a correction worth stating.** The original plan put CloudWatch logging on
the *task* role. That is wrong: the `awslogs` driver is executed by the ECS agent, so it
authenticates with the **execution** role. Built as originally planned, the log group would
have stayed empty.

- **Execution role** `[check 11]`: ECR pull scoped to `repository/haris`; `CreateLogStream`
  + `PutLogEvents` scoped to `log-group:/ecs/haris:*`; `GetSecretValue` scoped to the single
  secret ARN. One action — `ecr:GetAuthorizationToken` — sits on `Resource: "*"` because the
  ECR authorization token is account-wide by design and **cannot** be resource-scoped.
- **Task role** `[check 12]`: **no policies at all.** The dashboard makes no AWS API calls,
  so the container's own credentials can invoke nothing. The empty list is the result, not
  an omission.

**The secret.** Injected at task start from Secrets Manager via the execution role. Be
precise about the claim: it *does* become an environment variable inside the container. What
is true is that the value never appears in version control, in the image, in
`describe-task-definition` output `[check 13]`, or in CI logs. SSM Parameter Store
`SecureString` was considered — functionally identical for ECS and free — and Secrets
Manager chosen for rotation support.

**TLS.** ACM certificate for apex + wildcard, DNS-validated `[check 4]`. Policy
`ELBSecurityPolicy-TLS13-1-2-2021-06`; `:80` returns 301 `[checks 10, 15]`. **The private key
is generated inside ACM, is never exported, never enters version control, and is never
handled by an operator.** Renewal is automatic via the validation record retained in the
hosted zone.

**Image scanning.** Basic scanning, scan-on-push, wildcard filter `[check 6]`. 4 CRITICAL /
8 HIGH / 6 MEDIUM, all in Debian base packages, none in application dependencies. Accepted:
eliminating them means a distroless or Alpine base, and the spaCy/Presidio chain expects
glibc.

> **Finding worth reporting.** The per-repository "Scan on push" toggle is **deprecated and
> inert** — enabling it produced no scan at all. Scanning is governed by the registry-level
> configuration. Verified by outcome rather than by the setting; had we trusted the switch,
> this section would contain a false claim.

## 5.4 The failure that cost a day

Deployed over plain HTTP, the dashboard rendered a permanent loading skeleton. Infrastructure
was provably healthy throughout: service 1/1, target healthy, `/_stcore/health` returning 200,
static assets served, WebSocket upgrade returning `101 Switching Protocols`, no errors in
CloudWatch or the browser console.

Isolated from the browser's WebSocket frame log: the client sent exactly **one** 104-byte
message — the rerun request — and the server sent nothing back. Server-side debug logging
showed `AppSession initialized` and no script run whatsoever.

**Cause:** an intercepting proxy on the operator's ISP relayed the HTTP Upgrade and the 101
response correctly, then silently discarded every subsequent client frame. Two symptoms, one
cause — the rerun message never arrived, so no script ran; and the keepalive pong never
returned, so uvicorn's 30 s ping plus 30 s timeout produced the observed 60-second reconnect
loop. That timeout logs at TRACE, invisible even with debug logging enabled.

**Confirmed** by loading the same URL over a phone hotspot, which rendered instantly.
**Resolved** by TLS: `wss://` is opaque to the middlebox.

**Consequence for the plan.** The documented fallback — "deploy on the ALB's DNS name over
HTTP" — is therefore unsafe for this application. Its failure mode is a blank page for *some*
viewers and a working page for others, which is worse than a clean failure.

Nothing in the image, the Streamlit configuration, the task definition, the load balancer or
the service was ever wrong. The template already contained the conditional HTTPS listener,
the redirect and the DNS alias; it had simply been deployed with `CertificateArn` empty. The
fix was one parameter, not new infrastructure.

## 5.5 What we deliberately did not build

| Scoped out | Reason |
|---|---|
| Private subnets + NAT Gateway | ~$32/month. The task sits in a public subnet with a public IP so it can reach ECR without NAT; the security group makes it unreachable from the internet regardless. |
| WAF | Cost. The exposure it would cover — brute force against the shared operator token — is named honestly in §8 instead. |
| Horizontal scaling | Blocked by the audit log, see below. |
| EFS for the audit log | An extra security group and an extra failure mode, and `AuditLog.record()` guards with a process-local lock: correct at one task, silently wrong at two. |
| AWS App Runner | Documented WebSocket problems that break Streamlit specifically. |
| Lightsail Containers | Cheaper, but strips out every artefact this section is graded on. |

**Two AZs of load balancer in front of one task is HA-*shaped*, not HA.** Say it before a
reader does.

**The audit log and scaling are one limitation, not two.** The deployed log is a seeded,
read-only artefact baked into the image. Live persistence needs an external append-capable
store — and that same missing store is what blocks running more than one task. One cause,
two consequences.

## 5.6 Cost

| Resource | ~ / month |
|---|---|
| Application Load Balancer | $16.40 |
| Fargate 1 vCPU / 2 GB | $36.00 |
| Secrets Manager, 1 secret | $0.40 |
| ECR storage | $0.14 |
| Route 53 hosted zone | $0.50 |
| **Total** | **≈ $53** |

Domain registration $16/year, separate. Roughly $16 of infrastructure across the project
window. A `$40` monthly budget with alerts at 25/50/80/100% guards it — configured to
**exclude credits and refunds** `[check 2]`, so it measures gross consumption rather than the
net invoice. With credits included it would have read $0 all month and never fired.

## 5.7 What we would do differently at scale

- Private subnets with NAT, or VPC endpoints for ECR/Logs/Secrets Manager
- Authentication at the load balancer (ALB `authenticate-oidc` / Cognito) so an
  unauthenticated request never reaches the container — instead of a shared token checked
  inside the application
- An external audit store, which unblocks horizontal scaling at the same time
- WAF with rate limiting on the sign-in path
- IAM Identity Center instead of a long-lived IAM access key for operators
- Immutable ECR tags, and `--provenance=false` at build so the published image is a single
  directly scannable manifest rather than an OCI index

---

## Appendix B checklist

- [ ] `haris-infra.yaml` — the whole stack, reviewable and diffable
- [ ] `deployment-verification.txt` — all 16 checks
- [ ] `task-definition.json`
- [ ] Execution role policy JSON (console screenshot)
- [ ] Task role permissions tab, empty, **with the caption explaining why**
- [ ] ECS service 1/1 · target group healthy
- [ ] Padlock + `https://haris-monitor.com` · sign-in gate · dashboard
- [ ] CloudWatch log group with real lines
- [ ] ECR repository + registry scanning settings + scan findings
- [ ] Decide once whether account IDs are redacted, and be consistent