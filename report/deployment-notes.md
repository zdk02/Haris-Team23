# §5 Deployment — working notes

**Owner:** Batoul · **Written:** 23 Aug 2026, while the work was fresh (task J8)
**Revised:** 24 Aug 2026 — keyed audit chain, `www`, resilience settings, HSTS,
out-of-process alerting; three overstated claims corrected (marked ⚠ below).
**Status:** notes and evidence pointers, not prose. Turn into §5 on Fri 28.

Every claim below has evidence. `[check N]` refers to a numbered section of
`report/appendix/deployment-verification.txt`, produced by `verify-deployment.ps1`.

---

## 5.1 What was built

One Fargate task behind an internet-facing ALB across two availability zones, fronted by
Route 53 and TLS, defined entirely in one CloudFormation template.

```
Internet → Route 53 (haris-monitor.com + www, A/alias)
         → ALB  :443 HTTPS (ACM cert, TLS 1.3 policy, HSTS) · :80 → 301 → :443
         → Target group :8501, health check /_stcore/health, lb_cookie stickiness
         → Fargate task ×1 (1 vCPU / 2 GB), image from ECR
         → CloudWatch Logs (14-day retention)

CloudWatch alarm (HealthyHostCount < 1) → SNS → email     [outside the container]
```

27 resources, one `aws cloudformation deploy`. Template is Appendix B. `[check 7]`

**Service behaviour, set explicitly rather than inherited:**

- **Deployment circuit breaker with rollback** `[check 8]`. Without it a bad image is
  retried indefinitely — the "loop forever with no useful error" failure the health-check
  grace period already anticipates. With it, ECS returns to the last task definition that
  reached a healthy target.
- **`lb_cookie` stickiness on the target group** `[check 9]`. At `DesiredCount: 1` this
  changes nothing, but ECS runs two tasks briefly during every rolling deploy, and
  Streamlit holds session state server-side behind a WebSocket — a client reconnecting in
  that window would otherwise land on the other task and lose its session. Visible in the
  live response as `Set-Cookie: AWSALB=…` (`report/appendix/response-headers.txt`).
- **`idle_timeout: 300s`** on the ALB `[check 10]`. The 60 s default drops a dashboard left
  open while someone talks over it.
- **`HealthCheckGracePeriodSeconds: 180`.** Fargate caches nothing between task starts, so
  every replacement pays a full ~281 MiB image pull before Python begins.

**Deliberately not in the stack:** the ECR repository and the two Secrets Manager secrets
(operator token, audit-chain key). They hold state that should outlive the stack, so
`delete-stack` cannot destroy the image or either secret. The three commands that created
them are recorded as a comment block in `haris-infra.yaml`, so the deployment is
reproducible from that file plus those three lines.

**Teardown is scripted** (`teardown.ps1`) and refuses to run unless
`sts:GetCallerIdentity` returns the deployment account. This is not defensive programming
for its own sake: `delete-stack` against the wrong account fails with *"stack does not
exist"*, a message indistinguishable from success. During development the workstation's
default CLI profile authenticated to a different account, and `list-stacks` returned an
empty result we initially read as a failed deployment. The guard checks which account was
**reached**, not which credentials were **requested** — only the first is safe to delete
on. Verified by running it against a deliberately wrong account ID and observing it abort.

## 5.2 The reproducible artefact

- Base `python:3.11-slim`; **pin by digest before the submission build** *(still open)*
- **No compiler in the image.** `build-essential` removed — numpy/blis/thinc/spaCy all
  publish cp311 manylinux wheels. ~250 MB and a whole toolchain off the attack surface
- **Runs as uid 10001**, not root. Proven with `whoami` / `id`, not asserted
- **Everything installed from `requirements.lock.txt`**, which pins the spaCy model wheel
  by **SHA-256**, not merely by version. `requirements.txt` documents intent; the lockfile
  pins reality
- Language model baked at **build** time, so a task start never depends on reaching a
  model host over the network
- Container `HEALTHCHECK` and the ALB target group poll the **same endpoint**
  (`/_stcore/health`), so one signal governs both environments

> ⚠ **Two corrections we found in our own artefact.**
>
> **The SHA-256 pin was decorative for several builds.** The Dockerfile installed the
> lockfile *and then* ran `python -m spacy download en_core_web_sm`, which re-resolves the
> model over the network and overwrites the pinned wheel — voiding the pin with no visible
> sign that it had. The download line is removed; the claim above is true of the submission
> build, not of every build that preceded it.
>
> **The health check is not identical across environments.** ECS/Fargate does **not** run a
> Dockerfile `HEALTHCHECK` at all — it honours only the `healthCheck` block in the container
> definition, which this deployment does not set. The endpoint is shared; the mechanism is
> not. Locally, Compose surfaces healthy/unhealthy; in production the ALB drains the target
> and ECS replaces the task. (Docker in any case *reports* health without acting on it —
> `restart: unless-stopped` fires on process exit, and a Streamlit whose socket has stopped
> answering has not exited.)

| Measurement | Value |
|---|---|
| Build time | 6m13s |
| Image, uncompressed on disk | 1.32 GB |
| **Image, compressed in ECR — what Fargate actually pulls** | **281 MB** |
| Push to ECR | 4m59s |
| Peak working set, all pages exercised, Presidio loaded | 198 MB |
| First render after sign-in (local) | ~2 s |
| Container healthcheck passes at | ~56 s |

Measured against commit `18d41ef`. Quote the **compressed** figure as the headline: it is
what governs pull time and task-start latency, and it is the number the ECR API proves
`[check 5]`. The 1.32 GB on-disk size invites a criticism the deployed system does not
actually suffer from.

**Sizing rationale:** 1 vCPU / 2048 MB against a 198 MB working set is a deliberate ~10×
margin. A Fargate OOM kill surfaces as an unexplained task restart loop, not a diagnosable
error, so the headroom buys diagnosability rather than performance.

## 5.3 Security boundaries — the part that carries the section

**Network.** The task's security group admits port 8501 **from the load balancer's security
group**, not from a CIDR range. There is no address anyone can route from to reach the
container. `[check 17]` — exactly one inbound rule, `FromGroup` set, `FromCidr: null`.

**Identity — and a correction worth stating.** The original plan put CloudWatch logging on
the *task* role. That is wrong: the `awslogs` driver is executed by the ECS agent, so it
authenticates with the **execution** role. Built as originally planned, the log group would
have stayed empty.

- **Execution role** `[check 11]`: ECR pull scoped to `repository/haris`; `CreateLogStream`
  + `PutLogEvents` scoped to `log-group:/ecs/haris:*`; `GetSecretValue` scoped to **two
  enumerated secret ARNs** — not a prefix, not a wildcard. One action —
  `ecr:GetAuthorizationToken` — sits on `Resource: "*"` because the ECR authorization token
  is account-wide by design and **cannot** be resource-scoped; the statement is named
  `EcrAuthTokenCannotBeScoped` so a reader knows it was a finding, not a shortcut.
  No AWS-managed policy is attached anywhere: `AmazonECSTaskExecutionRolePolicy` would have
  granted ECR and Logs on `Resource: "*"`, so the hand-written policy is strictly tighter
  than the standard one.
- **Task role** `[check 12]`: **no policies at all.** The dashboard makes no AWS API calls,
  so the container's own credentials can invoke nothing. The empty list is the result, not
  an omission.

**The two secrets.** Both injected at task start from Secrets Manager via the execution
role `[check 13]`. They answer different questions and neither substitutes for the other:

| | question | property |
|---|---|---|
| `HARIS_DASHBOARD_TOKEN` | who may **read** the audit log? | authentication |
| `HARIS_AUDIT_KEY` | can the log be silently **rewritten**? | integrity |

Without the second, `AuditLog`'s hash chain degrades to a plain SHA-256 chain: anyone able
to write the log can also recompute it, so the chain is *corruption-evident* but not
*tamper-evident* — which is weaker than `THREAT_MODEL.md` §2 claims. It was missing from
the task definition until 24 Aug; the deployed instance ran the unkeyed variant until then.
The key is held in Secrets Manager, never beside the log it protects.

Be precise about the exposure: a secret *does* become an environment variable inside the
container. What is true is that neither value appears in version control, in the image, in
`describe-task-definition` output `[check 13]`, or in CI logs. SSM Parameter Store
`SecureString` was considered — functionally identical for ECS and free — and Secrets
Manager chosen for rotation support.

Note an operational property of the design: **secrets are read once, at task start.**
Rotating a value in Secrets Manager does not reach a running container; that needs a new
task (`ecs update-service --force-new-deployment`, or any task-definition change).

**TLS.** ACM certificate for apex + wildcard, DNS-validated `[check 4]`. Policy
`ELBSecurityPolicy-TLS13-1-2-2021-06`; `:80` returns 301 `[checks 10, 16]`. **The private key
is generated inside ACM, is never exported, never enters version control, and is never
handled by an operator.** Renewal is automatic via the validation record retained in the
hosted zone. **HSTS** (`max-age=31536000; includeSubDomains`) is set as a load-balancer
listener attribute, so after one visit a browser will not attempt `http://` again — which
matters here for the reason §5.4 describes.

Both `haris-monitor.com` and `www.haris-monitor.com` resolve `[checks 15, 16]`. The
certificate covers `*.haris-monitor.com`, so a name it advertises must answer; a wildcard
certificate over a hostname with no record reads as a broken deployment.

**Image scanning.** Basic scanning, scan-on-push, wildcard filter `[check 6]`. 4 CRITICAL /
8 HIGH / 6 MEDIUM `[check 6b]` — CVE-2026-5450 (glibc) and three in perl, all Debian base
packages, **none in application dependencies**. Accepted: eliminating them means a
distroless or Alpine base, and the spaCy/Presidio chain expects glibc.

State the boundary of that evidence: **BASIC scanning reads the distribution package
manifest only.** It does not read `requirements.lock.txt`, so our Python dependencies are
**unscanned**. Language-level scanning requires Enhanced scanning via Amazon Inspector,
scoped out on cost. The lockfile constrains dependency drift; it is not a vulnerability
scan and we do not present it as one.

> **Two findings worth reporting, both found by outcome rather than by setting.**
>
> The per-repository "Scan on push" toggle is **deprecated and inert** — enabling it
> produced no scan at all. Scanning is governed by the registry-level configuration.
>
> The scan is also **not addressable by tag**. `buildx` pushes an OCI image *index* carrying
> a provenance attestation, so `haris:v1` names the index rather than a manifest, and ECR
> does not scan indexes: `describe-image-scan-findings --image-id imageTag=v1` returns
> `ScanNotFoundException` while the console resolves the child manifest silently and shows
> results. The figures above are addressed by digest. The submission build uses
> `--provenance=false`, after which the tag addresses a single scannable manifest.
>
> Had we trusted either surface, this section would contain a false claim.

**Alerting, and why there are two layers.** Haris has its own `Notifier`, which reports what
Haris *observes* — a crashed detector, a blocked leak, a failed health probe. It runs
in-process, and it structurally **cannot** report that Haris is not running: the code that
would send the message is the code that stopped. A crash-loop produces zero notifications
from inside the container, indefinitely. A CloudWatch alarm on the target group's
`HealthyHostCount` covers exactly that case, from outside the container, over SNS to email —
a path that shares no failure mode with the application. **In-process alerting handles the
application's failures; out-of-process alerting handles the application's absence.**

The metric is `HealthyHostCount < 1`, not `UnHealthyHostCount ≥ 1`: a task that dies
completely is *deregistered* from the target group, so the unhealthy count reads 0 and an
alarm on it would stay silent through the total outage it exists to catch.

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
**Resolved** by TLS: `wss://` is opaque to the middlebox. And having established that a
plaintext path is actively harmful for this application, we then set HSTS so a browser that
has visited once will not attempt `http://` again.

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
| Private subnets + NAT Gateway | ~$32/month. The task sits in a public subnet with a public IP so it can reach ECR without NAT; the security group makes it unreachable from the internet regardless. VPC interface endpoints, the no-NAT alternative, cost ~$7.20/month each × 4 — *more* than NAT at this scale. The cost-correct answer here is neither. |
| WAF | Cost. The exposure it would cover — brute force against the shared operator token — is named honestly in §8 instead. |
| ALB `authenticate-oidc` / Cognito | The architecturally correct answer, and free at this scale — but a half-day of hosted-UI, callback and listener-rule configuration whose failure mode is a redirect loop on the only demo URL, one week from submission. Recommended in §5.7, not attempted. |
| Horizontal scaling | Blocked by the audit log, see below. |
| EFS for the audit log | An extra security group and an extra failure mode, and `AuditLog.record()` guards with a process-local lock: correct at one task, silently wrong at two. |
| AWS App Runner | Documented WebSocket problems that break Streamlit specifically. |
| Lightsail Containers | Cheaper, but strips out every artefact this section is graded on. |
| Container Insights | Bills per metric and adds nothing at one task. Recorded as an explicit decision rather than left as silence. |

**Two AZs of load balancer in front of one task is HA-*shaped*, not HA.** Say it before a
reader does. (An AZ failure is survived — ECS replaces the task in the other subnet — but as
a ~2–3 minute outage, not transparently.)

> ⚠ **Correction.** An earlier draft of this section described the deployed audit log as "a
> seeded, read-only artefact baked into the image." **No such artefact exists.** Runbook
> Stage 6 was never built and was subsequently cut.

**The audit log and scaling are one limitation, not two.** The deployed dashboard replays a
fixed scenario battery in-process on each request; nothing is persisted between requests and
no audit file exists in the running container. `AuditLog` is restart-safe, thread-safe and
keyed, and `load_jsonl()` is implemented and tested — but nothing in the deployed path calls
it. Live persistence needs an external append-capable store, and that same missing store is
what blocks running more than one task, because `record()` guards with a process-local lock.
One cause, two consequences.

## 5.6 Cost

| Resource | ~ / month |
|---|---|
| Application Load Balancer | $16.40 |
| Fargate 1 vCPU / 2 GB | $36.00 |
| Public IPv4 × 3 (2 ALB ENIs + 1 task) | $10.95 |
| Secrets Manager, 2 secrets | $0.80 |
| Route 53 hosted zone | $0.50 |
| ECR storage | $0.14 |
| SNS + 1 CloudWatch alarm | free tier |
| **Total** | **≈ $65** |

> The IPv4 line is easy to miss, and our first table missed it: since February 2024 every
> public IPv4 address bills at $0.005/hour whether or not it carries traffic, and an ALB
> holds one ENI per availability zone. Against a `$40` budget a $65 run rate means the 100%
> alert fires around day 19 by construction — the budget doing its job, not a
> misconfiguration.

Domain registration $16/year, separate; auto-renew is **off** `[check 3]`, so it lapses
rather than surprising us. The budget is configured to **exclude credits and refunds**
`[check 2]`, so it measures gross consumption rather than the net invoice — with credits
included it would have read $0 all month and never fired.

## 5.7 What we would do differently at scale

- Private subnets with NAT, or VPC endpoints for ECR/Logs/Secrets Manager
- Authentication at the load balancer (ALB `authenticate-oidc` / Cognito) so an
  unauthenticated request never reaches the container — instead of a shared token checked
  inside the application
- An external audit store, which unblocks horizontal scaling at the same time
- WAF with rate limiting on the sign-in path
- IAM Identity Center instead of a long-lived IAM access key for operators
- Immutable ECR tags, and the task definition pinned to an image **digest** rather than a
  mutable tag, so a re-push cannot silently change what is running
- `aws:SourceAccount` / `aws:SourceArn` conditions on both roles' trust policies — the
  confused-deputy hardening AWS recommends for `ecs-tasks.amazonaws.com`. Same-account only
  here, so low risk, but it is a named best practice
- Explicit `SecurityGroupEgress` on both groups. Neither declares one, so CloudFormation
  applies allow-all: a PHI-processing container can currently reach any internet host
- Unify the two alerting paths — an `SNSChannel` behind the existing `Channel` interface, or
  a Lambda relaying SNS into the existing webhook, so infrastructure and application alerts
  arrive in one place

---

## Appendix B checklist

- [x] `haris-infra.yaml` — the whole stack, reviewable and diffable
- [x] `deployment-verification.txt` — all 17 checks, plus the PASS/FAIL summary
- [x] `task-definition.json`
- [x] `response-headers.txt` — HSTS and the stickiness cookie, live
- [x] Execution role policy JSON — printed in full at `[check 11]`
- [x] Task role permissions, empty `[check 12]`, **with the caption explaining why**
- [x] ECS service 1/1 `[check 8]` · target group healthy `[check 9]`
- [x] Padlock + `https://haris-monitor.com` · sign-in gate · dashboard *(figures/)*
- [x] CloudWatch log group with real lines `[check 14]`
- [x] ECR repository + registry scanning settings + scan findings `[checks 5, 6, 6b]`
- [x] CloudWatch alarm in OK state · SNS subscription Confirmed *(figures/)*
- [x] `teardown.ps1` guard aborting against a wrong account ID
- [ ] Alarm proven to **fire** — take the service to `desired-count 0`, capture the email
- [ ] Base image pinned by digest, rebuilt `--provenance=false`, pushed as an immutable tag
- [ ] Re-run `verify-deployment.ps1` after the submission build
- [ ] Decide once whether account IDs are redacted, and be consistent