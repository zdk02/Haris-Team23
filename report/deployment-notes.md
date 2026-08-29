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


---

# Part 2 — 26 to 29 August 2026

**Owner:** Batoul · **Written:** 29 Aug 2026, while the work was fresh
**Status:** notes and evidence pointers, not prose. Source material for §5 and Appendix B.

Part 1 (above) describes the deployment as it stood on 24 August. Between 26 and 29 August
the notification system was completed, the submission image was built and deployed, and the
CloudWatch alarm was tested rather than assumed. Several statements in Part 1 are superseded;
they are listed first rather than edited in place, because *what we believed and when* is
part of the record.

---

## Corrections to Part 1

| Part 1 says | Now |
|---|---|
| "the two Secrets Manager secrets" | **Three.** `HARIS_ALERT_WEBHOOK` added 29 Aug. |
| "**The two secrets.** Both injected at task start" (§5.3) | Three, from `Sid: ReadTheThreeTaskSecretsOnly`. |
| "4 CRITICAL / 8 HIGH / 6 MEDIUM" (§5.3, image scanning) | Those are `v1`'s figures **scanned 23 Aug**. The submission image `v2`, scanned 29 Aug, reports **4 CRITICAL / 15 HIGH / 4 MEDIUM / 2 UNDEFINED**. The two are *not comparable* — see "The CVE comparison trap" below. |
| Appendix B: "Alarm proven to **fire**" unchecked | ✅ done 26 Aug, with measured latencies. |
| Appendix B: "Base image pinned by digest… immutable tag" unchecked | ✅ done 29 Aug. |
| Appendix B: "Re-run `verify-deployment.ps1`" unchecked | ✅ done 29 Aug — six assertions became nine. |
| Appendix B: "Decide once whether account IDs are redacted" unchecked | ✅ decided — see "Recorded decisions". |
| §5.7 wish-list: "Immutable ECR tags, and the task definition pinned to an image **digest**" | ✅ **shipped**, not future work. Remove from §5.7. |

---

## 5.1b The notification path, end to end in production

Nine notification items landed on 26 August. Three are worth §5 or §4.4 space because they
were **deployment** defects, not library defects — properties true of the test suite and
false of the running container.

**The deployed entry point had no operational log.** `configure_logging()` was called only
from `haris_pipeline.main()`. The ECS task runs `streamlit run demo_app/dashboard.py`, which
never reached it, so audit checkpoints, notifier events and health errors were emitted at
INFO to a logger with no handler and dropped. This mattered beyond tidiness: §4.3's
truncation defence works by emitting the `(head, count)` checkpoint to that stream, so the
external anchor the threat model relies on did not exist in production. Fixed by calling
`configure_logging()` from `dashboard.main()` behind `@st.cache_resource`, so it runs once
per server process. On Fargate the handler writes to stderr, which the `awslogs` driver
ships to `/ecs/haris`.

**The deployed path had no out-of-band channel.** `WebhookChannel(min_severity=WARNING)` was
set in `haris_pipeline.run_secured()` — a function the container never calls.
`dashboard_data.get_dashboard()` built `Notifier(channels=[incidents_buffer])`: one in-memory
buffer feeding the banner, and no route out of the process at all. A blocked leak reached the
screen and nothing else, whatever `HARIS_ALERT_WEBHOOK` was set to.

Both are the same species as the defects the 24 August wiring audit found: **a property that
is true of a component, documented as true of the system, and never checked at the seam.**
Both are now held by tests in `tests/test_shipped_pipeline_wiring.py` that assert the
*connections*, and both were sabotage-verified — cut the wire, the test goes red.

**Alerts now leave the container.** CloudWatch, 29 Aug 08:59, task `2aeb8297…`:

```
haris.ops | WARNING | haris.notify | WARNING · security · orchestrator:
  Haris blocked a summary flow summarizer -> emailer (session s-tc2) [ref 731ff7fe9003]
  ... (session s-tc3) [ref 941f382e5167]
  ... (session s-tc4) [ref c8ab44ac4e83]
```

Three distinct alerts for three sessions — which is also the per-session de-duplication key
(task R1) working in production. Under the previous key, `(category, source, summary)`, two
of these would have collapsed into one and an incident would have been silently deleted.

---

## 5.2b The submission image

Built 29 Aug, tag `v2`.

| | |
|---|---|
| base | `python:3.11-slim@sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76` |
| image digest | `sha256:39debb061fea785a44d2069db73ce4f3c84235a16aa25f39c7334135487c4100` |
| manifest type | `application/vnd.oci.image.manifest.v1+json` — a **manifest**, not an index |
| size in ECR | 296.32 MB |
| repository | `IMMUTABLE`, scan-on-push enabled |
| referenced by | **digest** in task definition revision 7, not by tag |

**Three properties, one build sequence.**

*Pinned by digest.* A tag moves when the upstream image is rebuilt; a digest does not. This
is also what makes the scan meaningful — a scan of an image built from a moving tag describes
bytes nobody can reconstruct.

*Built with `--provenance=false`.* The default `buildx` export pushes an OCI image **index**
carrying a provenance attestation, and ECR cannot scan an index by tag:
`describe-image-scan-findings --image-id imageTag=<tag>` returns `ScanNotFoundException` even
though the console resolves the child manifest and shows results. `v1` has that shape, which
is why `verify-deployment.ps1` §6b carries a fallback that resolves the child manifest
explicitly. `v2` does not: scan-by-tag now returns counts directly. **This is the cleanest
proof the flag did its job** — the same call that failed on `v1` succeeds on `v2`.

*Immutable repository + digest reference.* Together these make the deployment circuit
breaker's rollback meaningful: it returns to bytes that were tested rather than to whatever a
name currently resolves to.

**Build timings (cold — the base digest changed, so nothing was cached):**

| | |
|---|---|
| `pip install` from lockfile | 603.3 s |
| layer export | 29.5 s |
| layer push | 279.2 s |
| **total** | **914.3 s (15 m 14 s)** |

Part 1 records 6 m 13 s + 4 m 59 s for `v1`. That was a warm build on an unchanged base; the
figures are not comparable, and the honest label for 914 s is **cold build time**.

**The image runs its own test suite.**

```
docker run --rm <image> python -m pytest tests/ -q
  → 463 passed, 0 skipped, 41.10 s
```

A development machine reports **457 passed** for the same suite, because Presidio, spaCy and
langgraph are absent there and those tests skip. The image is the only environment in which
the full suite runs, which makes it — not the developer machine — the reference environment.
Worth one sentence in §5: *the artefact validates itself.*

**One accidental hardening property worth claiming deliberately.** `WORKDIR /app` creates the
directory as root and `COPY --chown=haris:haris` changes ownership only of the copied files,
so `/app` itself stays root-owned. The runtime user therefore cannot write into its own code
tree: a compromised process cannot modify the application it is running. The visible symptom
is pytest warning that it cannot create `.pytest_cache` when the suite runs in-container.

### The CVE comparison trap — do not quote a delta without reading this

| image | CRITICAL | HIGH | MEDIUM | UNDEFINED | scanned |
|---|---|---|---|---|---|
| `v1` | 4 | 8 | 6 | — | **23 Aug** |
| `v2` | 4 | 15 | 4 | 2 | **29 Aug** |

`v2` looks worse. **It may not be.** ECR **BASIC** scanning does not re-scan automatically
(that is Enhanced / Inspector), so `v1`'s findings are frozen against the CVE database as it
stood on 23 August and `v2`'s are against 29 August. `describe-image-scan-findings` on `v1`
returns `vulnerabilitySourceUpdatedAt: 2026-08-23`, confirming this. Comparing them compares
two databases, not two images.

**Before quoting anything in §5**, force a same-day re-scan of `v1` and compare like with
like:

```powershell
aws ecr start-image-scan --repository-name haris `
  --image-id imageDigest=sha256:a196015c84a816c18f657bdba6faec50255b91d05281a2666e171de9fd11ab40 ...
```

(BASIC allows one manual scan per image per 24 h.) Then check whether the four criticals are
the *same* four — `v1`'s were `CVE-2026-5450` (glibc) and three in perl.

**The defensible framing regardless of the outcome:** pinning the base by digest buys
**reproducibility, not fewer vulnerabilities**. And BASIC scanning reads the distribution
manifest only — it does not read `requirements.lock.txt`, so Python dependencies are
**unscanned**. "No findings in application dependencies" would be a statement about the
scanner, not about the image.

---

## 5.3b Secret handling — three secrets, and an incident worth telling

Three values reach the container, all resolved from Secrets Manager by the execution role at
task start. The task definition's `environment` list is empty.

| variable | secret | protects |
|---|---|---|
| `HARIS_DASHBOARD_TOKEN` | `haris/dashboard-token-hmBUtX` | who may **read** the audit log |
| `HARIS_AUDIT_KEY` | `haris/audit-key-q2TDDb` | whether the log can be silently **rewritten** |
| `HARIS_ALERT_WEBHOOK` | `haris/alert-webhook-43q0rX` | where runtime alerts are pushed |

The IAM statement enumerates all three ARNs and is renamed `ReadTheThreeTaskSecretsOnly` —
the `Sid` had said "Two", and a `Sid` that misdescribes its own statement is the kind of
detail this project has spent two weeks removing.

A webhook URL is a **bearer credential**: anyone holding it can post to the channel. That is
why it is a secret rather than an environment variable, and why the one pasted during setup
was rotated.

### The placeholder incident, 29 August

`haris/alert-webhook` was first created holding the literal placeholder text from the setup
instructions rather than a URL. The deployed Notifier reported it on every blocked flow:

```
haris.ops | ERROR | haris.notify | notify: channel 'webhook' failed to send
  (ValueError: unknown url type: 'your NEW Discord webhook URL')
```

Correcting the secret value changed nothing until `update-service --force-new-deployment`
replaced the task — **exactly as the template's own comment warns**: *"secrets are read ONCE
at task start; rotating a value in Secrets Manager does not reach a running container."*

This is worth stating in §5 rather than hiding, because one misconfiguration exercised four
claimed properties at once:

1. **The alerting diagnosed its own misconfiguration**, in one line, without an operator
   noticing anything.
2. **A broken channel did not become an outage.** Three security alerts were still raised,
   the replay completed, the site stayed up — the robustness guarantee in `notifier.py`'s
   docstring, demonstrated in production rather than in a test.
3. **`counts["failed"]` vs `counts["skipped"]` earned their keep.** `failed` means a channel
   tried and could not; `skipped` means a channel is present but unconfigured. The
   distinction turned a five-minute diagnosis into a five-second one.
4. **The operational log reached CloudWatch** — which was only true because of the R4 fix
   above. Without it this failure would have been silent.

---

## 5.6b The alarm, proven to fire

Tested 26 August by scaling the service to `desired-count 0`. Before this, the alarm had sat
in `OK` since it was created on 24 August and had never changed state — i.e. it was
configuration, not a control.

| | local | UTC | elapsed |
|---|---|---|---|
| `desired-count 0` | 19:02:20 | 16:02 | — |
| **→ ALARM** | 19:12:50 | 16:12:41 | **10.5 min** |
| `desired-count 1` | 19:15:15 | 16:15 | — |
| **→ OK** | 19:19:47 | 16:19:41 | **4.5 min** |

During the outage: `runningCount 0, desiredCount 0`, and `https://haris-monitor.com` returned
**503** — the ALB answering with no healthy target. After recovery: target `healthy`, apex and
`www` both **200**.

**The line to quote in §5** is from the ALARM notification, because it is AWS stating the
design decision under test:

> "Threshold Crossed: **no datapoints were received for 3 periods and 3 missing datapoints
> were treated as [Breaching]**." — 26 August 2026, 16:12:41 UTC

That is `TreatMissingData: breaching` doing its job. An emptied target group stops publishing
`HealthyHostCount` altogether, so an alarm on `UnHealthyHostCount` would have read 0 and
stayed silent through the entire outage it exists to catch.

The recovery notification carries the mirror statement:

> "Threshold Crossed: 1 datapoint [1.0 (26/08/26 16:16:00)] was not less than the threshold
> (1.0) and 2 missing datapoints were treated as [Breaching]." — 16:19:41 UTC

**Two honest observations for §5:**

*Detection is slower than the configuration implies.* The alarm's arithmetic is 3 × 60 s, but
measured latency is **ten and a half minutes**, dominated by ALB metric publication delay and
by the time CloudWatch takes to conclude that datapoints are missing rather than late.
Tightening `EvaluationPeriods` would save about one minute of ten.

*Recovery is signalled faster than failure* — 4.5 min versus 10.5. Returning to `OK` needs
only one real datapoint to arrive; reaching `ALARM` requires concluding that data is absent.
For an alerting system that is the wrong way round. State it as a limitation rather than
quoting the nominal three minutes.

**Timings cross-check across three independent sources** — the polling transcript, the two
SNS emails, and the console graph — agreeing to within one 20-second poll interval.

---

## Production observations, 29 August

From `/ecs/haris` after the `v2` deploy, on the live task:

**Latency.** 425.36 ms on the first hop of the first request (Presidio and spaCy load lazily),
then **7–26 ms per hop** steady state. Consistent with the Presidio-on figures in §6.5
measured off-platform. Reported per hop with `latency` and `total` separately, the second
including the audit write.

**All four enforcement actions observed live**, not just in tests: `flag`, `allow`, `block`,
`redact` — including `action=redact` on `summarizer -> emailer`, which confirms task S2 on the
deployed system rather than only in the local battery.

**What the deployed site actually is.** The dashboard re-runs the recorded scenario battery
in-process on each load and renders Haris's decisions from the resulting audit log. It is
**not** monitoring live traffic. The topbar says `replay · <timestamp>` for that reason. §5
must say this in words; a reader who works it out mid-demo will feel misled, and the honest
version costs nothing.

---

## Verification — nine assertions

`verify-deployment.ps1` re-run 29 Aug: **9 PASS, 0 FAIL**.

```
PASS  account is 007267918845
PASS  deployment circuit breaker enabled
PASS  target group stickiness enabled
PASS  all three task secrets injected
PASS  image pinned by digest, not tag
PASS  ECR repository is immutable
PASS  scanned tag 'v2' is the deployed image
PASS  apex and www A records both present
PASS  https://www.haris-monitor.com responds 200
```

The script itself was updated first, because re-running it unchanged would have produced six
fresh PASS lines that **check none of this week's work** — the old summary asserted only
`HARIS_AUDIT_KEY`, which passes on a two-secret, tag-addressed task. A green transcript that
proves less than it appears to is worse than a stale one.

Changes: §13 heading, comment and query (all three secrets; prints `Revision` and `Image`);
§5 comment on why `IMMUTABLE` matters; §6b defaults to `v2`, records scan and CVE-source
timestamps, prints `scanned:` beside `deployed:`, and notes the database-drift trap; SUMMARY
six checks → nine; header shows a UTF-8 capture instead of `Tee-Object`.

The assertion worth pointing a grader at is **"scanned tag 'v2' is the deployed image"** — it
closes the gap between *we scanned an image* and *we scanned **this** image*.

**Deploy timing.** `update-stack` → `stack-update-complete`: 11:36:27 → 11:41:15 = **4 m 48 s**,
with the site serving throughout (ECS keeps the old task until the new one is healthy).

---

## Recorded decisions

**Account identifiers are NOT redacted.** They are identifiers, not credentials: no secret
value, access key or webhook URL appears anywhere in the repository (verified across the full
commit history). Further, `teardown.ps1`'s account guard defaults `$AccountId` to the literal
account and refuses to run unless `sts:GetCallerIdentity` returns it — redacting would either
break that guard or make it depend on an operator typing the right value under pressure, so
redaction would *degrade a security control* to hide a non-secret. Verification transcripts
are also more useful to a reader intact than blurred. **Paragraph for §5:**

> AWS account and resource identifiers appear unredacted throughout this report and its
> appendices. They are identifiers, not credentials: no secret value, access key or webhook
> URL appears anywhere in the repository, and the `teardown.ps1` account guard depends on the
> literal account ID to refuse a destructive command against the wrong account. Verification
> transcripts are more useful to a reader intact than blurred.

**`SESChannel` exists but the deployed instance does not use it.** Wiring it in would require
granting the task role `ses:SendEmail`, and the empty task role is worth more than a duplicate
alerting path — particularly since the path that matters most, reporting that Haris is *not
running*, cannot come from inside the container at all. boto3 is imported lazily and is
deliberately absent from `requirements.lock.txt` and the image.

**Two cuts, both recorded in `SCOPE_FREEZE.md`.** The persisted audit log: a build-time-seeded
log would need `HARIS_AUDIT_KEY` at `docker build`, putting the audit key in an image layer and
undoing the Secrets Manager wiring — and a Fargate container filesystem is ephemeral, so the
feature as specified never delivered durability. The `POST /v1/inspect` service: its
justification was "you need `/health` for the target group anyway", and the target group polls
Streamlit's own `/_stcore/health` and is healthy, so the justification expired.

---

## Every measured number, in one place

| quantity | value | source |
|---|---|---|
| Cold build (base changed) | 914.3 s — pip 603.3 s, push 279.2 s | build log, 29 Aug |
| Image size in ECR | 296.32 MB | `describe-images` |
| Tests inside the image | **463 passed, 0 skipped**, 41.10 s | `docker run … pytest` |
| Tests on a dev machine | 457 passed (Presidio/spaCy/langgraph absent) | local |
| Stack update duration | 4 m 48 s, no downtime | 11:36:27 → 11:41:15 |
| Outage → ALARM | **10.5 min** | polling log + SNS email |
| Restore → OK | **4.5 min** | polling log + SNS email |
| Status during outage | 503, `runningCount 0` | alarm test |
| First-hop latency (cold) | 425.36 ms | `/ecs/haris`, 29 Aug |
| Steady-state latency | 7–26 ms per hop | `/ecs/haris`, 29 Aug |
| CVE `v2` (29 Aug scan) | 4 CRITICAL / 15 HIGH / 4 MEDIUM / 2 UNDEFINED | ECR BASIC |
| CVE `v1` (23 Aug scan) | 4 / 8 / 6 — **not comparable, different DB** | ECR BASIC |
| Verification assertions | 9 PASS, 0 FAIL | `verify-deployment.ps1` |
| CloudFormation resources | 27, all COMPLETE | `describe-stack-resources` |
| Task definition | revision 7 | `describe-services` |
| Notifier, fully configured demo | emitted 3, suppressed 1, delivered 8, failed 0, skipped 0 | `notify_demo` |

---

## Evidence index — what proves what

| claim | artefact |
|---|---|
| All 17 checks + 9 assertions | `report/appendix/deployment-verification.txt` |
| Three secrets, digest image, empty env | `report/appendix/task-definition.json` (revision 7) |
| Alarm fires and clears, with timings | `report/appendix/alarm-test.txt` |
| CloudWatch's own words on missing data | `report/figures/alarm-fired-email.png` |
| `OKActions` works | `report/figures/alarm-recovered-email.png` |
| Outage visible on the metric | `report/figures/alarm-graph-fired.png` |
| One `notify()` → three mechanisms | `report/figures/alert-discord.png`, `alert-ses-inbox.png` |
| HSTS, stickiness cookie, TLS | `report/appendix/response-headers.txt` |
| Scoped IAM | `[check 11]`; empty task role `[check 12]` |
| Live site, sign-in gate, dashboard | `report/figures/haris-dashboard 1–3.png` |
| The whole stack, diffable | `haris-infra.yaml` |

---

## Updated Appendix B checklist

- [x] `haris-infra.yaml` — the whole stack, reviewable and diffable
- [x] `deployment-verification.txt` — 17 checks + **nine** PASS assertions
- [x] `task-definition.json` — **revision 7**, three secrets, digest-pinned image
- [x] `response-headers.txt` — HSTS and the stickiness cookie, live
- [x] Execution role policy JSON — printed in full at `[check 11]`
- [x] Task role permissions, empty `[check 12]`, **with the caption explaining why**
- [x] ECS service 1/1 `[check 8]` · target group healthy `[check 9]`
- [x] Padlock + `https://haris-monitor.com` · sign-in gate · dashboard *(figures/)*
- [x] CloudWatch log group with real lines `[check 14]`
- [x] ECR repository + registry scanning settings + scan findings `[checks 5, 6, 6b]`
- [x] CloudWatch alarm in OK state · SNS subscription Confirmed *(figures/)*
- [x] `teardown.ps1` guard aborting against a wrong account ID
- [x] **Alarm proven to fire** — ALARM and OK notifications, alarm-state graph, transcript
- [x] **Base image pinned by digest**, built `--provenance=false`, immutable repository
- [x] **Re-ran `verify-deployment.ps1`** after the submission build — nine assertions
- [x] **Account-ID redaction decided** — not redacted, reasoning above
- [ ] `docker-compose.yml` referenced from Appendix B
- [ ] Same-day re-scan of `v1` before quoting any CVE comparison

---

## Still open

- **Same-day `v1` re-scan** before §5 quotes any before/after CVE figure. One command, 40 s.
- **Budget mismatch.** The AWS Budget is set to **$40/month** against a corrected run rate of
  **~$65/month**. Two of our own artefacts disagree. Either raise it to $80 or state that $40
  is deliberately below run-rate so the alarm fires early — but decide, and say which.
- **No application-level health surface in production.** `audit_chain_probe`,
  `state_store_probe` and `agents_present_probe` are registered only inside
  `run_secured()`, which the dashboard never calls — so no probe runs in the deployed
  container, while the banner renders "✓ All systems healthy". If the Incidents & Health page
  (task S3/D1) does not ship, §5 must say this plainly.
- **`NOTIFICATIONS.md`** — accurate as written, but it documents the *pre-26-August* Notifier:
  no `dedup_key`, no eviction or rollup, no `delivered`/`failed`/`skipped` counters, no SES
  channel. Update before submission or it becomes a doc that describes code we replaced.
- **`alarm-test.txt` encoding** — still UTF-8 **with** BOM; the other two appendix files were
  normalised on 29 Aug. Rewrite for consistency.
- **`report/figures/cloudwatch alarm.png`** is the 24 August OK-state graph. Superseded by
  `alarm-graph-fired.png`; keep only if captioned as the steady state.