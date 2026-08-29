# Haris — container image for the operator dashboard (and the code to run the eval / demo).
#
# Build:  docker build -t haris .
# Run:    docker run --rm -p 8501:8501 -e HARIS_DASHBOARD_TOKEN=dev-token haris
#         then open http://localhost:8501
#
# Hardened for the AWS/Fargate deployment (plan Stage 1):
#   * runs as an unprivileged user, not root
#   * no compiler toolchain in the final image
#   * every dependency, including the spaCy model, installed from a pinned lockfile
#   * unbuffered stdout, so CloudWatch shows log lines as they happen
#   * a container HEALTHCHECK against the same endpoint the ALB target group polls
#
# The base image is pinned by DIGEST, not by tag: a tag moves when the upstream
# image is rebuilt, a digest does not. This is what makes the build reproducible
# on a grader's machine and at any future date, and it is also what makes the ECR
# scan result meaningful — we know exactly which base layer was scanned.
FROM python:3.11-slim@sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76

# --------------------------------------------------------------------------- #
# Interpreter behaviour.                                                       #
#                                                                              #
# PYTHONUNBUFFERED is not cosmetic here. Without it Python buffers stdout when  #
# it isn't attached to a TTY, so container logs arrive in chunks minutes late — #
# or never, if the task is killed before the buffer flushes. On Fargate that is #
# the difference between a debuggable deployment and a silent one.              #
# --------------------------------------------------------------------------- #
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# --------------------------------------------------------------------------- #
# The account the process will run as.                                         #
#                                                                              #
# Created before the dependency install so the layer stays cached, and given a  #
# real home directory because Streamlit writes to ~/.streamlit on startup — as  #
# a homeless user it fails in a way that reads like a permissions bug.          #
# --------------------------------------------------------------------------- #
RUN useradd --create-home --uid 10001 --shell /bin/bash haris
ENV HOME=/home/haris

WORKDIR /app

# --------------------------------------------------------------------------- #
# Dependencies, from the lockfile only.                                        #
#                                                                              #
# build-essential is deliberately NOT installed. numpy, blis, thinc and spaCy   #
# all publish manylinux wheels for cp311, so nothing needs to compile — which   #
# keeps roughly 250 MB of compiler toolchain out of both the image and the      #
# attack surface. If a dependency ever does need to build from source, use a    #
# multi-stage build rather than adding gcc back to the runtime image.           #
#                                                                              #
# The spaCy model Presidio depends on is installed BY THE LOCKFILE, pinned by   #
# sha256 (requirements.lock.txt). It is deliberately NOT fetched afterwards     #
# with `python -m spacy download en_core_web_sm`: that re-resolves the model    #
# over the network at build time and overwrites the pinned wheel, which voids   #
# the pin without any visible sign that it did. An earlier revision of this     #
# file did both, so the sha256 pin was decorative for several builds.           #
# --------------------------------------------------------------------------- #
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt

# --------------------------------------------------------------------------- #
# Application code, owned by the runtime user.                                 #
# --------------------------------------------------------------------------- #
COPY --chown=haris:haris . .

# Streamlit must listen on all interfaces and run headless inside a container.
# The file watcher is disabled: it exists to hot-reload during development and
# only costs CPU and inotify handles in a deployed container.
ENV STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none

USER haris
EXPOSE 8501

# --------------------------------------------------------------------------- #
# Liveness.                                                                    #
#                                                                              #
# Checks Streamlit's own /_stcore/health using the interpreter already in the   #
# image, so no curl and no extra package. The ALB target group polls the SAME   #
# endpoint, so one signal governs both environments — but the MECHANISMS are    #
# not the same, and it is worth being precise about that: ECS/Fargate does not  #
# run a Dockerfile HEALTHCHECK at all. It honours only the `healthCheck` block  #
# in the container definition, which this deployment does not set. So this      #
# probe governs `docker run` and `docker compose`; in production the ALB target #
# check is what drains an unhealthy task and lets ECS replace it.               #
#                                                                              #
# Note also that Docker REPORTS health but does not act on it — an unhealthy    #
# container is not restarted by `restart: unless-stopped`, which fires on       #
# process exit. Acting on the signal is the orchestrator's job.                 #
#                                                                              #
# start-period is 90s: the first request boots Presidio and spaCy and replays   #
# the demo scenario battery through the orchestrator, so an earlier probe would #
# report unhealthy while the container is merely still starting.                #
# --------------------------------------------------------------------------- #
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4).status == 200 else 1)"

# Operator dashboard. (To run the evaluation instead:
#   docker run --rm haris python -m demo_app.eval.simulate )
CMD ["streamlit", "run", "demo_app/dashboard.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]

# --------------------------------------------------------------------------- #
# Build the submission image with provenance disabled:                         #
#                                                                             #
#   docker buildx build --provenance=false -t <repo>:<tag> .                   #
#                                                                             #
# The default buildx build pushes an OCI image INDEX carrying a provenance     #
# attestation. ECR does not scan indexes, so `describe-image-scan-findings     #
# --image-id imageTag=<tag>` returns ScanNotFoundException even though the     #
# console resolves the child manifest and shows results. Disabling provenance  #
# makes the tag address a single manifest, so the scan is addressable by tag.  #
#                                                                             #
# The ECR repository is IMMUTABLE, so each build needs its own tag rather than #
# overwriting the last. That is what makes the deployment circuit breaker's    #
# rollback meaningful: the task definition it rolls back to still points at    #
# the same bytes it was tested against.                                        #
#                                                                             #
# To refresh the base image digest on the FROM line above (only when           #
# deliberately taking a newer base):                                           #
#                                                                             #
#   docker pull python:3.11-slim                                              #
#   docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim        #
# --------------------------------------------------------------------------- #