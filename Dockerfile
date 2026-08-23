# Haris — container image for the operator dashboard (and the code to run the eval / demo).
#
# Build:  docker build -t haris .
# Run:    docker run --rm -p 8501:8501 -e HARIS_DASHBOARD_TOKEN=dev-token haris
#         then open http://localhost:8501
#
# Hardened for the AWS/Fargate deployment (plan Stage 1):
#   * runs as an unprivileged user, not root
#   * no compiler toolchain in the final image
#   * unbuffered stdout, so CloudWatch shows log lines as they happen
#   * a container HEALTHCHECK against the same endpoint the ALB target group uses
#
# The base image is pinned by tag during development. Pin it by digest before the
# submission build — see the note at the end of this file.
FROM python:3.11-slim

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
# Dependencies first, so this layer is reused unless requirements.txt changes.  #
#                                                                              #
# build-essential is deliberately NOT installed. numpy, blis, thinc and spaCy   #
# all publish manylinux wheels for cp311, so nothing needs to compile — which   #
# keeps roughly 250 MB of compiler toolchain out of both the image and the      #
# attack surface. If a dependency ever does need to build from source, use a    #
# multi-stage build rather than adding gcc back to the runtime image.           #
# --------------------------------------------------------------------------- #
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt \
    && python -m spacy download en_core_web_sm   # Presidio (Secrets/PII agent) needs this model

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
# Checks Streamlit's own /_stcore/health using the interpreter that is already  #
# in the image, so no curl and no extra package. This is the same endpoint the  #
# ALB target group will check, which means a health failure looks identical     #
# locally and in production.                                                    #
#                                                                              #
# start-period is 90s: the first request boots Presidio and spaCy and replays   #
# all five demo scenarios through the orchestrator, so an early check would     #
# report unhealthy while the container is merely still starting.                #
# --------------------------------------------------------------------------- #
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4).status == 200 else 1)"

# Operator dashboard. (To run the evaluation instead:
#   docker run --rm haris python -m demo_app.eval.simulate )
CMD ["streamlit", "run", "demo_app/dashboard.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]

# --------------------------------------------------------------------------- #
# Before the submission build, pin the base image by digest for reproducibility:#
#                                                                              #
#   docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim         #
#                                                                              #
# then replace the FROM line above with the sha256 form it prints, e.g.         #
#   FROM python:3.11-slim@sha256:<digest>                                       #
#                                                                              #
# Pinning is left until last on purpose — a pinned digest makes iterating on    #
# the image slower, and the value is in the final artefact, not the drafts.     #
# --------------------------------------------------------------------------- #