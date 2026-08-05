# Haris — container image for the operator dashboard (and the code to run the eval / demo).
#
# Build:  docker build -t haris .
# Run:    docker run -p 8501:8501 haris        # then open http://localhost:8501
#
# This is the deployment STARTING POINT (plan Step 14): one reproducible image that serves the
# dashboard with all five agents active. Splitting Haris into its own service, a persisted audit
# store, and AWS are later steps.

FROM python:3.11-slim

# Build tools: some of Presidio/spaCy's deps (blis/thinc) may compile from source on slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so this layer is cached unless requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_sm   # Presidio (Secrets/PII agent) needs this model

# Copy the rest of the project.
COPY . .

# Streamlit must listen on all interfaces and run headless inside a container.
ENV STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

EXPOSE 8501

# Operator dashboard. (To run the evaluation instead:
#   docker run haris python -m demo_app.eval.simulate )
CMD ["streamlit", "run", "demo_app/dashboard.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]