import os
import tempfile

# app.api.routes_events builds its EventStore at import time, so the DB path
# env var must be set before any test module imports app.main / app.api.*.
os.environ.setdefault(
    "BLACKBOX_DB_PATH", os.path.join(tempfile.mkdtemp(prefix="blackbox-test-"), "test.db")
)
