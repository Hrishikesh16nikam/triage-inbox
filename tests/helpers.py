import shutil
import tempfile
import unittest
from pathlib import Path

from triage.config import Settings
from triage.providers import MockTranscriber, RuleClassifier
from triage.server import App


def make_settings(tmp: Path, **overrides) -> Settings:
    s = Settings(data_dir=tmp, secret_key=b"t" * 64, worker_poll_seconds=0.05)
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


class AppTestCase(unittest.TestCase):
    """Fresh app with its own temp database for every test."""

    settings_overrides: dict = {}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="triage-test-"))
        self.settings = make_settings(self.tmp, **self.settings_overrides)
        self.app = App(self.settings, transcriber=MockTranscriber(), classifier=RuleClassifier())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_user(self, username="alice", role="triager", password="correct horse battery"):
        user = self.app.users.create(username, password, role, "test")
        return user, password
