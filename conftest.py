import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from backend import database


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    test_db = tmp_path / "honeywatch_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", test_db)

    database.initialize_database()

    yield test_db