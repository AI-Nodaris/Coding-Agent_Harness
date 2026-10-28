import pytest


@pytest.fixture(autouse=True)
def harness_home(tmp_path, monkeypatch):
    """Hooks read the person's harness settings; a test never sees the real ones."""
    monkeypatch.setenv("NODARIS_HARNESS_HOME", str(tmp_path / "harness-home"))
