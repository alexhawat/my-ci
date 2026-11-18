import pytest

from localci.runner import Runner


@pytest.fixture(autouse=True)
def no_real_docker_network_cleanup(monkeypatch):
    """Run finalization removes the per-run Docker network; unit tests must not shell out."""

    async def remove_network(self, name):
        return None

    monkeypatch.setattr(Runner, "remove_network", remove_network)
