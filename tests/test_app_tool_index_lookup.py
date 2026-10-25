"""Exercise each app's public index handler against its bundled manifest."""

import importlib
import sys
from types import ModuleType

import pytest


@pytest.mark.parametrize(
    ("package", "name"),
    [
        ("unifi_network_mcp", "unifi_list_devices"),
        ("unifi_protect_mcp", "protect_list_cameras"),
        ("unifi_access_mcp", "access_list_doors"),
    ],
)
@pytest.mark.asyncio
async def test_app_handler_preserves_exact_name_semantics(
    monkeypatch: pytest.MonkeyPatch, package: str, name: str
) -> None:
    # The index needs registration metadata, not runtime controller factories.
    bootstrap = ModuleType(f"{package}.bootstrap")
    bootstrap.UNIFI_TOOL_REGISTRATION_MODE = "lazy"
    monkeypatch.setitem(sys.modules, bootstrap.__name__, bootstrap)
    module = importlib.import_module(f"{package}.tool_index")

    result = await module.tool_index_handler({"name": name, "include_schemas": True})
    assert result["filtered"] is True
    assert result["count"] == 1
    assert [tool["name"] for tool in result["tools"]] == [name]
    assert "input" in result["tools"][0]["schema"]

    missing = await module.tool_index_handler({"name": "__nonexistent_exact_tool__"})
    assert missing["filtered"] is True
    assert missing["count"] == 0
    assert missing["tools"] == []

    invalid = await module.tool_index_handler({"name": name, "search": ""})
    assert invalid["success"] is False


@pytest.mark.parametrize(
    ("package", "server", "read_tool"),
    [
        ("unifi_network_mcp", "NETWORK", "unifi_list_devices"),
        ("unifi_protect_mcp", "PROTECT", "protect_list_cameras"),
        ("unifi_access_mcp", "ACCESS", "access_list_doors"),
    ],
)
@pytest.mark.asyncio
async def test_app_handler_lists_only_reads_in_read_only_mode(
    monkeypatch: pytest.MonkeyPatch, package: str, server: str, read_tool: str
) -> None:
    monkeypatch.delenv("UNIFI_READ_ONLY", raising=False)
    bootstrap = ModuleType(f"{package}.bootstrap")
    bootstrap.UNIFI_TOOL_REGISTRATION_MODE = "lazy"
    monkeypatch.setitem(sys.modules, bootstrap.__name__, bootstrap)
    module = importlib.import_module(f"{package}.tool_index")

    monkeypatch.delenv(f"UNIFI_{server}_READ_ONLY", raising=False)
    full = await module.tool_index_handler({"include_schemas": True})
    monkeypatch.setenv(f"UNIFI_{server}_READ_ONLY", "true")
    read_only = await module.tool_index_handler({"include_schemas": True})

    mutating = {tool["name"] for tool in full["tools"] if (tool.get("permission_action") or "read").lower() != "read"}
    assert mutating, "the manifest should declare tools that change state"
    assert read_only["read_only"] is True
    assert read_only["count"] == full["count"] - len(mutating)
    assert {tool["name"] for tool in read_only["tools"]} == {tool["name"] for tool in full["tools"]} - mutating
    assert read_tool in {tool["name"] for tool in read_only["tools"]}
