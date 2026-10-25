"""Read-only mode: tools that change state are not registered, and every non-read action is denied."""

import json
import logging
import sys
import types
import uuid
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver import MCPServer as FastMCP
from mcp.types import ToolAnnotations
from unifi_core.policy_gate import PolicyGateChecker
from unifi_mcp_shared.lazy_tools import setup_lazy_loading
from unifi_mcp_shared.meta_tools import register_load_tools, register_meta_tools
from unifi_mcp_shared.permissioned_tool import create_permissioned_tool
from unifi_mcp_shared.tool_index import READ_ONLY_HIDDEN_TOOLS, TOOL_REGISTRY, get_tool_index, register_tool

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    for key in ("UNIFI_READ_ONLY", "UNIFI_NETWORK_READ_ONLY", "UNIFI_PROTECT_READ_ONLY"):
        monkeypatch.delenv(key, raising=False)
    TOOL_REGISTRY.clear()
    READ_ONLY_HIDDEN_TOOLS.clear()
    yield
    TOOL_REGISTRY.clear()
    READ_ONLY_HIDDEN_TOOLS.clear()


def _permissioned_tool(server, server_prefix="network"):
    return create_permissioned_tool(
        original_tool_decorator=server.tool,
        policy_gate_checker=PolicyGateChecker(server_prefix=server_prefix, category_map={}),
        server_prefix=server_prefix,
        register_tool_fn=register_tool,
        diagnostics_enabled_fn=lambda: False,
        wrap_tool_fn=lambda func, name: func,
        logger=logging.getLogger("test"),
    )


def _declare_tools(pt):
    @pt(name="unifi_list_things", description="List things", annotations=READ_ONLY)
    async def unifi_list_things() -> dict:
        return {"success": True, "data": []}

    @pt(
        name="unifi_get_thing",
        description="Get a thing",
        annotations=READ_ONLY,
        permission_category="things",
        permission_action="read",
    )
    async def unifi_get_thing() -> dict:
        return {"success": True, "data": {}}

    @pt(
        name="unifi_delete_thing",
        description="Delete a thing",
        annotations=DESTRUCTIVE,
        permission_category="things",
        permission_action="delete",
    )
    async def unifi_delete_thing(confirm: bool = False) -> dict:
        return {"success": True}

    return unifi_delete_thing


class TestRegistration:
    @pytest.mark.asyncio
    async def test_mutating_tools_are_neither_listed_nor_indexed(self, monkeypatch):
        monkeypatch.setenv("UNIFI_READ_ONLY", "true")
        server = FastMCP("test")

        _declare_tools(_permissioned_tool(server))

        listed = sorted(tool.name for tool in await server.list_tools())
        assert listed == ["unifi_get_thing", "unifi_list_things"]
        assert sorted(TOOL_REGISTRY) == ["unifi_get_thing", "unifi_list_things"]
        assert READ_ONLY_HIDDEN_TOOLS == {"unifi_delete_thing"}

    @pytest.mark.asyncio
    async def test_hidden_tool_is_returned_undecorated_for_direct_calls(self, monkeypatch):
        monkeypatch.setenv("UNIFI_READ_ONLY", "true")

        delete = _declare_tools(_permissioned_tool(FastMCP("test")))

        assert await delete(confirm=True) == {"success": True}

    @pytest.mark.asyncio
    async def test_without_read_only_mode_every_tool_registers(self):
        server = FastMCP("test")

        _declare_tools(_permissioned_tool(server))

        listed = sorted(tool.name for tool in await server.list_tools())
        assert listed == ["unifi_delete_thing", "unifi_get_thing", "unifi_list_things"]
        assert READ_ONLY_HIDDEN_TOOLS == set()

    @pytest.mark.asyncio
    async def test_another_servers_read_only_variable_does_not_hide_tools(self, monkeypatch):
        monkeypatch.setenv("UNIFI_PROTECT_READ_ONLY", "true")
        server = FastMCP("test")

        _declare_tools(_permissioned_tool(server, server_prefix="network"))

        listed = sorted(tool.name for tool in await server.list_tools())
        assert listed == ["unifi_delete_thing", "unifi_get_thing", "unifi_list_things"]

    @pytest.mark.asyncio
    async def test_call_time_check_still_denies_a_tool_registered_before_the_switch(self, monkeypatch):
        server = FastMCP("test")
        _declare_tools(_permissioned_tool(server))
        monkeypatch.setenv("UNIFI_READ_ONLY", "true")

        result = await server.call_tool("unifi_delete_thing", {"confirm": True})

        assert result.structured_content["success"] is False
        assert "read-only mode" in result.structured_content["error"]


class TestToolIndex:
    def test_read_only_index_drops_manifest_tools_that_are_not_reads(self, tmp_path):
        manifest = {
            "tools": [
                {"name": "unifi_list_things", "description": "List"},
                {"name": "unifi_get_thing", "description": "Get", "permission_action": "read"},
                {"name": "unifi_update_thing", "description": "Update", "permission_action": "update"},
                {"name": "unifi_delete_thing", "description": "Delete", "permission_action": "DELETE"},
            ],
        }
        manifest_path = tmp_path / "tools_manifest.json"
        manifest_path.write_text(json.dumps(manifest))

        full = get_tool_index(registration_mode="lazy", manifest_path=manifest_path)
        read_only = get_tool_index(registration_mode="lazy", manifest_path=manifest_path, read_only=True)

        assert full["count"] == 4
        assert "read_only" not in full
        assert [tool["name"] for tool in read_only["tools"]] == ["unifi_list_things", "unifi_get_thing"]
        assert read_only["count"] == 2
        assert read_only["read_only"] is True


class TestLazyLoading:
    @pytest.fixture
    def lazy_server(self, monkeypatch, tmp_path):
        """A server whose delete tool lives in a module the lazy loader imports on first call."""
        monkeypatch.setenv("UNIFI_READ_ONLY", "true")
        server = FastMCP("test")
        original_tool = server.tool
        pt = _permissioned_tool(server)

        holder = f"_read_only_test_decorator_{uuid.uuid4().hex}"
        module_name = f"_read_only_test_tools_{uuid.uuid4().hex}"
        monkeypatch.setitem(sys.modules, holder, types.SimpleNamespace(tool=pt))
        (tmp_path / f"{module_name}.py").write_text(
            f"from {holder} import tool\n\n"
            "@tool(\n"
            '    name="unifi_delete_thing",\n'
            '    description="Delete a thing",\n'
            '    annotations={"readOnlyHint": False, "destructiveHint": True},\n'
            '    permission_category="things",\n'
            '    permission_action="delete",\n'
            ")\n"
            "async def unifi_delete_thing(confirm: bool = False) -> dict:\n"
            '    return {"success": True}\n'
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        yield server, original_tool, {"unifi_delete_thing": module_name}
        sys.modules.pop(module_name, None)

    @pytest.mark.asyncio
    async def test_loading_a_hidden_tool_fails_and_says_why(self, lazy_server):
        server, original_tool, module_map = lazy_server
        loader = setup_lazy_loading(server, original_tool, module_map)

        assert await loader.load_tool("unifi_delete_thing") is False
        assert loader.is_loaded("unifi_delete_thing") is False
        with pytest.raises(ValueError, match="not available: the server is in read-only mode"):
            await server.call_tool("unifi_delete_thing", {"confirm": True})
        assert [tool.name for tool in await server.list_tools()] == []

    @pytest.mark.asyncio
    async def test_execute_and_load_tools_report_read_only_mode(self, lazy_server):
        server, original_tool, module_map = lazy_server
        loader = setup_lazy_loading(server, original_tool, module_map)
        register_meta_tools(
            server=server,
            tool_decorator=original_tool,
            tool_index_handler=AsyncMock(return_value={}),
            start_async_tool=AsyncMock(),
            get_job_status=AsyncMock(),
            register_tool=register_tool,
        )
        register_load_tools(
            server=server,
            tool_decorator=original_tool,
            lazy_loader=loader,
            register_tool=register_tool,
            tool_module_map=module_map,
        )

        executed = await server.call_tool(
            "unifi_execute", {"tool": "unifi_delete_thing", "arguments": {"confirm": True}}
        )
        loaded = await server.call_tool("unifi_load_tools", {"tools": ["unifi_delete_thing"]})

        executed_body = json.loads(executed.content[0].text)
        loaded_body = json.loads(loaded.content[0].text)
        assert "read-only mode" in executed_body["error"]
        assert loaded_body["loaded"] == []
        assert loaded_body["errors"] == [
            {"tool": "unifi_delete_thing", "error": "Not available: the server is in read-only mode"}
        ]
