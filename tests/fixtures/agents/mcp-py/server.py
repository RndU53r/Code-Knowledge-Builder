from mcp.server.fastmcp import FastMCP

mcp = FastMCP("records")


@mcp.tool()
def lookup(record_id: str):
    return record_id
