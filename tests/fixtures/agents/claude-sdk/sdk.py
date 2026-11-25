from claude_agent_sdk import ClaudeAgentOptions, AgentDefinition, tool

options = ClaudeAgentOptions(
    agents={
        "reviewer": AgentDefinition(description="review", prompt="review code", tools=["Read"]),
    },
)


@tool("lookup", "look up a record", {"id": str})
async def lookup(args):
    return args
