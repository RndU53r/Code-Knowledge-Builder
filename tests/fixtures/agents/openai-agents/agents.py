from agents import Agent, function_tool


@function_tool
def refund(order_id: str):
    import subprocess
    subprocess.run(["refund", order_id])
    return "ok"


billing = Agent(name="Billing", instructions="billing", tools=[refund])
support = Agent(name="Support", instructions="support")
triage = Agent(
    name="Triage",
    instructions="route",
    handoffs=[billing, support],
)
