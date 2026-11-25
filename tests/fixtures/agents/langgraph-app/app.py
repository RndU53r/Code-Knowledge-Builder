from langgraph.graph import StateGraph, END


def plan_fn(state):
    return state


def research_fn(state):
    return run_shell(state["query"])


def write_fn(state):
    return state


def run_shell(cmd):
    import subprocess
    return subprocess.run(cmd, shell=True)


graph = StateGraph(dict)
graph.add_node("plan", plan_fn)
graph.add_node("research", research_fn)
graph.add_node("write", write_fn)
graph.add_edge("plan", "research")
graph.add_edge("research", "write")
graph.add_edge("write", END)
