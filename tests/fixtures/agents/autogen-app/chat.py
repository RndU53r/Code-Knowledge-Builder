import autogen

assistant = autogen.AssistantAgent("assistant", llm_config={})
user_proxy = autogen.UserProxyAgent("user_proxy", code_execution_config={"work_dir": "x"})
user_proxy.initiate_chat(assistant, message="hi")
