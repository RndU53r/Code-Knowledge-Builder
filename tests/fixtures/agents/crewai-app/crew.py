from crewai import Agent, Crew, Task

researcher = Agent(role="Researcher", goal="find facts", backstory="x")
writer = Agent(role="Writer", goal="write", backstory="y")
crew = Crew(agents=[researcher, writer], tasks=[Task(description="t", agent=writer)])
