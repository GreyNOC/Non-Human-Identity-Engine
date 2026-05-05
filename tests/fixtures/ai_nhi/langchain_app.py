from langchain.agents import initialize_agent

OPENAI_API_KEY = "GNOC_FAKE_SECRET_DO_NOT_USE_LANGCHAIN_OPENAI_123456"

def build_agent():
    return initialize_agent([])
