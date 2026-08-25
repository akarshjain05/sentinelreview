import functools
from typing import Any

from langgraph.graph import END, StateGraph

from app.agents.nodes.classification import make_classification_node
from app.agents.nodes.fix_suggestion import make_fix_suggestion_node
from app.agents.nodes.reporting import reporting_node
from app.agents.nodes.retrieval import make_retrieval_node
from app.agents.nodes.static_analysis import make_static_analysis_node
from app.agents.nodes.triage import triage_node
from app.agents.nodes.verification import make_verification_node
from app.agents.state import ReviewState
from app.core.config import get_settings
from app.knowledge.tfidf_index import TfidfKnowledgeIndex
from app.services.static_analysis import get_default_analyzers


@functools.lru_cache(maxsize=1)
def get_cached_knowledge_index():
    return TfidfKnowledgeIndex.from_seed_corpus()

def build_graph(
    static_analyzers: dict[str, Any] | None = None,
    knowledge_index: TfidfKnowledgeIndex | None = None,
    zero_shot: Any | None = None,
    generator: Any | None = None,
) -> StateGraph:
    """
    Constructs the LangGraph state machine. Nodes are extracted into app.agents.nodes.*.
    """
    from app.agents.model_clients import (
        LiteLLMClassifier,
        LiteLLMClient,
        MockGenerationClient,
        MockZeroShotClassifier,
    )

    settings = get_settings()
    if settings.openai_api_key or settings.anthropic_api_key or settings.gemini_api_key or settings.groq_api_key or settings.nvidia_api_key:
        if settings.nvidia_api_key:
            model = "nvidia_nim/nvidia/nemotron-4-340b-instruct"
        elif settings.openai_api_key:
            model = "gpt-4o-mini"
        elif settings.anthropic_api_key:
            model = "claude-3-haiku-20240307"
        elif settings.groq_api_key:
            model = "groq/llama3-8b-8192"
        else:
            model = "gemini/gemini-1.5-flash"
        
        classifier = zero_shot or LiteLLMClassifier(model=model)
        generator = generator or LiteLLMClient(model=model)
    else:
        classifier = zero_shot or MockZeroShotClassifier()
        generator = generator or MockGenerationClient()

    static_analyzers = static_analyzers or get_default_analyzers()
    knowledge_index = knowledge_index or get_cached_knowledge_index()

    graph = StateGraph(ReviewState)
    graph.add_node("triage", triage_node)
    graph.add_node("static_analysis", make_static_analysis_node(static_analyzers))
    graph.add_node("retrieval", make_retrieval_node(knowledge_index))
    graph.add_node("classification", make_classification_node(classifier))
    graph.add_node("fix_suggestion", make_fix_suggestion_node(generator))
    graph.add_node("verification", make_verification_node(static_analyzers))
    graph.add_node("reporting", reporting_node)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "static_analysis")
    graph.add_edge("static_analysis", "retrieval")
    graph.add_edge("retrieval", "classification")
    graph.add_edge("classification", "fix_suggestion")
    graph.add_edge("fix_suggestion", "verification")
    graph.add_edge("verification", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()
