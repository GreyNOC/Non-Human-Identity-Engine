"""RAG and vector-store configuration parser."""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_for

TEXT_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".md", ".mdx", ".prompt", ".ipynb"}
# "rag" itself is matched word-bounded via _RAG_WORD_RE so "storage",
# "average", "coverage", or "leverage" do not flag ordinary code.
RAG_MARKERS = {"langchain", "langgraph", "llamaindex", "llama_index", "haystack", "crewai", "retriever", "retrievalqa", "vectorstore", "vector_store", "embedding"}
VECTOR_STORES = {"chroma", "pinecone", "weaviate", "qdrant", "faiss", "milvus", "pgvector", "elasticsearch", "opensearch"}
# Stores that are commonly plain search backends rather than RAG stores.
AMBIGUOUS_VECTOR_STORES = {"elasticsearch", "opensearch"}
# "url" and "web" are matched word-bounded via _UNTRUSTED_WORD_RE so "curl",
# "urllib", and "webpack" do not count as untrusted sources.
UNTRUSTED_SOURCES = {"http", "github issue", "github issues", "slack", "email", "gmail", "google drive", "gdrive", "pdf", "notion", "jira", "s3", "blob"}
ACCESS_FILTERS = {"tenant_id", "tenantid", "organization_id", "org_id", "user_id", "owner_id", "metadata_filter", "where=", "where:", "filter=", "filter:", "acl", "document_acl", "permissions"}
WRITABLE_MARKERS = {"upsert", "add_documents", "adddocuments", "insert", "write", "ingest", "loader", "crawl", "sync"}
TOOL_SINKS = {"shell", "terminal", "github", "email", "database", "sql", "docker", "kubernetes", "terraform", "aws", "azure", "gcp", "deploy", "send_email"}

_RAG_WORD_RE = re.compile(r"(?<![a-z0-9_])rag(?![a-z0-9_])")
_UNTRUSTED_WORD_RE = re.compile(r"(?<![a-z0-9])(?:url|web)(?![a-z0-9])")
# Single alternation instead of one re.search per sink marker.
_TOOL_SINKS_RE = re.compile(
    r"(?<![a-z0-9_-])(?:"
    + "|".join(sorted(map(re.escape, TOOL_SINKS), key=len, reverse=True))
    + r")(?![a-z0-9_-])"
)


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in TEXT_EXTENSIONS or any(marker in name for marker in ["rag", "vector", "retriever", "embedding", "langchain", "llama"])


def _contains_any(lowered: str, markers: set[str]) -> bool:
    return any(marker in lowered for marker in markers)


def _tools(lowered: str) -> list[str]:
    tools = sorted(set(_TOOL_SINKS_RE.findall(lowered)))
    return ["database" if tool == "sql" else "shell" if tool == "terminal" else tool for tool in tools]


def parse(path: Path, text: str) -> list[Signal]:
    lowered = text.lower()
    has_rag = _contains_any(lowered, RAG_MARKERS) or bool(_RAG_WORD_RE.search(lowered))
    stores = sorted(store for store in VECTOR_STORES if store in lowered)
    if not (has_rag or stores):
        return []

    signals: list[Signal] = []
    has_untrusted_source = _contains_any(lowered, UNTRUSTED_SOURCES) or bool(_UNTRUSTED_WORD_RE.search(lowered))
    has_access_filter = _contains_any(lowered, ACCESS_FILTERS)
    has_writable_kb = _contains_any(lowered, WRITABLE_MARKERS)
    has_ingestion = has_writable_kb or "loader" in lowered or "load(" in lowered
    tools = _tools(lowered)
    provider = ", ".join(stores) if stores else None
    ambiguous_stores_only = bool(stores) and not has_rag and set(stores) <= AMBIGUOUS_VECTOR_STORES

    if has_untrusted_source and has_rag and has_ingestion:
        signals.append(
            make_signal(
                rule_id="nhi_rag_untrusted_source_ingestion",
                file_path=path,
                line_number=line_number_for(lowered, "loader") or line_number_for(lowered, "url") or line_number_for(lowered, "slack") or line_number_for(lowered, "github"),
                name=f"{path.stem} RAG ingestion",
                identity_type="ai_agent",
                source="RAG config",
                evidence="RAG pipeline appears to ingest external or user-controlled content",
                provider=provider,
                external_access=True,
                context_store=provider,
                tools=tools,
                tags=["rag", "untrusted_context", "external_content"],
                ai_attack_class="RAG poisoning",
                attack_chain_stage="untrusted input",
                confidence="high",
            )
        )

    if (stores or has_rag) and not ambiguous_stores_only and not has_access_filter:
        signals.append(
            make_signal(
                rule_id="nhi_rag_no_access_filter",
                file_path=path,
                line_number=line_number_for(lowered, "retriever") or line_number_for(lowered, "vector"),
                name=f"{path.stem} RAG access control",
                identity_type="vector_store",
                source="RAG config",
                evidence="RAG/vector retrieval was found without visible tenant, owner, or metadata access filters",
                provider=provider,
                context_store=provider,
                data_classes=["documents"],
                external_access=has_untrusted_source,
                tags=["rag", "vector_store", "access_filter"],
                ai_attack_class="vector and embedding weakness",
                attack_chain_stage="context store",
                confidence="medium",
            )
        )

    if stores and not has_access_filter and any(token in lowered for token in ["tenant", "multi_tenant", "customer", "workspace"]):
        signals.append(
            make_signal(
                rule_id="nhi_vector_store_cross_tenant_risk",
                file_path=path,
                line_number=line_number_for(lowered, stores[0]) if stores else None,
                name=f"{path.stem} vector tenant isolation",
                identity_type="vector_store",
                source="RAG config",
                evidence="Vector store appears shared or tenant-aware but lacks explicit retrieval filters",
                provider=provider,
                context_store=provider,
                data_classes=["customer", "documents"],
                data_access_level="customer",
                tags=["rag", "vector_store", "tenant_isolation"],
                ai_attack_class="vector and embedding weakness",
                attack_chain_stage="context store",
                confidence="high",
            )
        )

    if has_writable_kb and (has_untrusted_source or stores):
        signals.append(
            make_signal(
                rule_id="nhi_rag_poisoning_surface",
                file_path=path,
                line_number=line_number_for(lowered, "upsert") or line_number_for(lowered, "add_documents") or line_number_for(lowered, "ingest"),
                name=f"{path.stem} writable knowledge base",
                identity_type="vector_store",
                source="RAG config",
                evidence="Knowledge base or vector store appears writable from ingestion code",
                provider=provider,
                context_store=provider,
                external_access=has_untrusted_source,
                tags=["rag", "vector_store", "poisoning_surface", "untrusted_context"],
                ai_attack_class="data poisoning",
                attack_chain_stage="context store",
                confidence="high",
            )
        )

    if has_rag and tools:
        signals.append(
            make_signal(
                rule_id="nhi_rag_context_to_tool_bridge",
                file_path=path,
                line_number=line_number_for(lowered, "tool") or line_number_for(lowered, "agent"),
                name=f"{path.stem} RAG-to-tool bridge",
                identity_type="ai_agent",
                source="RAG config",
                evidence=f"RAG context appears connected to privileged tools: {', '.join(sorted(set(tools)))}",
                provider=provider,
                tools=sorted(set(tools)),
                context_store=provider,
                external_access=True,
                admin_access=any(tool in tools for tool in ["shell", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"]),
                approval_required=False if "approval" not in lowered and "human" not in lowered else None,
                tags=["rag", "context_to_tool", "privileged_sink", "untrusted_context"],
                ai_attack_class="toxic flow",
                attack_chain_stage="prompt/context",
                confidence="high",
            )
        )

    return signals
