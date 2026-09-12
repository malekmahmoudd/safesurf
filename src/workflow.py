"""LangGraph workflow for URL reputation screening and safe LLM routing."""

from __future__ import annotations

import base64
import os
from typing import Literal
from urllib.parse import urlparse

import requests
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict


class WorkflowState(TypedDict, total=False):
    website_url: str
    user_request: str
    history: list[dict[str, str]]
    safety_status: Literal["safe", "unsafe"]
    safety_reason: str
    response: str


def safety_check(state: WorkflowState) -> WorkflowState:
    """Check the submitted URL with VirusTotal; fail closed on uncertainty."""
    url = state["website_url"].strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"safety_status": "unsafe", "safety_reason": "Enter a valid HTTP or HTTPS URL."}

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"safety_status": "unsafe", "safety_reason": "The website safety service is not configured."}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=10)
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, KeyError, ValueError):
        return {"safety_status": "unsafe", "safety_reason": "The website could not be verified right now. Please try again later."}

    stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    if malicious or suspicious:
        return {"safety_status": "unsafe", "safety_reason": f"VirusTotal reported {malicious} malicious and {suspicious} suspicious detections."}
    return {"safety_status": "safe", "safety_reason": "No malicious or suspicious detections were reported by VirusTotal."}


def route_after_safety(state: WorkflowState) -> Literal["generate_response", "fallback"]:
    return "generate_response" if state["safety_status"] == "safe" else "fallback"


def generate_response(state: WorkflowState) -> WorkflowState:
    """Call Groq only after the reputation check has passed."""
    model = ChatGroq(model="openai/gpt-oss-20b", temperature=0)
    transcript = "\n".join(
        f"{item['role'].title()}: {item['content']}"
        for item in state.get("history", [])[-12:]
        if item.get("role") in {"user", "assistant"} and item.get("content")
    )
    message = model.invoke(
        "A website passed a URL reputation check, but you have not visited it. "
        f"Website: {state['website_url']}\nConversation so far:\n{transcript}\n\n"
        f"User question: {state['user_request']}\n\n"
        "Answer helpfully without claiming you inspected the website or guaranteeing it is safe."
    )
    return {"response": str(message.content)}


def fallback(state: WorkflowState) -> WorkflowState:
    return {"response": f"I can't process this website. {state['safety_reason']}"}


def build_graph():
    builder = StateGraph(WorkflowState)
    builder.add_node("safety_check", safety_check)
    builder.add_node("generate_response", generate_response)
    builder.add_node("fallback", fallback)
    builder.add_edge(START, "safety_check")
    builder.add_conditional_edges("safety_check", route_after_safety)
    builder.add_edge("generate_response", END)
    builder.add_edge("fallback", END)
    return builder.compile()
