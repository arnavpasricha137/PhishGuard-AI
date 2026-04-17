"""
LangGraph Orchestrator.
Coordinates parallel execution of all specialist agents and consensus.
"""

import asyncio
import time
from typing import Dict, Any, TypedDict
from typing_extensions import Annotated
from langgraph.graph import StateGraph, END
from agents.url_agent import get_url_agent
from agents.content_agent import get_content_agent
from agents.header_agent import get_header_agent
from agents.reputation_agent import get_reputation_agent
from agents.consensus import get_consensus_agent
from config import settings


class AgentState(TypedDict):
    """State shared across all agents in the graph."""
    email_payload: Dict[str, Any]
    url_agent_result: Dict[str, Any]
    content_agent_result: Dict[str, Any]
    header_agent_result: Dict[str, Any]
    reputation_agent_result: Dict[str, Any]
    final_verdict: Dict[str, Any]
    processing_time_ms: int


class PhishingOrchestrator:
    """Orchestrates parallel agent execution using LangGraph."""
    
    def __init__(self):
        """Initialize orchestrator with agents and graph."""
        self.url_agent = get_url_agent()
        self.content_agent = get_content_agent()
        self.header_agent = get_header_agent()
        self.reputation_agent = get_reputation_agent()
        self.consensus_agent = get_consensus_agent()
        self.timeout = settings.agent_timeout
        
        # Build the graph
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """
        Build LangGraph state graph for agent orchestration.
        
        Returns:
            Compiled StateGraph
        """
        # Create graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("parallel_agents", self._run_parallel_agents)
        workflow.add_node("consensus", self._run_consensus)
        
        # Define edges
        workflow.set_entry_point("parallel_agents")
        workflow.add_edge("parallel_agents", "consensus")
        workflow.add_edge("consensus", END)
        
        # Compile
        return workflow.compile()
    
    async def _run_single_agent(
        self, 
        agent_name: str, 
        agent_func, 
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Run a single agent with timeout protection.
        
        Args:
            agent_name: Name of the agent
            agent_func: Async agent function to call
            payload: Email payload
            
        Returns:
            Agent result or fallback on timeout/error
        """
        try:
            result = await asyncio.wait_for(
                agent_func(payload),
                timeout=self.timeout
            )
            return result
        
        except asyncio.TimeoutError:
            print(f"⚠ {agent_name} timed out after {self.timeout}s")
            return {
                "score": 0,
                "signals": [f"{agent_name} timeout - using fallback"],
                "url_verdicts": [] if agent_name == "url_agent" else None,
                "highlighted_phrases": [] if agent_name == "content_agent" else None,
                "spear_phishing_detected": False if agent_name == "content_agent" else None
            }
        
        except Exception as e:
            print(f"✗ {agent_name} error: {e}")
            return {
                "score": 0,
                "signals": [f"{agent_name} error: {str(e)}"],
                "url_verdicts": [] if agent_name == "url_agent" else None,
                "highlighted_phrases": [] if agent_name == "content_agent" else None,
                "spear_phishing_detected": False if agent_name == "content_agent" else None
            }
    
    async def _run_parallel_agents(self, state: AgentState) -> AgentState:
        """
        Run all 4 agents in parallel.
        
        Args:
            state: Current graph state
            
        Returns:
            Updated state with agent results
        """
        payload = state["email_payload"]
        
        # Create tasks for all agents
        tasks = [
            self._run_single_agent("url_agent", self.url_agent.analyze, payload),
            self._run_single_agent("content_agent", self.content_agent.analyze, payload),
            self._run_single_agent("header_agent", self.header_agent.analyze, payload),
            self._run_single_agent("reputation_agent", self.reputation_agent.analyze, payload),
        ]
        
        # Run in parallel
        results = await asyncio.gather(*tasks)
        
        # Update state
        state["url_agent_result"] = results[0]
        state["content_agent_result"] = results[1]
        state["header_agent_result"] = results[2]
        state["reputation_agent_result"] = results[3]
        
        return state
    
    async def _run_consensus(self, state: AgentState) -> AgentState:
        """
        Run consensus agent to combine results.
        
        Args:
            state: Current graph state with agent results
            
        Returns:
            Updated state with final verdict
        """
        final_verdict = self.consensus_agent.combine_results(
            state["url_agent_result"],
            state["content_agent_result"],
            state["header_agent_result"],
            state["reputation_agent_result"]
        )
        
        state["final_verdict"] = final_verdict
        
        return state
    
    async def analyze_email(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email using multi-agent orchestration.
        
        Args:
            payload: Email payload with all fields
            
        Returns:
            Complete analysis result
        """
        start_time = time.time()
        
        # Initialize state
        initial_state: AgentState = {
            "email_payload": payload,
            "url_agent_result": {},
            "content_agent_result": {},
            "header_agent_result": {},
            "reputation_agent_result": {},
            "final_verdict": {},
            "processing_time_ms": 0
        }
        
        # Run the graph
        final_state = await self.graph.ainvoke(initial_state)
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        
        # Extract final verdict and add processing time
        result = final_state["final_verdict"]
        result["processing_time_ms"] = processing_time
        
        return result


# Global orchestrator instance
_orchestrator = None


def get_orchestrator() -> PhishingOrchestrator:
    """
    Get or create global orchestrator instance.
    
    Returns:
        PhishingOrchestrator instance
    """
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = PhishingOrchestrator()
    return _orchestrator
