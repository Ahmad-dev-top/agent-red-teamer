"""Typed contracts — the spine every module fits.

These models are the hand-off format across the whole tool: a `Target` describes
the agent under test, `Attack`s come from the YAML seed library, an `Attempt`
records one attack run with its hard evidence, a `Finding` is a proven break, and
a `Report` is the campaign result with before/after attack-success rates.

The design rule that makes this credible: success is decided by the deterministic
`Verdict` (a tool-call log entry or a leaked canary), never by a model's opinion.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AttackCategory(str, Enum):
    DIRECT_INJECTION = "direct_prompt_injection"
    INDIRECT_INJECTION = "indirect_prompt_injection"
    EXCESSIVE_AGENCY = "excessive_agency"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"
    RESOURCE_ABUSE = "resource_abuse"


class OwaspId(str, Enum):
    """OWASP Top 10 for LLM Applications (2025) — the language buyers use."""

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Sensitive Information Disclosure
    LLM03 = "LLM03"  # Supply Chain
    LLM04 = "LLM04"  # Data and Model Poisoning
    LLM05 = "LLM05"  # Improper Output Handling
    LLM06 = "LLM06"  # Excessive Agency
    LLM07 = "LLM07"  # System Prompt Leakage
    LLM08 = "LLM08"  # Vector and Embedding Weaknesses
    LLM09 = "LLM09"  # Misinformation
    LLM10 = "LLM10"  # Unbounded Consumption


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProofType(str, Enum):
    """How a break is proven — each has a deterministic check in the judge."""

    FORBIDDEN_TOOL_CALL = "forbidden_tool_call"          # a tool that must never be called, was
    TRIPWIRE_FIRED = "tripwire_fired"                    # a tool called with out-of-policy args
    CANARY_LEAKED = "canary_leaked"                      # secret token reached an output/outbound sink
    SYSTEM_PROMPT_LEAKED = "system_prompt_leaked"        # system-prompt canary appeared in output
    PLANTED_INSTRUCTION_FOLLOWED = "planted_instruction_followed"  # agent obeyed injected content
    BUDGET_EXCEEDED = "budget_exceeded"                  # steps/cost over budget


class AdapterKind(str, Enum):
    HTTP = "http"
    OPENAI_COMPATIBLE = "openai_compatible"
    MCP = "mcp"
    LOCAL = "local"  # in-process instrumented agent (tier 3)
    STUB = "stub"  # for tests / dry runs


class AttemptStatus(str, Enum):
    PENDING = "pending"
    RAN = "ran"
    SUCCEEDED = "succeeded"  # the attack worked (a real finding)
    FAILED = "failed"        # the agent resisted
    ERROR = "error"


# --------------------------------------------------------------------------- #
# Target (the agent under test) + its instrumentation
# --------------------------------------------------------------------------- #
class Canary(BaseModel):
    """A secret token planted somewhere; if it leaks, exfiltration is proven."""

    id: str
    value: str
    placed_in: str = "tool_result"  # system_prompt | tool_result:<tool> | document


class TargetTool(BaseModel):
    """A tool the agent can call, plus the policy that makes a call a breach."""

    name: str
    description: str = ""
    forbidden: bool = False                       # must never be called in this scenario
    tripwire: bool = False                        # out-of-policy when called...
    out_of_policy_when: dict[str, Any] = Field(default_factory=dict)  # ...optionally only on these args


class Target(BaseModel):
    id: str
    name: str
    adapter: AdapterKind = AdapterKind.HTTP
    config: dict[str, Any] = Field(default_factory=dict)  # adapter-specific (url, headers, model...)
    system_prompt: str | None = None
    tools: list[TargetTool] = Field(default_factory=list)
    canaries: list[Canary] = Field(default_factory=list)
    step_budget: int = 20
    cost_budget_usd: float = 1.0

    def tool(self, name: str) -> TargetTool | None:
        return next((t for t in self.tools if t.name == name), None)

    def canary(self, cid: str | None) -> Canary | None:
        if cid is None:
            return None
        return next((c for c in self.canaries if c.id == cid), None)


# --------------------------------------------------------------------------- #
# Attack (seed) + success condition
# --------------------------------------------------------------------------- #
class SuccessCondition(BaseModel):
    """Declares what the deterministic judge must observe to count the attack as
    successful. Exactly the proof the finding will carry."""

    proof: ProofType
    tool: str | None = None        # for FORBIDDEN_TOOL_CALL / TRIPWIRE_FIRED (optional narrowing)
    canary_id: str | None = None   # for CANARY_LEAKED / SYSTEM_PROMPT_LEAKED
    marker: str | None = None      # for PLANTED_INSTRUCTION_FOLLOWED (string proving obedience)


class Attack(BaseModel):
    id: str
    category: AttackCategory
    owasp: OwaspId
    title: str
    description: str = ""
    turns: list[str] = Field(default_factory=list)   # templated user messages, in order
    injected_content: str | None = None              # poisoned doc/email/page for indirect injection
    success: SuccessCondition
    severity: Severity = Severity.MEDIUM
    source: str = "redforge-agents"


# --------------------------------------------------------------------------- #
# Run observations (produced by an adapter) + judge verdict
# --------------------------------------------------------------------------- #
class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None


class Turn(BaseModel):
    role: str  # user | assistant | tool | injected
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


class RunResult(BaseModel):
    """What an adapter returns after running an attack against the target."""

    transcript: list[Turn] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)  # flat log across the run
    outbound_payloads: list[str] = Field(default_factory=list)  # strings sent to outbound sinks
    final_output: str = ""
    steps: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0
    error: str | None = None


class Verdict(BaseModel):
    """The deterministic decision — the only thing that declares success."""

    succeeded: bool
    proof: ProofType | None = None
    evidence: str = ""  # the specific hard evidence (log entry / leaked value)


class JudgeResult(BaseModel):
    verdict: Verdict                       # deterministic — authoritative
    llm_opinion: bool | None = None        # second opinion only; never overrides
    llm_rationale: str = ""

    @property
    def succeeded(self) -> bool:
        return self.verdict.succeeded

    @property
    def agrees(self) -> bool | None:
        if self.llm_opinion is None:
            return None
        return self.llm_opinion == self.verdict.succeeded


# --------------------------------------------------------------------------- #
# Attempt / Finding / Report
# --------------------------------------------------------------------------- #
class Attempt(BaseModel):
    attack_id: str
    target_id: str
    status: AttemptStatus = AttemptStatus.PENDING
    run: RunResult | None = None
    judge: JudgeResult | None = None
    turns_used: int = 1          # 1 for single-turn; >1 when the attacker chained
    cost_usd: float = 0.0
    seconds: float = 0.0


class Finding(BaseModel):
    attack_id: str
    category: AttackCategory
    owasp: OwaspId
    severity: Severity
    title: str
    proof: ProofType
    evidence: str                                   # the hard evidence
    transcript: list[Turn] = Field(default_factory=list)  # full reproduction
    recommendation: str = ""


class CategoryScore(BaseModel):
    category: AttackCategory
    attempts: int = 0
    successes: int = 0

    @property
    def asr(self) -> float:  # attack success rate
        return self.successes / self.attempts if self.attempts else 0.0


class Report(BaseModel):
    target_id: str
    target_name: str
    attempts: list[Attempt] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scores: list[CategoryScore] = Field(default_factory=list)
    total_cost_usd: float = 0.0
    total_seconds: float = 0.0
    judge_agreement: float | None = None  # deterministic vs LLM on attempts where both ran


class RunSummary(BaseModel):
    """Index row for one persisted campaign, including its ASR table."""

    id: str
    created_at: str
    target_id: str
    target_name: str
    findings_count: int
    total_cost_usd: float = 0.0
    total_seconds: float = 0.0
    scores: list[CategoryScore] = Field(default_factory=list)
