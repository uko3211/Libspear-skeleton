
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class VulnerabilityContext:
    """CodeQL 분석 결과 JSON을 파싱하여 담는 데이터 클래스"""
    project: str
    language: str
    file_path: str
    function_name: str
    sink: str
    sink_id: str
    known_weakness: List[str]
    code_context: Dict[str, str]

@dataclass
class AttackAttempt:
    payload: str
    timestamp: str
    is_successful: bool
    execution_log: str
    analysis_reason: str
    simulated_code: str
    coverage_percent: Optional[float] = None


@dataclass
class AttackResult:
    """최종 공격 결과를 담는 데이터 클래스"""
    vulnerability_context: VulnerabilityContext
    status: str # SUCCESS, FAILED_MAX_RETRIES
    successful_payload: str | None = None
    attempts: List[AttackAttempt] = field(default_factory=list)
