import json
import subprocess
import re
import time
from typing import Optional
from pathlib import Path

from .data_structures import VulnerabilityContext
from .llm_interface import LLMInterface

class SandboxExecutor:
    def __init__(self, llm_interface: LLMInterface, coverage_cmd: Optional[list] = None, coverage_timeout: int = 10):
        self.llm = llm_interface
        # fuzzer_runner를 모듈로 실행하도록 변경
        self.base_coverage_cmd = coverage_cmd or ["python3", "-m", "coverage.fuzzer_runner", "--mode", "interactive"]
        self.coverage_timeout = coverage_timeout

        current_file_dir = Path(__file__).resolve().parent
        parent_dir = current_file_dir.parent
        self.default_coverage_cwd = str(parent_dir)

    def _create_prompt(self, payload: str, context: VulnerabilityContext) -> str:
        return f"""
You are a security expert and penetration testing simulator.
Your task is to first create a complete, simulated code script representing an attack, and then predict the execution log that would result from running it.

[Vulnerability Context]
- Known Weakness: {context.known_weakness}
- Function Name: {context.function_name}
- Target File: {context.file_path}
- Code Context:
{context.code_context.get('before', '')}
// Sink Line
{context.code_context.get('sinkLine', '')}
{context.code_context.get('after', '')}


[Malicious Input String]
`{payload}`

[Task 1: Create Simulated Attack Code]
Inject the [Malicious Input String] into the [Code Context] at the correct entry point to exploit the vulnerability. The result should be a single, complete, executable code block that represents the attack.

[Task 2: Predict Execution Log]
Based on the simulated code you just created, predict the application's log output.

[Output Format]
Provide your response as a single JSON object with two keys: "simulated_code" and "execution_log". Do not include any other text or explanations.
"""

    def _parse_llm_json(self, text: str) -> Optional[dict]:
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start == -1 or end == 0:
                return None
            candidate = text[start:end]
            return json.loads(candidate)
        except Exception:
            return None

    def _run_coverage_process(self, payload: str, pseudo_path: Optional[str] = None, cwd: Optional[str] = None) -> dict:
        cmd = self.base_coverage_cmd[:]
        if pseudo_path:
            cmd.extend(["--file", pseudo_path])

        try:
            proc = subprocess.run(
                cmd,
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.coverage_timeout,
                cwd=cwd,
                shell=False,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            coverage_pct = None
            coverage_max = None

            m_current = re.search(r"Current\s+cov\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*%", stdout, re.IGNORECASE)
            if m_current:
                try:
                    coverage_pct = float(m_current.group(1))
                except Exception:
                    coverage_pct = None

            m_max = re.search(r"Max\s+coverage\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*%", stdout, re.IGNORECASE)
            if m_max:
                try:
                    coverage_max = float(m_max.group(1))
                except Exception:
                    coverage_max = None

            return {
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "coverage_percent": coverage_pct,
                "coverage_max": coverage_max,
                "timestamp": time.time(),
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": f"Error: coverage run timed out after {self.coverage_timeout}s",
                "coverage_percent": None,
                "coverage_max": None,
                "timestamp": time.time(),
            }
        except Exception as e:
            return {
                "returncode": None,
                "stdout": "",
                "stderr": f"Error running coverage: {e}",   
                "coverage_percent": None,
                "coverage_max": None,
                "timestamp": time.time(),
            }

    def execute(self, payload: str, context: VulnerabilityContext, pseudo_path: Optional[str] = None, coverage_cwd: Optional[str] = None) -> dict:
        print(f"SIMULATING EXECUTION FOR PAYLOAD VIA LLM: '{payload}'")

        prompt = self._create_prompt(payload, context)
        llm_response = self.llm.generate_text(prompt, temperature=0.5)

        simulated_code = "// LLM failed to generate simulated code."
        simulated_execution_log = "Execution Log: LLM analysis failed or returned empty."

        if llm_response:
            parsed = self._parse_llm_json(llm_response)
            if parsed:
                simulated_code = parsed.get("simulated_code", simulated_code)
                simulated_execution_log = parsed.get("execution_log", simulated_execution_log)
            else:
                simulated_execution_log = llm_response.strip()

        coverage_result = self._run_coverage_process(payload, pseudo_path=pseudo_path, cwd=coverage_cwd)

        real_exec_log = coverage_result.get("stdout", "") or coverage_result.get("stderr", "")
        if not real_exec_log:
            real_exec_log = simulated_execution_log

        return {
            "simulated_code": simulated_code,
            "execution_log": real_exec_log,
            "coverage_result": coverage_result,
        }