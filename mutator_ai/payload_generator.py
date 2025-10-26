import re
from typing import Optional, List
from .llm_interface import LLMInterface
from .data_structures import VulnerabilityContext, AttackAttempt

class PayloadGenerator:
    def __init__(self, llm_interface: LLMInterface):
        self.llm = llm_interface

    def generate(
        self,
        context: VulnerabilityContext,
        previous_attempt: Optional[AttackAttempt] = None,
        coverage_rate: Optional[float] = None
    ) -> str:
        prompt = self._build_prompt(context, previous_attempt, coverage_rate)
        payload = self.llm.generate_text(prompt, temperature=0.4)
        return self._sanitize_payload(payload)

    def _sanitize_payload(self, payload: str) -> str:
        if not payload:
            return ""
        cleaned = payload.strip()
        # Remove surrounding quotes/backticks if they come in pairs
        for quote in ("```", "'''", '"""'):
            if cleaned.startswith(quote) and cleaned.endswith(quote):
                cleaned = cleaned[len(quote):-len(quote)].strip()
        if (cleaned.startswith("`") and cleaned.endswith("`")) or (cleaned.startswith("'") and cleaned.endswith("'")) or (cleaned.startswith('"') and cleaned.endswith('"')):
            cleaned = cleaned[1:-1].strip()
        # Collapse newlines
        cleaned = cleaned.replace("\r", "").strip()
        return cleaned

    def _build_prompt(
        self,
        context: VulnerabilityContext,
        previous_attempt: Optional[AttackAttempt],
        coverage_rate: Optional[float]
    ) -> str:
        param_names = self._extract_param_names(context)
        param_count = max(1, len(param_names))
        param_list = ", ".join(param_names) if param_names else "input"

        if param_count == 1:
            input_format_instruction = "Return a single string."
        else:
            input_format_instruction = f"Return exactly {param_count} arguments separated by '||' (e.g., arg1||arg2)."

        array_params = [name for name in param_names if self._param_expects_array(name)]
        array_instruction = ""
        if array_params:
            array_instruction = (
                f"\n- For array-like parameters ({', '.join(array_params)}), place a JSON array literal at that position (e.g., [\"-c\",\"echo hi\"])."
            )

        prompt = f"""You are an expert security researcher specializing in code analysis and exploit generation. Your task is to create a malicious input value that triggers a vulnerability.

[Vulnerability Analysis]
- Vulnerability Type: {context.known_weakness[0]}
- Language: {context.language}
- Sink Function: `{context.sink}` which is known to be vulnerable.
[Function Parameters]
- Parameters: {param_list}
- {input_format_instruction}{array_instruction}

[Code Analysis]
Here is the relevant code showing the data flow to the sink:
{context.code_context.get('before', '')}
// The vulnerable line is where the sink is called:
{context.code_context.get('sinkLine', '')}


If the code contains any input-filtering, sanitization, or validation logic, consider those checks and attempt to craft a payload that bypasses them (without producing destructive shell commands). If specific filter code is present in the provided snippets, reason about common bypass techniques relevant to the language and filter type and incorporate them into the payload.

"""

        if coverage_rate is not None:
            prompt += f"[Coverage Feedback]\n- Observed coverage rate from the last run: {coverage_rate}%\n\n"
        else:
            prompt += "[Coverage Feedback]\n- Observed coverage rate from the last run: unknown\n\n"

        prompt += """[Your Task]
1. Analyze the code to identify the entry point for user-controlled data (e.g., a function argument or variable).
2. Construct a malicious string that, when used as input, will exploit the '{context.known_weakness[0]}' vulnerability at the sink (`{context.sink}`).
3. The payload should be a single, simple string value designed to both trigger the vulnerability and, when possible, improve coverage of the vulnerable code paths.
4. If previous attempts produced partial coverage, prefer payloads that target uncovered branches or error-handling paths.
5. Do NOT include destructive system shell commands (e.g., 'rm -rf /') in the payload. Focus on exploit-triggering inputs that are safe to simulate.

"""

        if previous_attempt and not previous_attempt.is_successful:
            prev_cov = getattr(previous_attempt, "coverage", None)
            prompt += f"""[Previous Attempt Feedback]
The previous attempt failed.
- Previous Payload (Input String): {previous_attempt.payload}
- Previous Coverage: {prev_cov if prev_cov is not None else 'unknown'}
- Reason for failure: {previous_attempt.analysis_reason}

Analyze the failure and generate a new, improved malicious input string that addresses the observed failure reasons and attempts to increase coverage of the vulnerable code paths.
"""

        prompt += """
[Payload]
Based on your analysis, provide ONLY the malicious string input. Do not wrap it in code blocks or provide any explanation.
"""
        return prompt

    def _extract_param_names(self, context: VulnerabilityContext) -> List[str]:
        pseudocode = context.code_context.get("pseudocode", "") or ""
        function_name = context.function_name or ""
        if not pseudocode or not function_name:
            return []

        patterns = [
            rf"function\s+{re.escape(function_name)}\s*\(([^)]*)\)",
            rf"{re.escape(function_name)}\s*=\s*\(([^)]*)\)\s*=>",
        ]

        for pattern in patterns:
            match = re.search(pattern, pseudocode)
            if match:
                params = []
                for part in match.group(1).split(","):
                    param = part.strip()
                    if not param:
                        continue
                    param = param.split("=")[0].strip()
                    if param:
                        params.append(param)
                if params:
                    return params
        return []

    @staticmethod
    def _param_expects_array(name: str) -> bool:
        if not name:
            return False
        return bool(re.search(r"(args?|list|array|items|values|options|commands|parameters)", name, re.IGNORECASE))
