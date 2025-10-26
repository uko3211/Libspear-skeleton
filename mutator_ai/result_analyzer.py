import json
import re
from typing import Dict, Any
from .llm_interface import LLMInterface
from .data_structures import VulnerabilityContext

class ResultAnalyzer:
    """실행 결과 로그를 분석"""
    def __init__(self, llm_interface: LLMInterface):
        self.llm = llm_interface

    def analyze(self, payload: str, log: str, context: VulnerabilityContext) -> Dict[str, Any]:
        """로그를 분석하여 성공/실패 및 원인 반환"""
        prompt = self._build_prompt(payload, log, context)
        response_text = self.llm.generate_text(prompt, temperature=0.1)
        
        # LLM 응답에서 JSON 마크다운 블록을 추출하는 로직 추가
        cleaned_json = self._extract_json(response_text)
        
        if not cleaned_json:
            return {"success": False, "reason": "Failed to extract JSON from LLM response."}

        try:
            return json.loads(cleaned_json)
        except json.JSONDecodeError:
            return {"success": False, "reason": f"Failed to parse extracted JSON: {cleaned_json}"}

    def _build_prompt(self, payload: str, log: str, context: VulnerabilityContext) -> str:
        return f"""
        You are a security analyst. Your task is to determine if an attack payload successfully exploited a vulnerability based on the execution log.

        [Vulnerability Context]
        - Weakness: {context.known_weakness}
        - Target File: {context.file_path}

        [Attack Details]
        - Payload:
        '''
        {payload}
        '''
        - Execution Log:
        '''
        {log}
        '''

        [Analysis Instruction]
        1.  Analyze the payload and the resulting log.
        2.  Determine if the payload successfully exploited the vulnerability. A success means a clear sign of exploitation (e.g., auth bypass, data leakage like 'admin', 'user list', timeout for blind SQLi). A failure shows a syntax error, no effect, or a generic error message.
        3.  Provide your analysis ONLY in a compact JSON format with two keys: "success" (boolean: true for success, false for failure) and "reason" (a brief, one-sentence explanation of your decision).

        Example successful response:
        ```json
        {{
          "success": true,
          "reason": "The log indicates a successful login bypass, authenticating the user as admin."
        }}
        ```

        Example failed response:
        ```json
        {{
          "success": false,
          "reason": "The log shows a SQL syntax error, indicating the payload failed to execute correctly."
        }}
        ```

        Your JSON response:
        """

    def _extract_json(self, text: str) -> str:
        """응답에서 JSON 코드 블록을 추출"""
        # ```json ... ``` 패턴 찾기
        match = re.search(r"```json\n({.*?})\n```", text, re.DOTALL)
        if match:
            return match.group(1)
        
        # ``` ... ``` 패턴 찾기
        match = re.search(r"```\n({.*?})\n```", text, re.DOTALL)
        if match:
            return match.group(1)

        # JSON 객체가 직접 있는 경우 찾기
        match = re.search(r"({.*?})", text, re.DOTALL)
        if match:
            return match.group(1)

        return text # 못찾으면 원본 텍스트 반환