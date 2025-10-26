import datetime
import json
import os
import re
import pathlib
import glob
from typing import Dict, Any, List, Optional

from .data_structures import VulnerabilityContext, AttackResult, AttackAttempt
from .llm_interface import LLMInterface
from .payload_generator import PayloadGenerator
from .result_analyzer import ResultAnalyzer
from .sandbox_executor import SandboxExecutor

class MutatorAIOrchestrator:
    def __init__(self, max_retries: int | None = None):
        self.max_retries = max_retries if max_retries is not None else int(os.getenv('MAX_RETRIES', 3))
        self.llm_interface = LLMInterface(api_key=os.getenv("LLM_API_KEY"))
        self.payload_generator = PayloadGenerator(self.llm_interface)
        self.result_analyzer = ResultAnalyzer(self.llm_interface)
        self.sandbox_executor = SandboxExecutor(self.llm_interface)

    def _infer_weakness(self, codes: Dict[str, str], flows: List[Any]) -> str:
        print("Inferring weakness from code context via LLM...")
        flow_description = ""
        if flows and flows[0]:
            flow_path = " -> ".join([step.get("function", "unknown") for step in flows[0]])
            flow_description = f"Data flow: {flow_path}"

        code_snippets = "\n---\n".join(codes.values())

        prompt = f"""
As a security analyst, analyze the following data flow and code snippets to determine the most likely security vulnerability.

[Data Flow]
{flow_description}

[Code Snippets]

[Task]
Based on the information, identify the specific type of security vulnerability.
Provide only the name of the vulnerability as a single short string (e.g., "SQL Injection", "Command Injection", "Cross-Site Scripting").
"""
        response = self.llm_interface.generate_text(prompt, temperature=0.1)
        inferred_weakness = response.strip()
        print(f"LLM inferred weakness: {inferred_weakness}")
        return inferred_weakness

    def _extract_codeblock_or_full(self, text: str) -> str:
        if not text:
            return ""
        m = re.search(r"```(?:[\w+\-]*)\n([\s\S]*?)```", text)
        if m:
            return m.group(1).strip()
        return text.strip()

    def _generate_pseudocode_via_llm(self, codes: Dict[str, str], flows: List[Any], file_path: str, language_hint: str) -> str:
        flow_lines = []
        if flows and flows[0]:
            for step in flows[0]:
                fn = step.get("function", "<unknown>")
                sid = step.get("id", "")
                line = step.get("line", "")
                flow_lines.append(f"- function: {fn}, id: {sid}, line: {line}")
        flow_description = "\n".join(flow_lines) if flow_lines else "No flow information available."

        snippet_pairs = []
        for k, v in codes.items():
            header = f"/* snippet id={k} */"
            snippet_pairs.append(header + "\n" + v)
        snippets_text = "\n\n".join(snippet_pairs)

        ext = pathlib.Path(file_path).suffix or ""
        ext = ext.lstrip(".")
        lang = language_hint or ext or "unknown"

        prompt = f"""You are an expert at writing concise, human-readable pseudocode for security analysis based on code snippets and their flow.
Generate a single pseudocode file that captures the high-level behavior and data flow of the provided code pieces.
Do not include destructive or executable shell commands. Keep variable names readable, and preserve the original values of long literals or variables. If the original values are unknown, use arbitrary values matching the original data types. Focus on control flow and data movement.

[Flow]
{flow_description}

[Code snippets with IDs]
{snippets_text}

[Output requirements]

Output only the pseudocode file content, with no additional explanations.

If possible, format it in the style of the original language, using function-like structures.

**CRITICAL**: If a function is called that is not defined in the snippets (e.g., `sink2`), you MUST create an empty stub function for it to prevent crashes. For example: `function sink2(data) {{ /* Do nothing */ }}`.

**Important**: If the code uses functions from built-in Node.js modules (e.g., `exec` from `child_process`), you MUST include the necessary `require` statement at the top of the script. For example: `const {{ exec }} = require('child_process');`.

Do not include comments.

This pseudocode is intended for coverage measurement, so only extract code related to vulnerable functions from the original. Write it as faithfully as possible to the original style.

if original code's extension is ".ts" make convert to ".js" and save.

Also, for the functions generated in the pseudocode like this, be sure to export them using module.exports.
"""
        resp = self.llm_interface.generate_text(prompt, temperature=0.2)
        pseudocode = self._extract_codeblock_or_full(resp)
        return pseudocode

    def _parse_libspear_input(self, libspear_json: Dict[str, Any]) -> VulnerabilityContext:
        sink_info = libspear_json.get("sink", {})
        flows = libspear_json.get("flows", [])
        codes = libspear_json.get("codes", {})

        inferred_weakness = self._infer_weakness(codes, flows)

        project_name = "UnknownProject"
        language = "unknown"
        file_path = sink_info.get("filename", "")
        if file_path:
            try:
                project_name = file_path.split('/')[-1].split('.')[0]
                extension = file_path.split('.')[-1]
                lang_map = {'ts': 'typescript', 'js': 'javascript', 'java': 'java', 'py': 'python'}
                if extension in lang_map:
                    language = lang_map[extension]
                else:
                    language = extension
            except IndexError:
                pass

        function_name = ""
        function_line = 0
        if flows and flows[0]:
            relevant_step = flows[0][-2] if len(flows[0]) > 1 else flows[0][-1]
            function_name = relevant_step.get("function", "unknown_function")
            function_line = relevant_step.get("line", 0)

        sink_code = codes.get(str(sink_info.get("id", "")), "")
        before_code_parts = []
        if flows and flows[0]:
            for step in flows[0]:
                sid = step.get("id")
                if sid is None:
                    continue
                sid_str = str(sid)
                if sid_str in codes and sid_str != str(sink_info.get("id", "")):
                    before_code_parts.append(codes[sid_str])
        before_code = "\n".join(before_code_parts)

        pseudocode = ""
        try:
            pseudocode = self._generate_pseudocode_via_llm(codes, flows, file_path or "unknown", language)
        except Exception as e:
            print(f"Failed to generate pseudocode via LLM: {e}")
            pseudocode = ""

        return VulnerabilityContext(
            project=project_name,
            language=language,
            file_path=file_path,
            function_name=function_name,
            sink=sink_info.get("name", ""),
            sink_id=str(sink_info.get("id", "")),
            known_weakness=[inferred_weakness],
            code_context={"before": before_code, "sinkLine": sink_code, "after": "", "pseudocode": pseudocode}
        )

    def _save_pseudocode_file(self, context: VulnerabilityContext) -> Optional[str]:
        pseudo_code = context.code_context.get('pseudocode', '')
        if not pseudo_code:
            return None
        original_file_path = context.file_path or "unknown"
        original_path = pathlib.Path(original_file_path)
        original_filename = original_path.name or "unknown"
        stem = original_path.stem or original_filename
        ext = original_path.suffix.lower().lstrip(".")

        # 파일명 결정: 원본이 .ts이면 반드시 .js로 저장 (P_<stem>_<sink_id>.js)
        if ext == "ts":
            pseudo_filename = f"P_{stem}_{context.sink_id}.js"
        else:
            pseudo_filename = f"P_{original_filename}_{context.sink_id}"

        pseudo_folder_name = os.getenv("TARGET_DIR", "P_TARGET")
        pseudo_folder = pathlib.Path(pseudo_folder_name)
        try:
            pseudo_folder.mkdir(parents=True, exist_ok=True)
            pseudo_file_path = pseudo_folder / pseudo_filename
            with open(pseudo_file_path, "w", encoding="utf-8") as f:
                f.write(pseudo_code)
            print(f"Pseudocode saved to {pseudo_file_path}")
            self._create_seed_file(context, pseudo_file_path)
            return str(pseudo_file_path)
        except Exception as e:
            print(f"Failed to save pseudocode file: {e}")
            return None

    def _create_seed_file(self, context: VulnerabilityContext, pseudo_file_path: pathlib.Path) -> Optional[str]:
        param_names = self._extract_parameter_names(context)
        param_count = max(1, len(param_names))
        seed_content = self._generate_seed_via_llm(context, param_names)
        if not seed_content:
            seed_content = self._determine_seed_content(context, param_names)
        if not seed_content:
            return None

        seed_filename = f"seed_{pseudo_file_path.stem}.txt"
        seed_path = pseudo_file_path.with_name(seed_filename)
        try:
            with open(seed_path, "w", encoding="utf-8") as seed_file:
                seed_file.write(seed_content)
            print(f"Seed input saved to {seed_path}")
            return str(seed_path)
        except OSError as e:
            print(f"Failed to write seed file: {e}")
            return None

    def _generate_seed_via_llm(self, context: VulnerabilityContext, param_names: List[str]) -> Optional[str]:
        param_count = max(1, len(param_names))
        pseudo = context.code_context.get("pseudocode", "")
        weakness = ", ".join(context.known_weakness or [])
        function_name = context.function_name or "unknown_function"

        if param_count == 1:
            param_instructions = "Provide a single string input."
        else:
            param_instructions = f"Provide exactly {param_count} arguments separated by '||' (e.g., value1||value2||value3)."

        param_list = ", ".join(param_names) if param_names else "input"
        array_params = [name for name in param_names if self._param_expects_array(name)]
        array_instruction = ""
        if array_params:
            array_instruction = (
                "\n4. For parameters likely expecting arrays "
                f"({', '.join(array_params)}), emit a JSON array literal in that position (e.g., [\"-c\",\"echo ok\"])."
            )

        prompt = f"""
You are assisting with security fuzzing.
We need an initial input seed that is likely to explore the vulnerability.

- Vulnerability Type(s): {weakness or "unknown"}
- Target Function: {function_name}
- Parameters: {param_list}
- Code Snippet:
{pseudo}

Rules:
1. {param_instructions}
2. Avoid placeholders like 'input' or 'test'; use meaningful values.
3. Do not add explanations or quotes, return only the raw payload text.{array_instruction}
"""
        try:
            response = self.llm_interface.generate_text(prompt, temperature=0.2)
            seed = self._extract_codeblock_or_full(response).strip()
            if seed:
                return seed
        except Exception as e:
            print(f"Failed to get seed from LLM: {e}")
        return None

    def _determine_seed_content(self, context: VulnerabilityContext, param_names: List[str]) -> Optional[str]:
        if not param_names:
            return "fuzz-input"

        tokens = []
        for idx, name in enumerate(param_names):
            if self._param_expects_array(name):
                tokens.append(f'["arg{idx+1}"]')
            else:
                tokens.append(f"arg{idx+1}")

        if len(tokens) == 1:
            return tokens[0]
        return "||".join(tokens)

    def _extract_parameter_names(self, context: VulnerabilityContext) -> List[str]:
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

    def _cleanup_corpus(self):
        corpus_dir_name = os.getenv("CORPUS_DIR", "coverage/corpus")
        corpus_dir = pathlib.Path(corpus_dir_name)
        if corpus_dir.exists():
            for f in corpus_dir.glob("crash_*.json"):
                try:
                    f.unlink()
                except OSError as e:
                    print(f"Error removing file {f}: {e}")

    @staticmethod
    def _normalize_coverage(value: Any) -> float:
        if value is None:
            return 0.0
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def run_attack_simulation(self, libspear_json: Dict[str, Any], out_path: Optional[str] = None) -> AttackResult:
        self._cleanup_corpus()
        context = self._parse_libspear_input(libspear_json)
        pseudo_path = self._save_pseudocode_file(context)

        result = AttackResult(vulnerability_context=context, status="PENDING")
        last_attempt = None
        last_coverage = None

        for i in range(self.max_retries):
            print(f"\n--- ATTEMPT {i+1}/{self.max_retries} ---")
            payload = self.payload_generator.generate(context, last_attempt, coverage_rate=last_coverage)
            
            crash_files_before = set(glob.glob("coverage/corpus/crash_*.json"))

            sim_result = self.sandbox_executor.execute(payload, context, pseudo_path=pseudo_path)
            
            crash_files_after = set(glob.glob("coverage/corpus/crash_*.json"))
            new_crash_files = crash_files_after - crash_files_before

            coverage_result = sim_result.get("coverage_result", {})
            stderr = coverage_result.get("stderr", "").strip()
            
            is_successful = not stderr and not new_crash_files
            analysis_reason = "Execution successful with no stderr and no new crashes."

            if stderr:
                analysis_reason = f"Execution failed with stderr: {stderr}"
            elif new_crash_files:
                try:
                    latest_crash_file = max(new_crash_files, key=os.path.getctime)
                    with open(latest_crash_file, 'r') as f:
                        crash_data = json.load(f)
                    crash_info = crash_data.get("crashInfo", {})
                    func_name = crash_info.get("func", "unknown")
                    error_message = crash_info.get("message", "unknown")
                    analysis_reason = f"Fuzzer reported a crash in function '{func_name}': {error_message}"
                except Exception as e:
                    analysis_reason = f"Fuzzer reported a crash, but could not read details: {e}"

            last_coverage = self._normalize_coverage(coverage_result.get("coverage_percent"))

            attempt = AttackAttempt(
                payload=payload,
                timestamp=datetime.datetime.now().isoformat(),
                is_successful=is_successful,
                execution_log=sim_result.get("execution_log", ""),
                analysis_reason=analysis_reason,
                simulated_code=sim_result.get("simulated_code", "// Code not generated."),
                coverage_percent=last_coverage
            )
            result.attempts.append(attempt)

            if attempt.is_successful:
                print(f"SUCCESS! Reason: {attempt.analysis_reason}")
                result.status = "SUCCESS"
                result.successful_payload = payload
                break
            else:
                print(f"FAILED. Reason: {attempt.analysis_reason}")
                last_attempt = attempt

        if result.status != "SUCCESS":
            result.status = "FAILED_MAX_RETRIES"
            print("\n--- Attack Simulation FAILED after max retries ---")

        self.save_report(result, out_path=out_path)
        return result

    async def run_interactive_simulation(self, libspear_json: Dict[str, Any], out_path: Optional[str] = None) -> AttackResult:
        self._cleanup_corpus()
        context = self._parse_libspear_input(libspear_json)
        pseudo_path = self._save_pseudocode_file(context)

        result = AttackResult(vulnerability_context=context, status="PENDING")
        last_attempt = None
        max_coverage = 0.0
        attempt_count = 0

        while True:
            attempt_count += 1
            print(f"\n--- INTERACTIVE ATTEMPT {attempt_count} ---")

            current_coverage_percent = self._normalize_coverage(last_attempt.coverage_percent if last_attempt else 0.0)

            payload = self.payload_generator.generate(context, last_attempt, coverage_rate=current_coverage_percent)

            crash_files_before = set(glob.glob("coverage/corpus/crash_*.json"))
            corpus_files_before = set(glob.glob("coverage/corpus/*.js"))

            sim_result = self.sandbox_executor.execute(payload, context, pseudo_path=pseudo_path)

            crash_files_after = set(glob.glob("coverage/corpus/crash_*.json"))
            new_crash_files = crash_files_after - crash_files_before
            
            corpus_files_after = set(glob.glob("coverage/corpus/*.js"))
            new_corpus_files = corpus_files_after - corpus_files_before

            coverage_result = sim_result.get("coverage_result", {})
            stderr = coverage_result.get("stderr", "").strip()
            
            is_successful = not stderr and not new_crash_files
            analysis_reason = "Execution successful with no stderr and no new crashes."

            if stderr:
                analysis_reason = f"Execution failed with stderr: {stderr}"
            elif new_crash_files:
                try:
                    latest_crash_file = max(new_crash_files, key=os.path.getctime)
                    with open(latest_crash_file, 'r') as f:
                        crash_data = json.load(f)
                    crash_info = crash_data.get("crashInfo", {})
                    func_name = crash_info.get("func", "unknown")
                    error_message = crash_info.get("message", "unknown")
                    analysis_reason = f"Fuzzer reported a crash in function '{func_name}': {error_message}"
                except Exception as e:
                    analysis_reason = f"Fuzzer reported a crash, but could not read details: {e}"

            current_coverage_percent = self._normalize_coverage(coverage_result.get("coverage_percent"))
            max_coverage = max(max_coverage, current_coverage_percent)

            attempt = AttackAttempt(
                payload=payload,
                timestamp=datetime.datetime.now().isoformat(),
                is_successful=is_successful,
                execution_log=sim_result.get("execution_log", ""),
                analysis_reason=analysis_reason,
                simulated_code=sim_result.get("simulated_code", "// Code not generated."),
                coverage_percent=current_coverage_percent
            )
            result.attempts.append(attempt)

            print(f"ATTEMPT {attempt_count} ANALYSIS: {attempt.analysis_reason}")
            last_attempt = attempt

            # AI decision making
            continue_fuzzing = await self._decide_next_step(result, max_coverage, new_corpus_files, new_crash_files)
            if not continue_fuzzing:

                if attempt.is_successful:
                    result.status = "SUCCESS_CONFIRMED_BY_AI"
                    result.successful_payload = payload
                    print("\n--- Attack confirmed as SUCCESSFUL by AI ---")
                else:
                    result.status = "STOPPED_BY_AI"
                    print("\n--- Fuzzing session stopped by AI decision ---")
                break

        if result.status == "PENDING":
            result.status = "UNKNOWN_REASON"

        self.save_report(result, out_path=out_path)
        return result

    async def _decide_next_step(self, current_result: AttackResult, max_coverage: float, new_corpus_files: set, new_crash_files: set) -> bool:
        print("\n--- AI Decision Point ---")
        last_attempt = current_result.attempts[-1]
        attempt_coverage = self._normalize_coverage(last_attempt.coverage_percent)
        max_coverage = self._normalize_coverage(max_coverage)

        summary = f"""
        Fuzzing Status Summary:
        - Total Attempts: {len(current_result.attempts)}
        - Last Payload: `{last_attempt.payload}`
        - Last Result: {'FAILED' if not last_attempt.is_successful else 'SUCCESS'}
        - Reason: {last_attempt.analysis_reason}
        - Current Coverage: {attempt_coverage:.2f}%
        - Max Coverage Achieved: {max_coverage:.2f}%
        - New Corpus Files Found: {len(new_corpus_files)} ({list(new_corpus_files)})
        - New Crashes Found: {len(new_crash_files)}
        """

        prompt = f"""
        You are a security testing AI controlling a fuzzing loop.
        Based on the summary below, should you continue fuzzing or stop?

        {summary}

        [Decision Criteria]
        - STOP if you are confident the vulnerability has been successfully exploited (e.g., a crash indicates a potential exploit).
        - STOP if you are stuck in a loop with no new coverage or findings for several attempts.
        - CONTINUE if you are making progress (new coverage, new corpus files) or if you have a new strategy to try.

        [Your Decision]
        Respond with a single word: `CONTINUE` or `STOP`.
        """
        print(summary)
        print("Asking AI for next step...")

        response = self.llm_interface.generate_text(prompt, temperature=0.2)
        decision = response.strip().upper()

        print(f"AI decision: {decision}")
        return "CONTINUE" in decision

    def save_report(self, result: AttackResult, out_path: Optional[str] = None) -> None:
        if out_path is None:
            prefix = os.getenv("MUTATOR_OUTPUT_PREFIX", "report_index_mid")
            out_path = f"{prefix}.json"

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "status": result.status,
                    "successful_payload": getattr(result, "successful_payload", None),
                    "attempts": [a.__dict__ for a in result.attempts],
                    "vulnerability_context": {
                        "project": result.vulnerability_context.project,
                        "language": result.vulnerability_context.language,
                        "file_path": result.vulnerability_context.file_path,
                        "function_name": result.vulnerability_context.function_name,
                        "sink": result.vulnerability_context.sink,
                        "sink_id": result.vulnerability_context.sink_id,
                        "known_weakness": result.vulnerability_context.known_weakness,
                        "code_context": result.vulnerability_context.code_context,
                    }
                }, f, ensure_ascii=False, indent=2)
            print(f"Report saved to {out_path}")
        except Exception as e:
            print(f"Failed to save report: {e}")
