import json
import os
from typing import List, Dict, Any

def generate_markdown_report(json_file_paths: List[str], output_md_path: str) -> None:
    """여러 개의 JSON 결과 파일을 취합하여 하나의 Markdown 보고서를 생성합니다."""
    print(f"\n--- Generating report ---")
    
    report_parts = []
    
    for i, file_path in enumerate(json_file_paths):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            report_parts.append(f"# Vulnerability Report {i+1}")
            report_parts.append(_format_single_report(data))
        except (FileNotFoundError, json.JSONDecodeError) as e:
            report_parts.append(f"# Report for {os.path.basename(file_path)}")
            report_parts.append(f"*Could not process report file: {e}*")

    final_report = "\n\n---\n\n".join(report_parts)
    
    try:
        with open(output_md_path, 'w', encoding='utf-8') as f:
            f.write(final_report)
        print(f"Successfully generated final report: {output_md_path}")
    except Exception as e:
        print(f"Failed to write final report: {e}")

def _format_single_report(data: Dict[str, Any]) -> str:
    """MarkDown 형태로 결과를 반환."""
    parts = []
    context = data.get("vulnerability_context", {})
    
    # --- Summary ---
    parts.append("## 1. Vulnerability Summary")
    parts.append(f"- **Status:** `{data.get('status', 'UNKNOWN')}`")
    if data.get('status') == "SUCCESS":
        parts.append(f"- **Successful Payload:** `{data.get('successful_payload', 'Not found')}`")
    parts.append(f"- **Vulnerability Type:** {context.get('known_weakness', ['N/A'])[0]}")
    parts.append(f"- **Location:** `{context.get('file_path', 'N/A')} : {context.get('function_name', 'N/A')}`")
    parts.append(f"- **Sink:** `{context.get('sink', 'N/A')}`")

    # --- Code Context ---
    parts.append("## 2. Code Context")
    code_context = context.get('code_context', {})
    parts.append("### Sink Code")
    parts.append(f"```javascript\n{code_context.get('sinkLine', '// Not available')}\n```")
    parts.append("### Pseudocode for Fuzzing")
    parts.append(f"```javascript\n{code_context.get('pseudocode', '// Not available')}\n```")

    # --- Attack Attempts ---
    parts.append("## 3. Attack Simulation Details")
    attempts = data.get("attempts", [])
    if not attempts:
        parts.append("*No attack attempts were recorded.*")
    else:
        for i, attempt in enumerate(attempts):
            parts.append(f"### Attempt {i+1}")
            parts.append(f"- **Timestamp:** {attempt.get('timestamp')}")
            parts.append(f"- **Success:** {attempt.get('is_successful')}")
            parts.append(f"- **Payload:** `{attempt.get('payload')}`")
            parts.append("- **Reason for Failure:**")
            parts.append(f"```\n{attempt.get('analysis_reason', 'N/A')}\n```")
            
    return "\n".join(parts)
