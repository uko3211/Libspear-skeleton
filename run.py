import asyncio
import json
import os
from dotenv import load_dotenv
from joern.joern import Joern
from mutator_ai.orchestrator import MutatorAIOrchestrator
from mutator_ai.vul_report import generate_markdown_report

async def run_joern():
    """Joern을 실행하여 report.json을 생성합니다."""
    print("--- Starting Joern Analysis ---")
    try:
        joern_host = os.getenv("JOERN_HOST", "localhost:8080")
        joern_user = os.getenv("JOERN_USER", "admin")
        joern_pass = os.getenv("JOERN_PASS", "admin")
        import_path = os.getenv("JOERN_IMPORT_PATH", "/TARGET")
        rules_path = os.getenv("JOERN_RULES_PATH", "/rules/test.scala")
        project_name = os.getenv("JOERN_PROJECT_NAME", "test_project")
        report_dir = os.getenv("REPORT_DIR", "report")
        report_path = os.path.join(report_dir, "report.json")

        os.makedirs(report_dir, exist_ok=True)

        joern = Joern(joern_host, joern_user, joern_pass)
        await joern.import_code(input_path=import_path, project_name=project_name)
        await joern.client.q(f':load {rules_path}')
        res = await joern.client.q('ReportGenerator.run()')
        await joern.delete(project_name)
        with open(report_path, 'w') as f:
            json.dump(res, f, indent=4)
        print(f"--- Joern Analysis Finished, report saved to {report_path} ---")
    except Exception as e:
        print(f"An error occurred during Joern analysis: {e}")
        return False
    return True

def run_mutator_ai():
    """Joern 분석 결과를 바탕으로 Mutator AI를 실행하고, 결과 파일 목록을 반환합니다."""
    print("\n--- Starting Mutator AI ---")
    load_dotenv()

    report_dir = os.getenv("REPORT_DIR", "report")
    input_file = os.path.join(report_dir, "report.json")
    output_prefix = os.getenv("MUTATOR_OUTPUT_PREFIX", "report_index_mid")
    generated_files = []

    print(f"Loading analysis results from {input_file}...")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            libspear_input_json = json.load(f)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please ensure the file exists.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {input_file}.")
        return None

    print("Starting Mutator AI Attack Simulation...")
    orchestrator = MutatorAIOrchestrator()

    if isinstance(libspear_input_json, list) and libspear_input_json:
        reports_list = libspear_input_json[0].get("reports", [])
        for i, report in enumerate(reports_list):
            print(f"\n--- Processing Report {i+1}/{len(reports_list)} ---")
            output_file = f"{output_prefix}_{i+1}.json"
            final_result = orchestrator.run_attack_simulation(report, out_path=output_file)
            generated_files.append(output_file)
    
            print("\n--- SIMULATION COMPLETE ---")
            print(f"Final Status: {final_result.status}")
            if final_result.successful_payload:
                print(f"Successful Payload: {final_result.successful_payload}")

    else:
        output_file = f"{output_prefix}.json"
        final_result = orchestrator.run_attack_simulation(libspear_input_json, out_path=output_file)
        generated_files.append(output_file)
        print("\n--- SIMULATION COMPLETE ---")
        print(f"Final Status: {final_result.status}")
        if final_result.successful_payload:
            print(f"Successful Payload: {final_result.successful_payload}")
            
    return generated_files

async def run_batch_mode():
    """배치 모드로 전체 파이프라인을 실행합니다."""
    if await run_joern():
        generated_reports = run_mutator_ai()
        if generated_reports:
            should_generate_report = os.getenv("GENERATE_FINAL_REPORT", "true").lower() == "true"
            if should_generate_report:
                generate_markdown_report(generated_reports, "Vulnerability_Report.md")

async def run_interactive_mode():
    """대화형 모드로 Mutator AI를 실행합니다."""
    if not await run_joern():
        print("Halting due to Joern analysis failure.")
        return

    print("\n--- Starting Mutator AI in Interactive Mode ---")
    load_dotenv()

    report_dir = os.getenv("REPORT_DIR", "report")
    input_file = os.path.join(report_dir, "report.json")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            libspear_input_json = json.load(f)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run Joern analysis first.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {input_file}.")
        return

    orchestrator = MutatorAIOrchestrator()
    
    if isinstance(libspear_input_json, list) and libspear_input_json:
        reports_list = libspear_input_json[0].get("reports", [])
        if not reports_list:
            print("No reports found in the input file.")
            return
        
        print("Please select a vulnerability to test:")
        for i, report in enumerate(reports_list):
            sink = report.get("sink", {})
            print(f"  {i+1}: {sink.get('name')} in {sink.get('filename')}:{sink.get('line')}")

        while True:
            selection_input = input(f"Enter numbers (e.g., 1,3,5) or 'all' (1-{len(reports_list)}): ").strip().lower()
            
            if selection_input == "all":
                indices_to_process = list(range(len(reports_list)))
                break
            else:
                try:
                    selected_numbers = [int(s.strip()) for s in selection_input.split(',')]
                    indices_to_process = []
                    for num in selected_numbers:
                        if 1 <= num <= len(reports_list):
                            indices_to_process.append(num - 1) 
                        else:
                            print(f"Invalid number: {num}. Please enter numbers between 1 and {len(reports_list)}).")
                            indices_to_process = [] 
                            break
                    if indices_to_process: 
                        break
                except ValueError:
                    print("Invalid input. Please enter comma-separated numbers or 'all'.")

        for index in indices_to_process:
            report_to_process = reports_list[index]
            output_file = f"interactive_report_{index+1}.json" # output file name
            
            final_result = await orchestrator.run_interactive_simulation(report_to_process, out_path=output_file)
            
            print(f"\n--- INTERACTIVE SIMULATION COMPLETE for report {index+1} ---")
            print(f"Final Status: {final_result.status}")
            if final_result.successful_payload:
                print(f"Successful Payload: {final_result.successful_payload}")
                
            should_generate_report = os.getenv("GENERATE_FINAL_REPORT", "true").lower() == "true"
            if should_generate_report:
                generate_markdown_report([output_file], f"Vulnerability_Report_Interactive_{index+1}.md")

    else:
        print("Unsupported report format for interactive mode.")


async def main():
    """스크립트 메인 진입점"""
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Run Mutator AI Fuzzer.")
    parser.add_argument(
        '--mode',
        type=str,
        choices=['batch', 'interactive'],
        default='batch',
        help='Execution mode: "batch" for automated runs, "interactive" for AI-driven session.'
    )
    args = parser.parse_args()

    if args.mode == 'interactive':
        await run_interactive_mode()
    else: # batch
        await run_batch_mode()

if __name__ == "__main__":
    import argparse
    asyncio.run(main())
