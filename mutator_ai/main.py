import json
import os
from dotenv import load_dotenv
from mutator_ai.orchestrator import MutatorAIOrchestrator

def main():
    """메인 실행 함수"""
    load_dotenv()

    report_dir = os.getenv("REPORT_DIR", "report")
    input_file = os.path.join(report_dir, "report.json")
    output_prefix = os.getenv("MUTATOR_OUTPUT_PREFIX", "report_index_mid")

    print(f"Loading analysis results from {input_file}...")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            libspear_input_json = json.load(f)
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {input_file}.")
        return

    print("Starting Mutator AI Attack Simulation...")
    orchestrator = MutatorAIOrchestrator()

    if isinstance(libspear_input_json, list) and libspear_input_json:
        reports_list = libspear_input_json[0].get("reports", [])
        for i, report in enumerate(reports_list):
            print(f"\n--- Processing Report {i+1}/{len(reports_list)} ---")
            output_file = f"{output_prefix}_{i+1}.json"
            final_result = orchestrator.run_attack_simulation(report, out_path=output_file)
    
            print("\n--- SIMULATION COMPLETE ---")
            print(f"Final Status: {final_result.status}")
            if final_result.successful_payload:
                print(f"Successful Payload: {final_result.successful_payload}")

    else:
        final_result = orchestrator.run_attack_simulation(libspear_input_json)
        print("\n--- SIMULATION COMPLETE ---")
        print(f"Final Status: {final_result.status}")
        if final_result.successful_payload:
            print(f"Successful Payload: {final_result.successful_payload}")

if __name__ == "__main__":
    main()
