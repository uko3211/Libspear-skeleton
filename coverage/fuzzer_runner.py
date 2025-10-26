import os
import subprocess
import argparse
from dotenv import load_dotenv
from coverage.coverage_module import CovChecker

load_dotenv()

TARGET_DIR = os.getenv("TARGET_DIR")
FUZZER_JS = os.path.join(os.path.dirname(__file__), "core", "fuzzer_interface.js")
MUTATOR_PY = os.path.join(os.path.dirname(__file__), "core", "mutator.py")

def run_batch_fuzzing(js_files, max_iterations=1000):
    for js_file in js_files:
        print(f"Batch fuzzing {js_file}")

        seed_file = None
        base_name = os.path.splitext(os.path.basename(js_file))[0]
        specific_seed = os.path.join(os.path.dirname(js_file), f"seed_{base_name}.txt")
        default_seed = os.path.join(os.path.dirname(js_file), "seed.txt")
        if os.path.exists(specific_seed):
            seed_file = specific_seed
        elif os.path.exists(default_seed):
            seed_file = default_seed

        args = ["node", FUZZER_JS, js_file, MUTATOR_PY, "--batch", str(max_iterations)]
        if seed_file:
            args.append(seed_file)

        subprocess.run(args)

def run_interactive_fuzzing(js_files):
    if len(js_files) > 1:
        print("[INFO] - 대화형 모드에서는 한 번에 하나의 파일만 테스트할 수 있습니다.")
        for i, js_file in enumerate(js_files, 1):
            print(f"  {i}. {js_file}")
        
        while True:
            try:
                choice = int(input("[INFO] - 테스트할 파일 번호를 선택하세요: ")) - 1
                if 0 <= choice < len(js_files):
                    js_file = js_files[choice]
                    break
                else:
                    print("[WARN] - 잘못된 번호입니다.")
            except ValueError:
                print("[INFO] - 숫자를 입력해주세요.")
    else:
        js_file = js_files[0]

    print(f"\n대화형 퍼징 시작: {js_file}")
    print("Ctrl+C로 종료할 수 있습니다.")

    seed_file = None
    base_name = os.path.splitext(os.path.basename(js_file))[0]
    specific_seed = os.path.join(os.path.dirname(js_file), f"seed_{base_name}.txt")
    default_seed = os.path.join(os.path.dirname(js_file), "seed.txt")
    if os.path.exists(specific_seed):
        seed_file = specific_seed
    elif os.path.exists(default_seed):
        seed_file = default_seed

    args = ["node", FUZZER_JS, js_file, MUTATOR_PY, "--interactive"]
    if seed_file:
        args.append(seed_file)

    subprocess.run(args)

def main():
    parser = argparse.ArgumentParser(description="JavaScript Fuzzing Tool")
    parser.add_argument("--mode", choices=["batch", "interactive"], 
                       default="batch", help="퍼징 모드 선택")
    parser.add_argument("--iterations", type=int, default=1000,
                       help="배치 모드에서 실행할 반복 횟수")
    parser.add_argument("--file", type=str, help="특정 파일만 테스트")
    
    args = parser.parse_args()

    if not TARGET_DIR:
        print("[ERR] - TARGET_DIR이 설정되지 않았습니다. .env 파일을 확인해주세요.")
        return

    cov_checker = CovChecker(TARGET_DIR)
    js_files = cov_checker.js_file_path()

    if not js_files:
        print("[WARN] - 테스트할 JavaScript 파일을 찾을 수 없습니다.")
        return

    if args.file:
        js_files = [f for f in js_files if args.file in f]
        if not js_files:
            print(f"[WARN] - '{args.file}'과 일치하는 파일을 찾을 수 없습니다.")
            return

    print(f"[INFO] - 발견된 JavaScript 파일: {len(js_files)}개")
    for js_file in js_files:
        print(f"  - {js_file}")

    if args.mode == "batch":
        run_batch_fuzzing(js_files, args.iterations)
    elif args.mode == "interactive":
        run_interactive_fuzzing(js_files)

if __name__ == "__main__":
    main()
