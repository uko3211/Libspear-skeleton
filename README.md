# Libspear

## 1. 개요

`Libspear`는 정적 분석 도구(Joern)를 통해 발견된 타겟 소스코드의 sink 함수 정보를 바탕으로, LLM(대규모 언어 모델)을 사용하여 실제 공격 페이로드를 자동으로 생성하고, **퍼징(Fuzzing)을 통해** 취약점의 유효성을 검증하는 시스템입니다.

이 시스템은 `Joern 분석 -> AI 기반 취약점 추론 -> 페이로드 생성 -> 샌드박스 실행 및 커버리지 측정 -> 결과 분석 -> 피드백`으로 이어지는 전체 과정을 하나로 통합한 파이프라인을 제공합니다.

## 2. 주요 기능


- **AI 기반 취약점 추론**: 데이터 흐름 및 코드 스니펫을 분석하여 Command Injection과 같은 보안 취약점을 자동으로 식별합니다.

- **자동 의사 코드 생성**: 분석된 코드를 바탕으로 테스트 및 커버리지 측정을 위한 실행 가능한 의사 코드(Javascript)를 생성합니다.

- **지능형 페이로드 생성**: 식별된 취약점과 이전 공격 시도의 피드백(크래시 정보, 커버리지)을 바탕으로 지능적으로 다음 공격 페이로드를 생성합니다.

- **취약점 트리거**: 생성된 페이로드를 실제로 실행하고, 커버리지를 측정하며 성공 여부를 분석합니다.

- **보고서 생성**: 모든 분석 및 시뮬레이션 결과를 종합하여 Markdown 형식의 최종 보고서를 생성합니다.

## 3. 프로젝트 구조

<img width="898" height="677" alt="libspear2" src="https://github.com/user-attachments/assets/2776068d-4f23-4d38-8d31-6c3c5306e6c8" />

## 4. 설치 및 설정

1.  **필요 도구 설치 및 실행**
    
```batch
python3 run.py 3 rude b --mode interactive
```
interactive
python3 run.py --mode interactive
```
    
    **또한, Joern 서버가 실행 중이어야 합니다.** (예: `docker-compose up -d`)

2.  **환경 변수 설정 (`.env`)**

    프로젝트 루트에 `.env` 파일을 생성하고, 다음과 같이 자신의 환경에 맞게 값을 설정합니다. (경로는 기본 값으로 설정되어 있습니다.)

    ```dotenv
    # .env
    # OpenAI API 키를 입력하세요.
    LLM_API_KEY="YOUR_OPENAI_API_KEY"

    # 최대 재시도 횟수
    MAX_RETRIES=3

    # 사용할 OpenAI 모델 이름 (예: gpt-4o, gpt-4-turbo)
    OPENAI_MODEL="gpt-4o"

    # --- Joern Settings ---
    JOERN_HOST=localhost:8080
    JOERN_USER=admin
    JOERN_PASS=admin
    JOERN_IMPORT_PATH=/TARGET
    JOERN_RULES_PATH=/rules/test.scala
    JOERN_PROJECT_NAME=test_project

    # --- Directory and Path Settings ---
    # 커버리지 측정 대상 디렉터리 (수정하지 마세요)
    TARGET_DIR="P_TARGET"
    REPORT_DIR=report
    CORPUS_DIR=coverage/corpus

    # --- Output Settings ---
    MUTATOR_OUTPUT_PREFIX=report_index_mid
    # 최종 Markdown 보고서 생성 여부 (true/false)
    GENERATE_FINAL_REPORT=true
    ```

## 5. 실행 방법

모든 설정이 완료되면, 프로젝트 루트 디렉토리에서 다음 명령어를 통해 프로그램을 시작합니다.

```bash
python3 run.py
```

실행이 완료되면, 시뮬레이션 중간 결과물인 `interactive_report_*.json` 파일들과 함께, 최종적으로 분석 내용이 정리된 **`Vulnerability_Report.md`** 파일이 루트 디렉토리에 생성됩니다.

## 6. 실험 수행 결과

- **성공/실패 보고서 현황 (`interactive_report_*.json`)**
  - `interactive_report_1`, `4`, `6`, `7` : 취약점 발견 및 입력 생성 성공
 - `interactive_report_2` : 디렉토리 및 파일 검색 에러로 인한 실패
 - `interactive_report_3` : 권한 오류로 인한 실패  
 - `interactive_report_5` : 입력 전처리 및 환경 제약으로 인해 실패

## 7. 기타
\> Libspear 연구계획서 
(https://naver.me/x0X7n6mN) `password : 2024`

\> thank you for your contribution
`bmcyber, oxqnd`
