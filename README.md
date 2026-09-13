# zero-trust-llm-secops

LLM 기반 지능형 제로 트러스트 보안 오퍼레이션 및 자동화 프레임워크의 시연용 웹 애플리케이션입니다.
합성 보안 이벤트를 입력받아 위험도를 분석하고, 실제 시스템을 변경하지 않는 대응 미리보기를 반환합니다.

## 현재 구현 범위

- 제로 트러스트 판단에 필요한 공통 이벤트 모델
- 정상 3건과 위협 5건으로 구성된 합성 이벤트
- 규칙 기반 위험 분석기
- OpenAI Structured Outputs 기반 선택형 LLM 분석기
- 정책 안전장치와 대응 미리보기
- 재시작 후에도 복원되는 JSONL 감사 기록
- 누적 분석·위험도·분석기별 현황 API
- 천안아산역 콘셉트의 한국어 관제 대시보드
- FastAPI 엔드포인트와 자동 테스트

실제 계정 차단, 권한 변경, 세션 격리는 수행하지 않습니다.

## 빠른 시작

PowerShell에서 다음 명령을 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

브라우저에서 다음 주소를 엽니다.

- 관제 대시보드: http://127.0.0.1:8000/
- API 문서: http://127.0.0.1:8000/docs
- 상태 확인: http://127.0.0.1:8000/health

테스트는 아래 명령으로 실행합니다.

```powershell
pytest -q
```

## 분석 모드

### 규칙 기반 모드

별도 API 키 없이 실행됩니다. 기본값이므로 초기 개발과 API 연동 시험에 사용합니다.

```powershell
$env:ANALYZER_MODE="rule"
uvicorn app.main:app --reload
```

### OpenAI 모드

프로젝트 루트의 `.env.local`에 환경변수를 설정한 뒤 서버를 다시 시작합니다.
이 파일은 Git에서 제외되며 키는 코드나 저장소에 기록하지 않습니다.

```dotenv
ANALYZER_MODE=openai
OPENAI_API_KEY=발급받은_키
OPENAI_MODEL=gpt-5.4-mini
```

OpenAI SDK는 환경변수의 키를 자동으로 읽으며, 분석 결과는 Pydantic 모델에 맞춘 구조화 출력으로 받습니다.

## 주요 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 서버와 분석 모드 확인 |
| GET | `/scenarios` | 준비된 합성 시나리오 목록 |
| POST | `/events/simulate` | 합성 이벤트 생성 |
| POST | `/analysis` | 이벤트 위험 분석과 정책 검토 |
| POST | `/response/preview` | 실제 조치 없는 대응 미리보기 |
| GET | `/metrics` | 누적 분석 현황 요약 |
| GET | `/results?limit=20` | 최근 분석 결과 목록 |
| GET | `/results/{event_id}` | 최근 분석 결과 조회 |

## 폴더 구조

```text
app/
  analyzers/       규칙 기반 및 OpenAI 분석기
  services/        정책 안전장치와 감사 기록
  config.py        환경변수 설정
  main.py          FastAPI 엔드포인트
  models.py        이벤트 및 분석 결과 모델
  scenarios.py     합성 이벤트 8건
  static/           관제 대시보드 화면
tests/             API와 정책 테스트
runtime/           실행 중 생성되는 감사 기록
```

## 안전 원칙

- `ground_truth`는 평가 전용이며 분석기 입력에서 제외합니다.
- 이벤트 안의 자유 텍스트는 지시가 아닌 데이터로 취급합니다.
- 고위험 결과와 낮은 신뢰도 결과는 사람 검토로 전환합니다.
- 대응은 허용 목록 안에서 선택하며 결과만 미리보기로 반환합니다.
- API 키와 실제 기업 로그는 저장소에 포함하지 않습니다.

## 참고한 공식 문서

- [OpenAI API Quickstart](https://developers.openai.com/api/docs/quickstart)
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
