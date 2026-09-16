# zero-trust-llm-secops

LLM 기반 지능형 제로 트러스트 보안 오퍼레이션 및 자동화 프레임워크의 시연용 웹 애플리케이션입니다.
합성 보안 이벤트를 입력받아 위험도를 분석하고, 실제 시스템을 변경하지 않는 대응 미리보기를 반환합니다.

## 현재 구현 범위

- 제로 트러스트 판단에 필요한 공통 이벤트 모델
- 정상 3건과 위협 5건으로 구성된 합성 이벤트
- ATT&CK 기법·관찰 신호·정상 예외를 포함한 3주차 위협 시나리오 카탈로그
- 설명 문자열과 분리된 실행 가능한 시나리오 탐지 조건
- 승인자·유효기간·대상·용량 범위를 검증하는 정책 예외
- 규칙 기반 위험 분석기
- 확신이 낮은 사례만 LLM으로 교차 검토하는 하이브리드 분석기
- 10개 Few-shot 예시와 OpenAI Structured Outputs 기반 선택형 LLM 분석기
- 정책 안전장치와 대응 미리보기
- 담당자·검토 메모·상태 전환이 포함된 분석가 검토 흐름
- 재시작 후에도 복원되는 JSONL 감사 기록
- AWS 배포 시 DynamoDB에 보존되는 감사 기록
- 단건·최대 20건 병렬 분석과 시나리오 자동 매칭 API
- 정확도·F1·JSON 유효율·평균/P95 응답시간 평가 API
- 제한 병렬 반복 평가와 P50·P95·P99·처리량 측정
- 오류 유형·혼동 행렬·시나리오별 품질 진단
- OIDC·해시 기반 API 키 인증과 역할 기반 접근 제어
- 인증된 테넌트별 분석·감사 결과 격리
- 요청 추적 ID, 보안 헤더, 본문 크기·분석 동시성 제한
- Prometheus 메트릭과 JSONL 감사 로그 해시 체인
- 공공·기업 보안 기준 18개를 구현·부분 구현·계획으로 구분한 기계판독 통제대장
- 완료 통제의 코드·구성·자동 시험 증거를 강제하는 보증 검증기와 준비도 API
- 천안아산역 콘셉트의 한국어 관제 대시보드
- FastAPI 엔드포인트와 자동 테스트
- AWS 계정 보호 장치가 포함된 Lambda 컨테이너 배포 정의
- API 키 없이 전체 검증 가능한 로컬 Docker·Compose 경로

실제 계정 차단, 권한 변경, 세션 격리는 수행하지 않습니다.

## 개발 주차 산출물

수행계획서의 목표와 실제 코드·검증 근거를 연결한 3~14주차 기록은 [주차별 산출물 색인](docs/README.md)에서 확인할 수 있습니다. 기업 적용을 위한 보안 기준선과 남은 운영 검증 항목은 [기업 적용 준비도](docs/enterprise-readiness.md), 실제 사례·논문과 다음 구현 순서는 [고도화 딥 리서치](docs/deep-research-enterprise-secops.md), 국내외 공공기관·금융권·표준·기업 실무 자료와 추가 논문은 [기업·공공부문 참고자료 카탈로그](docs/reference-catalog-enterprise-public-sector.md)에 정리했습니다.

## 기업용 보안 모드

로컬 Docker는 비용 없는 개발 편의를 위해 인증이 꺼진 `local` 환경으로 실행됩니다. 실제 조직 환경에서는 `APP_ENVIRONMENT=production`과 `AUTH_MODE=oidc`를 사용해야 하며, 인증을 끈 프로덕션 설정은 시작 단계에서 거부됩니다.

```dotenv
APP_ENVIRONMENT=production
AUTH_MODE=oidc
OIDC_ISSUER=https://identity.example.com
OIDC_AUDIENCE=zero-trust-secops
OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
ALLOWED_HOSTS=secops.example.com
```

OIDC 토큰은 RS256 서명, 발급자, 대상, 만료시간과 필수 사용자·테넌트·역할 클레임을 확인합니다. 역할은 `viewer`, `analyst`, `responder`, `admin`이며 조회, 분석, 검토 처리, 품질 평가 권한을 분리합니다. 서비스 연동용 API 키 모드도 제공하지만 실제 키 대신 SHA-256 해시만 설정에 보관합니다.

현재 구현은 기업 도입을 위한 기술 기준선입니다. 18개 통제의 요약은 조회 권한으로 볼 수 있지만, 코드·테스트 위치가 포함된 상세 증적은 관리자에게만 공개됩니다. 통제 구현률은 인증이나 규정 준수 선언이 아닙니다. 실제 운영 전에는 조직 IdP 연결, API Gateway/WAF 기반 분산 속도 제한, SIEM 전송, 보존·개인정보 정책, 장애 복구 훈련과 외부 침투시험을 완료해야 합니다.

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

## 비용 없는 Docker 실행과 검증

로컬 Docker는 `rule` 모드만 사용하므로 OpenAI API와 AWS 비용이 발생하지 않습니다. 컨테이너는 비루트 사용자, 읽기 전용 파일 시스템, Linux capability 제거, 추가 권한 획득 금지 설정으로 실행됩니다.

```powershell
docker compose up --build
```

브라우저에서 http://127.0.0.1:8000/ 을 열고 사용할 수 있습니다. 종료할 때는 다음 명령을 실행합니다.

```powershell
docker compose down
```

로컬 감사 기록까지 함께 지우려면 `docker compose down --volumes`를 사용합니다.

Docker 내부 코드 검사·단위 테스트와 실제 API 스모크 테스트를 한 번에 실행하려면 다음 스크립트를 사용합니다. 테스트 컨테이너는 성공 여부와 관계없이 자동으로 제거됩니다.

```powershell
.\scripts\test-docker.ps1
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

### 하이브리드 모드

규칙 분석의 신뢰도가 기준값 이상이면 즉시 결과를 반환하고, 애매한 사례만 OpenAI로 교차 검토합니다. API 호출량과 지연을 줄이면서 LLM 호출 실패 시 규칙 결과와 사람 검토 전환으로 안전하게 복구합니다.

```dotenv
ANALYZER_MODE=hybrid
OPENAI_API_KEY=발급받은_키
HYBRID_CONFIDENCE_THRESHOLD=0.85
HYBRID_LLM_TIMEOUT_SECONDS=2.5
```

## 주요 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 서버와 분석 모드 확인 |
| GET | `/health/live` | 공개 가능한 최소 생존 확인 |
| GET | `/health/ready` | 감사 저장소와 통제대장 무결성을 포함한 준비 상태 |
| GET | `/assurance/summary` | 통제 구현·증적·검토기한 요약 |
| GET | `/assurance/controls` | 관리자 전용 통제·근거·증적 목록 |
| GET | `/assurance/controls/{control_id}` | 관리자 전용 개별 통제 상세 |
| GET | `/scenarios` | 준비된 합성 시나리오 목록 |
| GET | `/scenarios/{scenario_id}` | ATT&CK 매핑과 관찰 신호를 포함한 시나리오 정의 |
| POST | `/events/simulate` | 합성 이벤트 생성 |
| POST | `/analysis` | 이벤트 위험 분석과 정책 검토 |
| POST | `/analysis/batch` | 최대 20개 이벤트 제한 병렬 분석 |
| POST | `/scenarios/evaluate` | 구조화 조건으로 시나리오 일치도 계산 |
| POST | `/evaluation/run` | 반복 사례 정확도·오류·혼동 행렬·시나리오별 성능 측정 |
| POST | `/response/preview` | 실제 조치 없는 대응 미리보기 |
| GET | `/metrics` | 누적 분석 현황 요약 |
| GET | `/results?limit=20` | 최근 분석 결과 목록 |
| GET | `/results/{event_id}` | 최근 분석 결과 조회 |
| GET | `/internal/metrics` | 관리자 전용 Prometheus 메트릭 |

## 폴더 구조

```text
app/
  analyzers/       규칙 기반 및 OpenAI 분석기
  data/            기계판독 보안 통제대장
  services/        정책 안전장치, 감사 기록과 보증 검증
  config.py        환경변수 설정
  main.py          FastAPI 엔드포인트
  models.py        이벤트 및 분석 결과 모델
  scenarios.py     합성 이벤트 8건
  static/           관제 대시보드 화면
tests/             API와 정책 테스트
runtime/           실행 중 생성되는 감사 기록
docs/week03/       3주차 위협 모델·이벤트 스키마·아키텍처 산출물
docs/week04/       정책 예외·조건 평가·가속 개발 산출물
docs/week05/       비용 없는 로컬 Docker 검증 산출물
docs/week06/       합성 로그·Few-shot·구조화 출력 산출물
docs/week07/       1차 분석 프로토타입 산출물
docs/week08/       하이브리드 분석·감사 저장 산출물
docs/week09/       대응 JSON·정책 실행 엔진 산출물
docs/week10/       리스크·안전 조건·예외 검증 산출물
docs/week11/       통합 API·평가·배포 검증 산출물
docs/week12/       대시보드·분석가 검토·MVP 완료 산출물
docs/week13/       반복 성능 측정·제한 병렬화 산출물
docs/week14/       오류 진단·품질 대시보드 고도화 산출물
docs/enterprise-readiness.md  기업 적용 보안 기준선과 운영 전 검증 게이트
infra/             ECR·Lambda·DynamoDB CloudFormation
scripts/           대상 계정 검증이 포함된 AWS 배포 스크립트
```

## AWS 배포

배포 대상 계정은 `172585182454`, 기본 리전은 서울(`ap-northeast-2`)이다. 배포 스크립트는 현재 AWS 자격 증명의 계정 번호가 다르면 이미지 업로드나 리소스 생성을 시작하기 전에 중단한다.

```powershell
.\scripts\deploy-aws.ps1 -Profile 대상_계정_프로필
```

기본 배포는 API 비용이 들지 않는 `rule` 분석 모드다. `openai`와 `hybrid` 모드는 키를 코드나 명령행 평문으로 전달하지 않고 AWS Secrets Manager의 비밀 ARN을 사용한다.

```powershell
.\scripts\deploy-aws.ps1 `
  -Profile 대상_계정_프로필 `
  -AnalyzerMode hybrid `
  -OpenAIApiKeySecretArn arn:aws:secretsmanager:ap-northeast-2:172585182454:secret:이름
```

배포 구성은 ECR 이미지 스캔, AWS IAM 인증이 필요한 HTTPS Lambda 함수 URL, 최소 권한 실행 역할, 암호화·시점 복구·삭제 방지를 적용한 테넌트 인식 DynamoDB 감사 테이블을 만든다. 모든 분석 모드가 IAM 인증을 요구하며 실제 기업 이벤트나 개인정보를 사용하는 운영 배포에는 별도 OIDC/API Gateway 통합이 필요하다.

## 안전 원칙

- `ground_truth`는 평가 전용이며 분석기 입력에서 제외합니다.
- 이벤트 안의 자유 텍스트는 지시가 아닌 데이터로 취급합니다.
- 고위험 결과와 낮은 신뢰도 결과는 사람 검토로 전환합니다.
- 대응은 허용 목록 안에서 선택하며 결과만 미리보기로 반환합니다.
- API 키와 실제 기업 로그는 저장소에 포함하지 않습니다.
- 구현 완료 통제는 코드 또는 구성과 자동 시험 증거를 모두 요구합니다.
- 통제 준비도는 현재 증거의 상태이며 인증·규정 준수 판정을 대신하지 않습니다.

## 참고한 공식 문서

- [OpenAI API Quickstart](https://developers.openai.com/api/docs/quickstart)
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
