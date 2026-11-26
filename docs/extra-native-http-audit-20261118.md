# extra 개발: 서비스 실행 근거의 HTTP 분석·감사 연결

> 11월19일 현재 구현은 [통합 현황](extra-development-status-20261119.md)을 먼저 본다. 이 문서의 “통합 조회가 남아 있다”는 최초 HTTP 연결 시점 기록이다. 이후 [검증 통합 조회](extra-audit-federation-20261119.md)와 별도 [SQLite 공동 writer](extra-transactional-audit-20261119.md), 백업/복원·checkpoint·취소 경계를 추가했다.

> 후속 상태: 같은 날 [암호화 공유 참조와 프로세스 재시작 검증](extra-shared-native-analysis-20261118.md)을 추가했다. 아래는 기본 메모리 모드와 `43cf3b1` 시점의 HTTP 연결 결과다. 공유 모드는 명시적 시작 설정으로 선택하며 감사 통합 조회는 아직 남아 있다.

2026-11-18. [내부 실행 근거 연결](extra-native-execution-llm-20261118.md)의 후속 작업이다. 기준은 로컬 extra의 `1bcd2d9`이며 이번 변경도 extra에만 저장한다. 원격 push·CI·main/aitest 병합·AWS 배포를 수행하지 않는다. 발표 자료와 기존 성능 평가 원본은 변경하지 않는다.

## 구현 결과

`POST /analysis/native-service`가 신뢰된 서버 수집기가 등록한 실행을 선택해 기존 분석·정책 가드·감사 저장 흐름으로 처리한다. HTTP 요청은 **실행 참조값 하나만** 받는다. 원문 명령, 실행 증거, 서명된 세션, 등록부 경로, 모델 입력이나 `verification_context`를 클라이언트가 지정할 수 없다.

```mermaid
flowchart LR
  A[관리형 systemd 실행과 서명된 근거] --> B[신뢰된 서버 publish_service_analysis]
  B --> C[호출자·팀에 묶인 짧은 실행 참조]
  C --> D[인증된 HTTP 분석 요청]
  D --> E[현재 근거 재검증과 grounded 분석]
  E --> F[기존 정책 가드와 사람 검토]
  F --> G[기존 해시 체인 감사 저장]
  G --> H[반환 직전 재검증]
```

| 구성 | 변경 내용 |
|---|---|
| `app/native_analysis_models.py` | `execution_ref`만 허용하는 엄격한 요청 모델. 소문자 16진수 64자리 |
| `app/services/native_analysis_registry.py` | 같은 프로세스의 신뢰된 수집기만 등록. 같은 tenant·호출자만 조회, 기본 128건·최대 설정 1,024건, 만료 자동 제거·명시적 철회 |
| `scripts/f1_lab/service_analysis_evidence.py` | `publish_service_analysis` 추가. 서명 입력을 복사해 보관하고 실제 HTTP 호출자의 인증으로 다시 수집. 앱 운영 객체가 다르면 등록 거부 |
| `app/main.py` | 새 HTTP 경로를 기존 `_analyze_event`에 연결. 수집 전·대기 후/모델 전·모델 후·감사 저장 후 권한과 출처 재검증 |
| 기존 `AuditStore` | 응답에 사용한 동일한 근거·가드·분석 ID·호출자·tenant·HTTP 요청 ID 저장. 형식과 기존 조회 경로 재사용 |
| `scripts/f1_lab/service_http_controls.py` | 실제 127.0.0.1 TCP 요청, API 키 인증, 기존 OpenAI 어댑터와 명시적인 provider stub, 실제 감사 파일 재로딩 인수 |

실행 참조값은 접근 권한이 아니다. 다른 호출자나 팀, 알 수 없는/철회된/만료된 참조는 동일한 404로 거부한다. 역할은 analyst 이상이고 인증은 API key/OIDC여야 한다. 인증을 끈 로컬 principal도 이 경로에서 신뢰하지 않는다. `production`에서는 기존 로컬 세션 분석과 같이 비활성화한다.

등록된 근거의 최단 만료 시점과 실행 후 최대 30초 제한을 유지한다. 대기열에서 기다리는 동안 근거가 만료·철회되면 모델을 호출하지 않는다. 모델 호출 중 또는 감사 저장 중의 철회도 성공 응답을 차단한다. API 키 설정 변경은 기존 요청별 인증 재검증을 사용하며, OIDC에 새로운 원격 계정 introspection 기능을 추가한 것은 아니다.

이미 소비된 앱 grant를 다시 발급하지 않는다. 정상/위협 분류를 임의로 바꾸지 않고, 소비된 grant에 대한 ALLOW **권고**만 기존 가드에서 HOLD로 제한한다. 모델의 가드 적용 전 권고와 적용 이유도 `verified_review_controls`에 남는다.

## 서버 수집기와 HTTP 사용

신뢰된 수집기가 동일한 앱 프로세스에서 실행 완료 직후 등록한다. 이 함수는 공개 HTTP 등록 API가 아니다.

```python
from app import main
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis

# gate.dispatch가 성공한 원래 요청/세션 및 반환한 event/proofs/receipt를 사용한다.
execution_ref = publish_service_analysis(
    registry=main.native_analysis_registry,
    operations=main.zero_trust_operations,
    signal=original_signed_signal,
    principal=authenticated_principal,
    joiner=broker.joiner,
    caller_registry=broker.registry,
    request=service_request,
    event=service_event,
    proofs=proofs,
    receipt=receipt,
)
```

같은 호출자의 인증으로 짧은 유효기간 안에 HTTP 요청을 보낸다:

```http
POST /analysis/native-service
X-API-Key: <로컬 호출자의 인증키>
Content-Type: application/json

{"execution_ref":"<서버 등록 함수가 반환한 64자리 참조>"}
```

grounded OpenAI/Hybrid 분석기가 설정되어야 한다. 기본 rule/legacy 동작을 변경하지 않았으며 별도 설정 없이 유료 호출을 자동으로 시작하지 않는다. 무료 재현은 아래 인수 실행기를 사용한다.

응답과 감사 기록의 `verification_context.native_execution.analysis_ref_sha256`는 참조값의 SHA-256이다. 여기에 원본 실행/근거/출처 해시, boot/invocation, 앱 세션 버전과 권한 소비 기록이 연결된다. 원문 실행 참조값·JWT·서명·nonce·개인키·API 키·grant token/hash를 새 근거에 저장하지 않는다. 원래 분석 이벤트의 기존 처리 방식은 유지한다.

성공 기록은 기존 `GET /results/{event_id}`로 조회한다. 기존 정책에 따라 같은 tenant의 viewer 이상이 과거 분석을 볼 수 있고 다른 tenant는 볼 수 없다. 이 조회는 현재 권한 재승인이나 실행 재시도가 아니다.

## 감사 기록의 의미

응답과 동일한 `AnalysisResult`를 해시 체인 JSONL에 저장하고 다시 읽어 내용 일치·체인 유효성을 검증했다. 조회 과정은 실행 근거 DB의 clock, 앱 권한 사용 이력, broker 요청을 변경하지 않는다.

감사 저장 직후 권한이 철회되면 HTTP는 성공을 반환하지 않는다. 이미 확정된 감사 기록은 **당시 계산한 과거 분석**으로 보존한다. 감사 기록의 존재 자체를 응답 전달 성공·현재 권한·추가 실행 승인으로 해석하면 안 된다. 감사 저장 오류도 성공 응답으로 대체하지 않는다. 무결성이 이미 깨진 로컬 감사 저장소는 모델 호출 전에 차단한다.

## 로컬 검증

[회귀 결과와 소스 해시](infrastructure-results/extra-native-http-audit-20261118.json), [실제 systemd + TCP HTTP 인수](infrastructure-results/extra-native-http-audit-20261118-systemd.json)를 기준으로 한다. **Linux 확대 회귀 698건 통과**, 이 안에 새 HTTP/등록부 60건이 포함된다. Windows에서도 같은 새 60건이 통과했다. 실제 systemd 인수는 **24조건 통과**, 이 안에 TCP HTTP/감사 연결 9조건이 포함된다. 같은 테스트 수를 중복 합산하지 않는다. Ruff와 `git diff --check`도 통과했다. 전체 프로젝트 테스트를 모두 재실행한 것은 아니다.

새 회귀는 정상 응답/감사 일치·재로딩, 인증/역할/호출자/tenant 분리, HTTP 근거/경로/명령 주입 거부, 참조 만료/철회, 수집원·세션·계정·정책 출처 철회, 모델 대기 중 철회, 저장소 교체, 감사 손상/쓰기 실패, 공급자 오류, 대기열 제한, 용량 제한, 재시작 후 참조 소멸, 원래 입력 변조 격리를 포함한다.

```sh
python -m pytest tests/test_native_analysis_http.py tests/test_native_analysis_registry.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --http-analysis
```

실제 systemd 인수는 Linux root·systemd PID1 환경용이다. 수집 unit의 `ProtectHome=yes` 안에서도 읽을 수 있는 프로젝트/의존성 `PYTHONPATH`를 사용한다. `--http-analysis`는 기존 `--llm-evidence` 검사도 포함한다. 모델 응답은 명시적인 stub이며 실제 API/AWS를 호출하지 않는다. 테스트 TCP 서버, UUID 소유 unit/임시 상태, `/run`의 임시 의존성 복사본을 종료·정리했다.

## 현재 한계와 다음 작업

- 참조 등록부는 **같은 프로세스의 메모리**에 있다. 재시작·다른 worker/host에서는 기존 참조를 재사용하지 못한다. 운영용 공유 등록부나 호스트 간 수집 전송을 구현한 것이 아니다.
- 모델의 native 근거 해석 능력을 실제 API로 새로 평가하지 않았다. 모든 이번 provider 호출은 stub이다. F1 향상 또는 독립 성능 목표 달성을 주장하지 않는다.
- 기존 첫 성공 exec 관측 범위, 로컬 OIDC fixture, 네트워크 목적지 미관측 한계는 그대로다. 실제 기업 SSO·호스트 전체 감사·실운영 배포를 완료한 것이 아니다.

후속 우선순위는 신뢰된 수집기의 프로세스/호스트 간 전달과 공유 참조 수명 관리, 운영 인증원 연결, 고정된 새 실행 사례의 실제 모델 비교다. 정답·원본·임계값은 변경하지 않았다. 기존 개발 360건 **TP163/FP6/FN17/TN174, F1 93.41%**는 이전 시점의 [평가 결과](llm-operation-evidence-20261117.md)로 유지하며 이번 기능 시험과 구분한다.
