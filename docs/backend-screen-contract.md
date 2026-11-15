# 행위 평가와 대응 승인 화면 연결 계약

대상은 현재 FastAPI API다. 기존 공유 화면의 추가 연결에 사용할 계약이며 새 운영 UI의
완료 기록은 아니다. 실제 스키마는 `app/behavior_context_api.py`, `app/response_api.py`,
`app/response_models.py`를 우선한다. 기존 단위 시험과 실제 mTLS 시험이 계약의 실행 근거다.

## 신원과 역할

서버가 검증한 subject, tenant, 역할과 전송 신원이 모두 맞아야 한다. 브라우저가 보내는
사용자 이름이나 화면의 버튼 숨김으로 권한을 결정하지 않는다. admin은 모든 앱 역할을
포함하지만 mTLS peer의 경로 제한을 없애지 않는다. observer의 전송 인증서는 승인 또는
허용 발급용으로 사용할 수 없다.

화면에는 현재 사용자와 테넌트를 표시한다. 검토자는 각자 자신의 인증 경로로 들어가야 한다.
두 검토자 키를 한 서버에 보관해 버튼 두 번으로 승인하는 구조는 사용하지 않는다.
API 키, grant token, 서명키와 응답 원문은 브라우저 저장소, URL 또는 콘솔 로그에 남기지 않는다.

| 화면 작업 | API와 역할 | 응답 |
| --- | --- | --- |
| 행위 변경 이력 | `GET /detections/context/history`, viewer | 200, kind와 record_id, actor, created_at |
| 수집 기록 등록 | `POST /detections/context/captures`, analyst | 201, 검증된 capture |
| 기준선 승인 | `POST /detections/context/baselines`, admin | 201 |
| 작업 승인 | `POST /detections/context/approvals`, responder | 201 |
| 실행 증거 등록 | `POST /detections/context/execution-evidence`, analyst | 201 |
| 문맥 평가 | `POST /detections/context/evaluate`, analyst, `capture_id` | 200, verdict와 reason, 인용 근거 |
| 기준선 또는 작업 승인 취소 | `POST /detections/context/baselines/{id}/revoke`, admin 또는 `.../approvals/{id}/revoke`, responder | 200 |
| 대응 목록과 상세 | `GET /response/requests`, `GET /response/requests/{id}`, viewer | 200, 현재 상태와 version, request_digest |
| 고위험 대응 요청 | `POST /response/requests`, responder | 201 |
| 검토 승인 | `POST /response/requests/{id}/approvals`, responder | 200 |
| 요청 취소 | `POST /response/requests/{id}/cancel`, responder | 200 |
| 모의 실행 | `POST /response/requests/{id}/execute`, responder | 200, SIMULATED와 effect_applied false |

목록의 `limit`는 1~100이고 기본 50이다. 행위 이력은 현재 페이지 분할 API가 아니므로
실제 운영의 무제한 스크롤 또는 대규모 검색 API로 표현하지 않는다.
viewer 조회에서도 서버가 보이는 테넌트와 권한을 검사한다. 토큰 발급과 실제 보호 자원 접근은
별도 `/zero-trust` 경로의 인가 조건을 그대로 따른다.

## 화면 표시와 동시성

행위 verdict는 normal, threat, unknown을 각각 정상, 위협, 판단 보류로 표시한다.
모든 결과에서 `enforcement_eligible: false`를 반영해 조사 보조 결과임을 표시한다.
unknown을 정상 또는 허용으로 바꾸지 않는다. 증거가 부족한 필드와 필요한 자료를 함께 보여준다.
기준선/작업 승인과 고위험 대응의 두 사람 승인은 서로 다른 개념이므로 화면을 구분한다.

대응 요청은 서버가 반환한 상태를 그대로 사용한다. 두 명의 서로 다른 subject가 필요하며
요청자의 자기 승인은 거부된다. 같은 사람의 키를 바꾸는 것은 두 번째 검토자가 아니다.
버전과 요청 digest를 상세 응답에서 읽고 승인, 취소와 실행에 함께 전송한다.
409가 오면 최신 상세를 다시 읽고 바뀐 조건을 사용자에게 보여준다. 오래된 요청에 자동으로
새 digest를 덮어씌워 승인하거나 실행하지 않는다. 반복 클릭도 서버의 원래 중복 계약을 따른다.

```json
{
  "request_id": "response-demo-001",
  "session_id": "session-demo-001",
  "expected_session_version": 1,
  "action": "isolate_device",
  "expires_at": "2026-11-16T12:00:00+09:00",
  "reason": "수집된 침해 증거의 모의 대응 검토"
}
```

날짜와 세션 버전은 실제 현재 값으로 지정해야 한다. create는 responder의 요청이고,
이후 서로 다른 검토자 두 명이 각자 다음 형식을 보낸다. 아래 digest는 자리표시자이며
실제 호출은 현재 상세의 64자리 SHA를 사용한다.

```json
{
  "expected_version": 1,
  "request_digest": "CURRENT_REQUEST_DIGEST_FROM_SERVER",
  "reason": "현재 증거와 제한된 모의 실행 범위 확인"
}
```

각 승인 후 version이 변하므로 다음 검토자는 최신 상세를 읽어야 한다. execute에는
최신 expected_version과 request_digest만 보낸다. `SIMULATED`를 실제 기기 격리 완료나
외부 계정 차단 완료라고 표시하지 않는다. 구현은 `effect_applied: false`다.

| 오류 | 화면 동작 |
| --- | --- |
| 401 | 인증 갱신을 안내하고 기존 조회 결과를 최신 상태로 사용하지 않음 |
| 403 | 권한 또는 전송 경로 거부, 재시도로 우회하지 않음 |
| 404 | 다른 테넌트의 존재를 유추하지 않으며 권한 있는 최신 목록으로 이동 |
| 409 | 현재 상태와 버전을 재조회한 뒤 명시적 재검토 |
| 422 | 필드 검증 오류를 표시하되 원문이나 자격 증명을 로그에 남기지 않음 |
| 503 | 상태 확인 불가, 승인/실행 성공 표시 금지, 영수증 및 상세로 결과 확인 |

응답 유실은 실패 확정도 성공 확정도 아니다. 같은 request ID를 조회하고 원래 명령의
중복 처리 계약으로 확인한다. 새 ID로 고위험 요청을 임의 재발급하지 않는다.

## 연결 전 통과 기준

기존 역할 검사와 두 사람 승인, CAS 충돌, 만료, 취소, 다른 테넌트 접근과 실제 재시작 시험을
먼저 실행한다. 정확한 시험 파일은 아래 명령으로 찾고 해당 모듈을 pytest로 실행할 수 있다.

```bash
rg --files tests | rg 'response|behavior_context_api|behavior_execution'
.venv/bin/python -m pytest -q
.venv/bin/python -m scripts.test_response_mtls_runtime --directory runtime/c02/response-screen-new-run
.venv/bin/python -m scripts.test_execution_mtls_runtime --directory runtime/c02/execution-screen-new-run
```

모든 명령은 저장소 루트에서 실행하며 Docker 시험은 각각 새 폴더를 사용한다.
현재 mTLS 환경은 내부망과 신원별 단기 probe를 사용한다. 외부 브라우저 경로를 임의 개방하거나
core 관리 인증서를 화면 서버에 함께 마운트하는 것은 이 계약의 구현 방법이 아니다.
배포 신원 경로를 공동 확정한 후 기존 화면 담당 코드에 연결하고 별도 통합 결과를 남긴다.
