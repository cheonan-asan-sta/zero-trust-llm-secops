# 고위험 대응 승인과 모의 실행

김택희 담당인 승인 상태와 실행 결과를 기존 앱에 연결한다. 탐지 규칙이나 F1 개선 작업은 변경하지 않는다. 자동 세션 회수와 보호 접근 거부는 기존 경로를 사용한다. 이 API의 계정 비활성화, 기기 격리, 권한 축소는 외부 서비스에 명령을 보내지 않는 모의 조치다.

## 신원과 대상

요청자는 `responder` 권한이 필요하다. 서버는 요청의 세션 ID와 버전을 현재 테넌트의 정책 저널에서 조회하고 실제 계정, 기기, 자원, 운영자와 입력 지문을 고정한다. 요청자는 해당 세션의 운영자여야 한다. 관리자는 같은 테넌트의 요청을 생성하고 실행할 수 있다.

요청자를 제외한 서로 다른 responder 두 명이 승인해야 한다. 동일한 사람의 두 번째 승인이나 API 키 교체는 승인 인원을 늘리지 않는다. 요청자가 자신을 승인하는 요청은 403이다. 승인자는 요청을 실행할 수 없으며 요청자 또는 관리자가 최종 모의 실행을 요청한다. 다른 테넌트에는 404를 반환한다.

실제 HTTP 신원은 서버가 인증한 사용자로 고정한다. 단일 `runtime-operator` 키만으로 정족수를 채울 수 없다. 기존 OIDC 경로의 서로 다른 서명된 `sub`를 사용할 수 있으며, 로컬 mTLS 환경에는 승인자 두 명의 별도 API 키와 인증서를 연결한다. 일반 운영자와 수집기에 승인자 비밀키를 마운트하지 않는다. 인증서 소유나 클라이언트가 보낸 `approved_by` 필드는 승인 권한이 아니다. 자동 시험에서 서로 다른 신원을 검증한 것과 실제 두 사람이 검토를 완료한 것은 구분한다.

## 요청 순서

1. `POST /response/requests`에 `request_id`, `session_id`, `expected_session_version`, `action`, `expires_at`, `reason`을 보낸다. 행위는 `disable_account`, `isolate_device`, `reduce_privilege` 중 하나다. 만료는 생성 시점에서 5분 이내다. 대상 계정이나 승인자 명단을 직접 지정할 수 없다.
2. 각 승인자는 `POST /response/requests/{id}/approvals`에 직전 응답의 `version`을 `expected_version`으로, `request_digest`와 검토 이유 `reason`을 보낸다. 두 번째 승인자는 첫 승인 이후의 버전을 사용한다.
3. 요청자 또는 관리자는 `POST /response/requests/{id}/execute`에 직전 `expected_version`과 `request_digest`를 보낸다. 응답의 `result.status`는 `SIMULATED`, `result.effect_applied`는 `false`다.
4. 요청자, 기존 승인자 또는 관리자는 실행 전 `POST /response/requests/{id}/cancel`로 취소할 수 있다. 버전, 지문과 취소 이유를 보낸다.
5. `GET /response/requests/{id}`와 목록 API에서 상태와 요청 사유를 확인한다. `reviews`에는 승인자별 검토 사유, 승인 시각과 영수증 버전이 남는다. 같은 테넌트 responder는 검토 대기열을 볼 수 있다. 일반 viewer는 본인과 관련 없는 요청을 조회할 수 없다.

생성 직후 버전은 1, 첫 승인 후 2, 두 번째 승인 후 3, 실행 또는 취소 후 최종 버전은 각각 한 단계 증가한다. 승인이나 실행 전 대상 세션의 버전과 지문이 바뀌면 `STALE`로 표시하고 409로 거부한다. 요청이 만료되면 `EXPIRED`다. 미승인 요청은 `PENDING`으로 유지한다.

같은 ID에 다른 대상이나 행위를 넣으면 409다. 저장된 명령과 같은 요청자의 정확한 재전송에는 기존 영수증을 반환한다. 이미 실행한 요청의 정확한 재전송은 만료나 복원 뒤에도 새 조치를 만들지 않고 기존 결과를 반환한다. 변경된 명령은 거부한다. 저장 실패와 손상된 저널에서는 503으로 중단한다.

## 저장과 복원

기존 `BehaviorContextStore` SQLite에 `response_request`, `response_approval`, `response_cancel`, `response_result` 종류를 추가한다. 정상 작업 기준선의 `approval`과 고위험 대응의 `response_approval`은 서로 다른 기록이며 승인 횟수를 공유하지 않는다. 대응 기록은 정상 작업 평가의 입력 지문에도 포함하지 않는다.

승인 검사와 결과 저장은 기존 context 잠금을 먼저, 정책 잠금을 나중에 획득한다. 정책의 대상 버전을 검사하는 동안 context 결과까지 커밋한 뒤 정책 잠금을 반환한다. SQLite의 `BEGIN IMMEDIATE`와 고유 기록 ID로 프로세스 사이의 중복 실행도 한 결과로 수렴한다.

별도 백업 파일을 추가하지 않는다. 기존 전체 앱 백업의 context DB, 순서와 해시 검증에 승인 기록도 포함된다. 복원은 이전 세션 버전을 차단하므로 이전 미실행 승인을 새 권한으로 사용하지 못한다. 실행 결과와 취소 기록은 그대로 남는다. 기존 grant는 복원 후 403이며, 새로 검증한 세션의 grant만 기존 단일 소비 규칙에 따라 사용할 수 있다.

## 검증 명령

저장소 루트에서 실행한다. 외부 API 호출이나 실계정 변경은 없다.

```sh
.venv/bin/python -m pytest -q tests/test_response_actions.py tests/test_response_recovery.py tests/test_response_processes.py tests/test_response_identity.py
.venv/bin/python -m pytest -q
.venv/bin/ruff check app tests scripts
```

개별 시험은 역할과 테넌트, 두 명의 독립 승인, 요청 변조, 만료와 세션 변경, 중복, SQLite 커밋 실패, 프로세스 동시 실행, 커밋 전 종료, 커밋 후 응답 유실, 암호화된 전체 백업과 복원, 기존 토큰 거부를 검증한다. 실제 외부 계정 비활성화나 기업 IdP 운영 검증은 포함하지 않는다.

## 로컬 mTLS 승인자 연결

추가 API 신원은 선택 설정 `API_KEY_ACCOUNTS_PATH`로 지정한 서버 소유 JSON 파일에서 읽는다. 기존 운영자의 `API_KEY_SHA256` 설정은 유지한다. 파일에는 `schema: api-key-accounts-1`과 `accounts` 배열을 두고, 각 항목에 `sha256`, `subject`, `tenant_id`, `roles`, `enabled`를 기록한다. 원문 API 키는 이 파일에 넣지 않는다. 같은 사용자의 교체 키는 같은 `subject`를 사용한다.

등록 파일은 요청마다 다시 읽으며 128KiB와 100개 신원 상한을 적용한다. 누락, 심볼릭 링크, 디렉터리, 손상된 JSON, 중복 필드와 키, 기존 운영자 키 충돌, 알 수 없는 역할은 503으로 중단한다. 설정이 잘못됐을 때 단일 키 경로로 자동 전환하지 않는다. 비활성화한 키는 다음 요청부터 401이다. 별도 등록 파일을 설정하지 않으면 기존 인증 방식이 유지된다.

새 mTLS 런타임은 `runtime-reviewer-a`, `runtime-reviewer-b`를 만든다. 각 승인자의 자격증명은 `reviewer-a-auth`, `reviewer-b-auth`, 인증서는 대응하는 TLS 볼륨에 둔다. 평소 서비스에는 마운트하지 않고 `Runtime.reviewer_probe()`의 일회용 클라이언트만 자기 자격증명을 읽는다. 이 클라이언트는 앱 내부망에만 연결하며 대상과 서버 인증서 pin을 검증한다. 승인자 인증서는 승인 요청 조회, 승인, 취소 경로만 사용할 수 있다. 세션 발급과 실제 실행 경로는 전송 경계에서도 거부한다.

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 .venv/bin/python -m scripts.test_response_mtls_runtime --directory runtime/c02/response-acceptance
```

매 실행에 새 디렉터리를 사용한다. 이 통합 시험은 실제 mTLS 요청으로 두 승인자, 미승인 실행 거부, 자기 승인 거부, 오래된 버전 거부, 중복 영수증과 권한 경계를 검증한다. 생성한 대응 기록을 기존 암호화 전체 백업과 강제 종료 복구에 포함하고, 복원 전 미실행 요청의 거부, 실행 결과와 취소 보존, 복원 후 새 승인 및 앱 재시작 후 단일 실행을 확인한다. 개인별 검토 완료나 실계정 조치 완료를 뜻하지 않는다.
