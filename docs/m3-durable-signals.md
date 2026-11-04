# M3 지속 신호 수신·처리 계약과 검증

2026년 11월 2일 작성. [김택희 이번 주 계획](roles/kimtaekhee.md)의 M3/I1 최소 경로를 구현한 로컬 개발 명세다. 실제 IdP·EDR 수집, AWS 배포, 독립 업무 PEP, 인프라 성능 측정이나 M6 신규 모델 비교 완료를 뜻하지 않는다. 기존 Sigma 규칙·임계값과 개선 전 탐지 평가 결과는 변경하지 않는다.

## 처리 경계

11월 3일 추가된 [Windows/Docker 인프라 재현·측정](m3-infrastructure-measurement.md)은 기존 기능 시연을 재사용한다. 최신 시험 실행기는 개인키를 파일로 저장하지 않고 worker를 `network_mode: none`으로 실행한다. 앞선 [11월 2일 Docker 검증](m3-docker-validation.md)의 키 파일·네트워크·환경 기록은 당시 실행 결과로 보존한다.

```text
인증된 analyst + 등록 수집기의 서명된 관측
  → 종류·주체·테넌트·키·신선도 검증
  → SQLite 수신함 commit → HTTP 202 영수증
                          ↓ 별도 CLI worker의 lease 취득
                    현재 수집기 권한·키 재검증
                          ↓
           관련 세션 제한 + 중복 방지 표식의 원자적 journal commit
                          ↓
                    수신함 완료 영수증 commit
                          ↓
               기존 허용으로 다음 모의 업무 접근 시 403
```

수신 성공은 내구 저장 완료를 뜻한다. 정책 적용 완료와 다르므로 호출자는 영수증을 조회해야 한다. 기존 케이스 **송신** 아웃박스와 이 **수신** 큐는 별개이며 새 메시지 브로커를 도입하지 않았다.

## 신호별 증명 권한

새 `SignedContinuousSignal`은 `zt-observation-1` 스키마의 Ed25519 서명 관측이다. 필수 필드는 `tenant_id`, `event_id`, `source_id`, `key_id`, `issued_at`, `expires_at`, `observed_at`, `observation`, `signature`다. 모든 시각은 시간대가 있어야 하며 서명 유효기간은 최대 120초다. 최초 접수는 발급 후 60초 이내·미래 발급 금지·미만료를 검사하고, 관측 시각은 발급 시각 이후일 수 없다. 과거 위험 관측의 나이를 정상 상태의 증거로 사용하지 않는다.

| 관측 종류 | 주장 가능한 필드 | 등록 범위 | 제한 판단 |
|---|---|---|---|
| `identity` | `subject_id`, `active`, `authentication_result` | 수집기의 `user_ids`, `observation_kinds`에 `identity` | 비활성 또는 인증 실패는 `DENY`, 인증 불명은 `HOLD` |
| `device` | `subject_id`, `managed`, `security_posture` | 수집기의 `device_ids`, `observation_kinds`에 `device` | 비관리 또는 침해는 `DENY`, 상태 불명은 `HOLD`, 위험 징후는 `STEP_UP` |

등록된 키가 있다는 이유만으로 모든 관측 권한을 얻지 않는다. `TrustedSignalSource.observation_kinds`는 명시적으로 허용하며 기본값 `[]`는 새 수신 경로의 권한이 없다. 기능별 수집기에는 필요한 종류와 주체만 등록한다. `canonical_observation()`으로 검증된 모델의 서명 필드를 제외하고 정렬 직렬화한 내용을 서명한다. 기존 `zt-signal-1` 세션 증명과 서명 도메인이 다르다.

서명은 등록된 출처와 무결성을 확인하며 실제 인증·기기 상태의 진실성을 보증하지 않는다. 이 관측은 MFA 성공, 새 세션 인증, 허용 토큰 발급 또는 회수 상태 해제의 근거로 사용하지 않는다. `observation_kinds`가 설정된 관측 전용 출처는 기존 `/signals/evaluate`의 전체 세션 증명을 제출할 수 없다. 따라서 기기 관측 키가 기존 경로로 인증·MFA 성공을 주장하는 우회를 차단한다. 같은 테넌트의 다른 출처에 동일한 공개키를 등록하는 구성도 실패 폐쇄하므로 `source_id`만 바꿔 증명 권한을 넓힐 수 없다. 기존 v0.17 세션 증명 API는 관측 권한이 없는 별도 출처·별도 키의 호환 경로로 유지한다. 이 호환 경로까지 실제 IdP·기기 증명을 분리한 운영 인증 체계가 완성됐다는 뜻은 아니다.

## HTTP 입력·응답

| 요청 | 최소 역할 | 결과 |
|---|---|---|
| `POST /zero-trust/signals/inbox` | analyst | 검증·저장 완료 후 202 영수증 |
| `GET /zero-trust/signals/inbox/{event_id}` | viewer | 호출자 테넌트의 영수증 또는 404 |
| `GET /zero-trust/signals/inbox` | viewer | 호출자 테넌트의 상태 개수·대기 나이·완료 지연 |

영수증은 `tenant_id`, `event_id`, `state`, `duplicate`, `received_at`, `attempts`, `next_attempt_at`, `completed_at`, `last_error`, `result`를 담는다. 원본 관측·서명·접수자·lease 토큰을 반환하지 않는다. 처리 결과의 `matched_sessions`, `changed_sessions`, `stale`, `duplicate`로 관련 세션과 실제 상태 변경을 구분한다. 입력에 `session_id`를 받아 한 세션만 갱신하는 방식이 아니며 인증 관측은 사용자, 기기 관측은 기기를 기준으로 해당 테넌트의 세션에 적용한다.

| 상황 | 상태 | 의미 |
|---|---|---|
| 동일 테넌트·이벤트 ID·내용 재전송 | 202, `duplicate=true` | 기존 영수증 반환, 신규 접수·효과 중복 없음 |
| 같은 ID에 다른 서명된 내용 | 409 | 기존 접수 내용을 바꿀 수 없음 |
| 출처·키·서명·종류/주체 권한·테넌트·최초 신선도 거부 | 401 | 저장·정책 적용 없음 |
| 역할 부족 | 403 | viewer가 접수할 수 없음 |
| 없는 ID 또는 다른 테넌트 ID 조회 | 404 | 타 테넌트의 접수 존재를 공개하지 않음 |
| 대기 상한 또는 이관으로도 확보할 수 없는 hot·archive·byte 용량 | 429, `Retry-After: 1` | 저장하지 않은 새 접수, 재전송 필요 |
| 수신함·키 등록 이용 불가 | 503 | 접수 성공으로 표시하지 않음 |
| 형식·필드·시간대·유효기간 모델 오류 | 422 | 서명 처리 전 입력 거부 |
| production 또는 미설정 수신기 | 404 | 로컬 기능 미노출 |

이미 접수한 정확한 재전송은 원래 신선도 기간이 지나도 영수증을 돌려줄 수 있다. 이때도 **현재** 수집기·키·종류/주체 권한과 서명을 검사하며 저장된 내용이 같아야 한다. 폐기된 키를 가진 재전송을 승인하지 않는다.

## 저장·중복·재시작 계약

수신함은 SQLite 트랜잭션과 `synchronous=FULL`을 사용한다. `(tenant_id,event_id)`를 기본키로 삼고 서명 제외 입력 지문과 서명 포함 전체 payload 지문을 보존한다. commit이 성공한 뒤에만 202를 반환한다. 앱과 worker는 동일한 `ZERO_TRUST_DB_PATH`를 사용하며 정책 journal과 수신함 테이블은 같은 파일 안의 **별도 트랜잭션**이다.

이 버전이 `kind=observation`을 기록한 journal DB는 이전 코드에서 읽을 수 없다. 코드만 이전 버전으로 되돌리는 롤백은 지원하지 않는다.
기존 자료와 분리한 로컬 DB로 시험하고, 기존 DB를 업그레이드하기 전에는 정책·키 등록·감사 기록을 포함한 일관된 스냅샷을 확보해야 한다.
회수 기록이 생긴 뒤 단순히 옛 백업으로 되돌려 허용을 되살리면 안 된다. 최신 회수·폐기 상태를 보존하는 운영 복원·롤백 절차는 아직 구현하지 않았다.

후속 [정책 저널 보관 이관](policy-journal-maintenance.md)은 같은 SQLite DB의 활성 journal prefix를 압축 segment에 보관하고 매 읽기에서 전체 체인을 검증·복원한다. 세션 이력·누적 관측 제한·중복 방지와 worker ACK 복구 표식은 archive 안에서도 유지한다. version 2 스키마의 필수 메타데이터 누락을 신규 DB로 재초기화하지 않으며 옛 코드 downgrade는 지원하지 않는다. 이 기능은 아래 inbox의 영수증 보관 상한이나 백업·복원 한계를 해소하지 않는다.

```text
pending → processing → completed
                └→ pending (재시도 시각 이후)
                └→ failed  (최대 시도 소진)
processing -- lease 만료 --> 새 worker가 다시 취득
```

lease 토큰은 완료·실패 기록의 소유권을 검사하므로 이전 worker가 새 worker의 영수증을 덮어쓰지 못한다. 재시도는 지수 백오프를 적용한다. 오류는 `SIGNAL_REJECTED`, `REGISTRY_UNAVAILABLE`, `JOURNAL_UNAVAILABLE`, `PROCESSING_ERROR`, `PROCESSING_EXHAUSTED` 같은 제한된 코드로 남기며 예외 원문을 저장하지 않는다.

전달은 **최소 한 번**이다. 모든 관련 세션 변경과 관측 표식은 정책 journal의 한 트랜잭션으로 기록된다. 정책 효과 이후 수신함 완료 기록 전에 종료되면 lease 만료 후 재전달되고, journal 표식이 같은 관측의 효과를 중복 적용하지 않게 한다. 수신함과 journal을 한 분산 트랜잭션 또는 정확히 한 번 전달로 설명하지 않는다.

일반 재전달에서도 먼저 테넌트·이벤트 ID·내용 지문에 맞는 기존 journal 표식을 조회한다. 마지막 정책 처리 시도에서 효과를 commit한 뒤 완료 기록을 잃었으면, lease 만료 후 **읽기 전용 결과 대조**를 위한 새 lease를 얻는다. 이 경로는 `attempts`를 늘리거나 정책을 다시 적용하지 않고 표식이 있으면 완료 영수증만 복구한다. 기존 효과를 확인하는 일에는 현재 키의 유효성이 필요하지 않으므로 그 뒤 키가 폐기됐어도 완료 상태를 복구할 수 있다. 표식이 없으면 `PROCESSING_EXHAUSTED`로 실패를 보관하며 추가 정책 시도를 하지 않는다. `failed`는 처리 중단 상태이며 그 단어만으로 정책 효과가 없었다고 단정하지 않는다. 실패 원인과 실제 세션·journal 결과를 함께 대조한다.

worker는 새 정책 적용 전에 현재 키와 수집기 권한을 다시 확인한다. 접수 후 정책 journal에 장애가 생기면 접수 영수증을 취소하지 않고 처리 오류·재시도 상태로 추적한다. 최초 신선도 검증 후 접수된 위험 관측이 대기 중 만료돼도 접근을 제한할 수 있다. 순서가 뒤집힌 과거 위험 관측도 제한을 강화할 수 있으며 `stale`로 표시한다. 정상 관측은 기록만 하고 제한을 낮추지 않는다. 기존 제한은 이후 동기 평가와 새 세션에도 적용된다. **안전한 제한 해제·복구 절차는 후속 작업**으로 남긴다.

완료·실패 영수증은 자동 삭제하지 않는다. [서버 inbox 영수증 보관 이관](server-inbox-maintenance.md)은 전역·테넌트 hot 한도에서 terminal 행만 같은 DB의 압축 archive로 옮겨 원래 payload·결과·오류·내용 지문과 공개 영수증을 보존한다. pending·processing·lease·시도 횟수는 바꾸지 않는다. 기본 hot 10,000행과 별도로 archive 100,000행·1,000개 segment·byte 한도를 두고, 공간을 확보할 수 없으면 새 입력을 거부한다. 영수증 조회·중복·충돌과 상태 집계는 hot·archive 전체를 포함하며 현재 출처·키·권한 검증도 유지한다. 각 연산 비용은 전체 보관량에 비례한다. 이관은 영수증 삭제·무한 운영·보안 소거·앱 DB 백업 복원이나 원격 변조 방지 보증이 아니다. 독립 inbox format과 application ID를 사용하는 스키마 이행 전후에는 같은 DB를 쓰는 앱·worker·watchdog·CLI의 코드를 정렬하며 구형 코드를 섞지 않는다.

## 별도 worker 실행과 앱 지표

API와 worker는 같은 설정 파일·DB·공개키 등록을 사용한다. 개인키는 worker나 API에 필요하지 않으며 수집기 밖으로 옮기지 않는다.

```sh
# 한 번에 한 건을 시도하고 종료
python -m scripts.signal_worker --once

# 별도 프로세스로 반복 처리 (SIGINT/SIGTERM으로 종료)
python -m scripts.signal_worker --poll-seconds 0.5
```

`--once`는 전체 대기열 배출 명령이 아니다. 대기 건이 없거나 재시도 시각 전인 경우에도 정상 종료하며, 영수증의 `pending`을 성공적인 정책 적용으로 해석하지 않는다. `--once`의 종료 코드 0만으로 완료를 판정하지 말고 영수증의 상태를 확인한다. CLI는 상태와 시도 횟수만 출력한다. production 환경은 실행을 거부한다.

로컬 Compose 실행에는 [신호 처리 overlay](../compose.signals.yaml)를 추가한다. 기존 앱과 별도 worker가 같은 `secops-audit` 볼륨의 SQLite를 사용한다. 호스트의 **공개키 등록 JSON 파일**을 두 서비스에 읽기 전용으로 마운트하며 개인키를 마운트하지 않는다.

```sh
SIGNAL_REGISTRY_PATH=/absolute/sources.json docker compose -f compose.yaml -f compose.signals.yaml up --build
```

`SIGNAL_REGISTRY_PATH`는 실제로 존재하고 컨테이너의 비관리자 계정이 읽을 수 있는 절대 파일 경로다. `create_host_path: false`로 잘못된 파일 경로를 빈 디렉터리로 자동 생성하지 않는다. worker에는 호스트 포트를 열지 않으며 읽기 전용 파일시스템·권한 제거 설정을 적용한다. 이 구성은 단일 호스트의 공유 SQLite 구조이며 mTLS·독립 PEP·다중 호스트 전달을 구현한 것이 아니다. 최초 구성 검사 후 별도 로컬 엔진에서 실제 앱·worker 빌드와 HTTP·저장·재시작 시나리오 11개를 통과했다. 테스트 이미지 내부의 전체 524건·경고 2건과 Ruff도 통과했으며 환경·재현·한계는 [실제 Docker 검증 기록](m3-docker-validation.md)에 분리했다.

| 환경 설정 | 기본값 | 의미 |
|---|---|---|
| `ZERO_TRUST_DB_PATH` | `runtime/zero-trust.sqlite3` | API·worker 공통 SQLite 경로 |
| `TRUSTED_SIGNAL_SOURCES_PATH` | 미설정 | 등록 공개키·종류/주체 권한, 미설정이면 서명 관측 접수 불가 |
| `SIGNAL_INBOX_MAX_PENDING` | 1000 | pending·processing 합계 상한 |
| `SIGNAL_INBOX_MAX_RECORDS` | 10000 | pending·processing·이관 전 완료/실패를 포함한 hot 행 상한 |
| `SIGNAL_INBOX_MAX_ATTEMPTS` | 3 | lease 취득 기준 최대 시도 |
| `SIGNAL_INBOX_LEASE_SECONDS` | 30 | 처리 소유권 유효기간 |
| `SIGNAL_INBOX_RETRY_SECONDS` | 1 | 첫 재시도 지연, 이후 지수 증가 |

요약 API의 `pending`, `processing`, `completed`, `failed`, `total`은 해당 테넌트의 hot·archive 전체 보관 자료 기준이다. `active_records`는 terminal을 포함한 hot 행 수, `archived_records`는 이관 행 수다. `oldest_pending_age_seconds`, `oldest_processing_age_seconds`는 접수부터 조회까지의 나이다. `completion_latency_samples`, `mean_completion_latency_seconds`, `max_completion_latency_seconds`는 **접수→완료** 구간이며 대기·재시도를 포함하고 archive의 완료 표본도 유지한다. 완료 표본이 없으면 지연은 `null`이다. 이는 worker CPU 실행 시간·수집기 관측부터 거부까지의 전체 지연·P95와 다르다. 경보 수집기·운영 임계값·RTO/RPO 실측은 채희주의 후속 인프라 실행과 연결한다.

## 검증 행렬

| 검증 조건 | 기대 증거 | 자동 시험 |
|---|---|---|
| 저장 실패·상한 초과 | 성공 응답 없음, 새 영수증 없음 | `test_continuous_signal_api.py`, `test_signal_inbox.py` |
| 동일 입력 재전송·ID 내용 충돌 | 동일 영수증 또는 409, 신규 효과 없음 | 위 두 파일 |
| 권한 없는 종류/주체·위조·타 테넌트·viewer POST | 401/403, 타 테넌트 조회 404 | `test_continuous_signal_api.py`, `test_continuous_signal_policy.py` |
| 처리 직전 종료·lease 만료·이전 worker 완료 | 재전달 가능, 소유권 없는 완료 거부 | `test_signal_inbox.py`, `test_signal_worker_process.py` |
| 정책 효과 직후 완료 기록 실패·재시작·마지막 시도·후속 키 폐기 | 관련 세션 변경 보존, 버전·이력 증가 없이 완료 상태 대조 복구 | `test_continuous_signal_api.py`, `test_signal_worker_process.py` |
| 관련 다중 세션·무관 세션 | 관련 세션의 다음 접근 403, 무관 세션은 200 | `test_continuous_signal_api.py` |
| 순서 역전·정상 관측·기존 제한 | 위험 근거 보존, 새 허용·MFA 복구 없음 | `test_continuous_signal_policy.py` |
| 재시도 소진·저장 손상 | failed 영수증 또는 실패 폐쇄 | `test_signal_inbox.py` |
| production 경계 | 새 API 404, CLI 실행 거부 | `test_continuous_signal_api.py`, `test_signal_worker_process.py` |

```sh
python -m pytest -q tests/test_continuous_signal_api.py tests/test_signal_inbox.py tests/test_continuous_signal_policy.py tests/test_signal_worker_process.py
python -m ruff check .
```

시험 개수·전체 회귀 결과는 실행 기록을 따른다. 위 행렬은 보장하려는 조건과 시험 위치이며 실제 Docker 실행은 [별도 기록](m3-docker-validation.md)을 따른다. 실제 IdP·EDR 수집기나 운영 부하 검증을 뜻하지 않는다. 독립 재현에는 날짜·코드 버전·설정·기대/실제·실행자/검증자·실패 목록을 함께 남긴다.

## M6·M7 데이터·평가 계약

이번 구현은 평가 계약의 틀을 정리한 것이며 신규 공개 원본 확보, 독립 라벨 검토, 실제 모델 호출·선정 결과가 아니다. 기존 합성 720건과 공개 12건을 신규 독립 세션 평가 완료로 재계산하지 않는다.

| 계약 항목 | 실행 전에 고정할 내용 |
|---|---|
| 자료 계보 | 자료 ID, 원본 URL·커밋, 라이선스, 원본/변환 파일 SHA-256, 변환 코드 버전, 공개 원본/재구성/합성 구분 |
| 분할 단위 | 세션·사용자·기기·계열·동일 신호 패턴 기준 개발/보정/평가 분리, 중복 검사 결과, 데이터 동결 버전 |
| 라벨·기대 결과 | event/session ID, 입력 시각·순서, 근거 이벤트 ID, 기대 제한·관련/무관 세션·다음 접근, 작성자·독립 검토자·불일치 처리 |
| 공통 입력 | 같은 정보·근거·선택지 제공, 정답 필드는 분석 입력 제외, 한국어/영문·정보 부족·지시문 포함 로그·선택지 순서 변형 구분 |
| 비교 경로 | 규칙 전용, 규칙+생성형, 규칙+판단 모델+선택적 생성형. AI는 관찰 모드이며 최종 허용·회수를 변경하지 않음 |
| 실행 조건 | 모델 ID/버전·가중치 지문, 프롬프트/규칙/정책 지문, 추론·입출력 상한, 하드웨어·지역, 콜드/웜, 반복 수·동시성·기간 |
| 품질 지표 | 혼동행렬·Precision/Recall/F1/FPR, 미탐·오탐·정상 업무 유지, 근거 없는 주장·근거 ID 충실도, JSON 유효율·오류율, 보정 시 Brier score |
| 시간·비용 | 모델 단독과 네트워크·재시도·후속 호출 포함 사건당 전체 P50/P95, 요청·토큰·실제/추정 비용과 불확실성, 시간초과·복구 |
| M3 앱 상태 | 접수·처리·회수·다음 접근 거부 시각, 관련/무관 세션 수, 대기·처리·실패 수, 재전달/중복 효과, 정상 업무 영향 |
| 중단·채택 | 요청/토큰/금액/시간 상한, 필수 안전 기준, 접근·라이선스·장비 제약, 미측정 이유, 채택/보류 근거·검증자 |

같은 세션의 여러 모델 응답과 반복 실행을 독립 공격 표본으로 세지 않는다. 분류와 한국어 설명은 다른 과제로 평가하며 서로 다른 기능을 한 성능 순위로 합치지 않는다. 실제 모델·도구 시험은 [멘토링 계획](mentoring-priority-roadmap.md)과 [기술 비교 대장](technology-decisions/README.md)의 담당·기한·실행 범위를 따른다.
