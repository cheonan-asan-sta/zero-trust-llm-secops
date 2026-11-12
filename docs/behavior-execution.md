# 승인된 작업의 실행 주체와 반출 목적지 확인

정상 작업 기준선과 운영 승인이 일치해도, 승인된 작업의 자격 증명을 다른 프로그램이 사용하거나
자료를 다른 목적지로 보내는 상황은 기존 관측만으로 구분하기 어렵다. 이 경로는 별도로 등록한
수집기가 실제로 관측한 실행 주체와 목적지를 하나의 행동 수집 건에 연결하고, 사전에 등록한
승인 범위와 비교한다. 확인하지 못한 정보는 `null`로 남긴다.

현재 수집기는 보호된 로컬 파일을 읽어 서명하고 전달하는 어댑터다. 운영체제 프로세스의 무결성을
스스로 증명하거나 실제 EDR, AWS, 네트워크 트래픽을 수집하는 센서는 아니다. 서명은 등록한 상위
관측기가 해당 내용을 제출했다는 근거이며 내용 자체의 독립적인 진실성을 보장하지 않는다.
실제 운영에서는 프로세스와 연결을 관측하는 신뢰된 상위 수집기가 파일을 작성해야 한다.

## 입력 계약

실행 증거의 서명 도메인은 `zt-execution-1`이고 알고리즘은 Ed25519다. 기존 `zt-behavior-1`
행동 수집의 서명 형식은 유지한다. 두 증거를 하나의 임의 신뢰 플래그로 합치지 않는다.

| 필드 | 내용 |
|---|---|
| `tenant_id`, `source_id`, `key_id`, `evidence_id` | 테넌트, 전용 출처, 키, 변경할 수 없는 증거 식별자 |
| `issued_at`, `expires_at`, `observed_at` | 발행 시각, 만료 시각, 실제 관측 시각 |
| `scope` | 기존 행동 수집과 동일한 출처 종류, 사용자, 기기, 자원, 동작, 주체 해시 |
| `session_id`, `session_version`, `session_input_sha256` | 증거가 적용되는 정확한 검증 세션과 입력 |
| `capture_id`, `capture_input_sha256` | 서버에 먼저 접수한 행동 수집 건과 서명 대상 입력의 해시 |
| `event_ids`, `connection_ids` | 해당 수집 건의 전체 이벤트와 연결 식별자 집합 |
| `actor` | 관측한 실행 주체, 작업 식별자와 실행 파일 해시. 미확인 상태는 `null` |
| `destinations` | 관측한 목적지 목록. 미확인 상태는 `null` |
| `signature` | 위 필드 전체에 대한 서명 |

`actor`는 `principal_id`, `workload_id`, `executable_sha256`로 구성한다. 실행 파일 해시는
소문자 SHA-256 값이다. 승인에 적힌 값을 관측값으로 복사하거나 사용자 요청의 `verified=true`를
증거로 받지 않는다. 같은 계정 이름만 같다는 이유로 같은 실행 작업으로 간주하지 않는다.

목적지는 `kind`, `host`, `port`, `path`로 표현한다. `kind`는 `https` 또는 `s3`다.
HTTPS는 포트를 명시하고, S3는 버킷 이름과 `port: null`을 사용한다. 호스트는 소문자 ASCII로
표기하며 끝의 점, 와일드카드, 사용자 정보가 있는 URL은 허용하지 않는다. 경로는 정확한 절대
경로이며 쿼리, fragment, 퍼센트 인코딩, `.` 및 `..` 경로 별칭은 거부한다.

이 비교는 등록한 구조화 값의 일치 확인이다. DNS가 해석한 IP, 실제 TLS 상대 인증서나 리다이렉트
최종 목적지를 검사하는 기능은 아니다. 상위 관측기는 실제로 확인한 최종 목적지를 제공해야 한다.

관측은 증거 발행 전 300초 이내여야 한다. 증거 수명은 최대 120초이며 첫 접수는 발행 후 60초
이내이면서 만료 전이어야 한다. 관측 시각은 연결할 행동 수집의 마지막 이벤트 이후이고 해당 행동
수집의 만료 전이어야 한다. 일부 이벤트만 골라 유리한 실행 증거를 만드는 것은 허용하지 않는다.

## 승인 범위와 판정

새 정상 판정에는 운영 승인 본문의 `execution_policy`가 필요하다. 기존 승인은 그대로 읽고
보존하지만 이 정책이 없으면 정상으로 확정하지 않고 `EXECUTION_POLICY_REQUIRED`로 보류한다.
과거 승인에 정보를 소급해서 채우지 않는다. 실제 관측 전에 새 기준과 승인을 등록한다.

다음은 승인 본문에 추가할 정책의 형태다. 해시와 주체 값은 예시이며 실제 검토한 값으로 지정한다.

```json
{
  "execution_policy": {
    "actor": {
      "principal_id": "backup-service",
      "workload_id": "nightly-backup",
      "executable_sha256": "4444444444444444444444444444444444444444444444444444444444444444"
    },
    "destinations": [
      {
        "kind": "https",
        "host": "archive.example.test",
        "port": 443,
        "path": "/approved-backup"
      }
    ]
  }
}
```

정상 판정은 기존 세션 검증, 기준선, 승인 유효 기간, 범위와 사용 횟수 검사를 모두 통과해야 한다.
여기에 현재 유효한 실행 증거의 주체 세 필드가 승인 주체와 같고, 관측된 각 목적지가 승인 목록에
정확히 포함돼야 한다. 목적지의 호스트 접미사나 경로 접두사 일치로 허용 범위를 넓히지 않는다.

| 상태 | 판정과 이유 |
|---|---|
| 실행 정책 없음 | 보류, `EXECUTION_POLICY_REQUIRED` |
| 실행 증거 없음 | 보류, `EXECUTION_EVIDENCE_REQUIRED` |
| 실행 주체나 목적지가 `null` | 보류, `EXECUTION_EVIDENCE_INCOMPLETE` |
| 증거 만료, 키나 등록 범위 변경 | 보류, `EXECUTION_EVIDENCE_STALE` |
| 같은 수집 건의 유효한 실행 증거가 서로 다름 | 보류, `EXECUTION_EVIDENCE_CONFLICT` |
| 현재 적용 가능한 승인 범위와 확인된 실행 주체 또는 목적지가 불일치 | 위협, `EXECUTION_SCOPE_MISMATCH` |
| 기존 조건과 실행 정책을 모두 충족 | 정상, `APPROVED_BASELINE_MATCH` |

알려진 침해 신호나 명시적인 원격 셸 시도의 위협 판정은 기존처럼 먼저 적용한다. 승인 범위가
불명확하거나 실행 정책 없는 적용 가능한 승인이 함께 있으면 이를 건너뛰어 위협을 확정하지 않는다.

접수된 증거는 덮어쓰지 않는다. 한 수집 건에 만료되거나 불완전하거나 충돌하는 증거가 있으면
나중에 유리한 증거 하나를 추가해 정상으로 바꿀 수 없다. 부족한 사실을 확인한 뒤 새 수집 건과
현재 유효한 세션에 연결된 새 증거로 다시 관측해야 한다.

이 판정은 조사 보조다. `enforcement_eligible`은 `false`이고, 실행 범위 불일치만으로 세션을 회수하거나
새 HTTP 403 접근 집행을 추가하지 않는다. 실제 접근은 기존 정책과 집행 경로가 계속 결정한다.

## 전용 출처와 키 등록

서버의 `TRUSTED_SIGNAL_SOURCES_PATH` 레지스트리에 실행 수집기 전용 공개 키와 `execution_scopes`를
등록한다. 각 범위는 `BehaviorScope`와 같으며 등록된 사용자와 기기를 벗어날 수 없다.
이 출처는 `behavior_scopes`나 `observation_kinds`를 함께 가질 수 없고 완전한 세션 증명을 발행하지
못한다. 같은 테넌트에서 다른 출처와 동일한 공개 키를 공유하는 것도 거부한다.

개인 키는 수집기 디렉터리에만 보관한다. 서버에 설치할 것은 공개 레지스트리 항목이며 기존 서버
레지스트리를 통째로 교체하지 않는다. 로컬 생성 자체가 서버의 신뢰 등록을 완료하지는 않는다.
발급된 출처와 키의 유효 기간 및 범위를 서버 운영자가 확인해야 한다.

CLI는 소유자만 읽고 쓸 수 있는 디렉터리와 파일을 요구한다. POSIX 환경에서는 디렉터리 700과
입력 및 개인 키 파일 600을 사용하며, 심볼릭 링크와 일반 파일이 아닌 입력을 거부한다. 이 검사는
같은 사용자 권한을 가진 악성 프로세스나 호스트 관리자까지 격리하는 보장은 아니다.

## 수집기 실행

먼저 소유자 전용 `scopes.json` 파일에 수집할 정확한 범위를 배열로 작성한다.
아래 명령의 경로와 식별자는 로컬 실행 환경에 맞게 지정한다.

```bash
chmod 600 /path/to/scopes.json
./.venv/bin/python -m scripts.behavior_execution_collector init \
  --directory runtime/execution-collector \
  --tenant tenant-a --source execution-observer --key-id key-1 \
  --scopes /path/to/scopes.json
```

생성한 `sources.json`의 공개 항목을 서버 레지스트리에 검토 후 등록한다. `private.pem`은 서버나
저장소에 올리지 않는다. 수집기는 기본적으로 로컬 또는 테스트 애플리케이션 환경에서만 실행한다.

상위 관측기가 작성하는 JSON 입력에는 표의 운영 필드를 넣되, 다음 외피 필드는 넣지 않는다.
`schema_version`, `algorithm`, `tenant_id`, `source_id`, `key_id`, `issued_at`, `expires_at`, `signature`는
수집기 설정과 현재 시각으로 만든다. `evidence_id`, `observed_at`, 정확한 수집 및 세션 연결,
이벤트와 연결 ID, `actor`, `destinations`는 상위 관측 자료에서 제공해야 한다.
기본 증거 수명은 90초다. 수집기가 대상 수집 해시나 관측 주체를 추측하지 않는다.

```bash
chmod 600 /path/to/observed-execution.json
./.venv/bin/python -m scripts.behavior_execution_collector enqueue \
  --directory runtime/execution-collector \
  --base-url http://127.0.0.1:18080 \
  --input /path/to/observed-execution.json
./.venv/bin/python -m scripts.behavior_execution_collector send-once \
  --directory runtime/execution-collector --base-url http://127.0.0.1:18080
./.venv/bin/python -m scripts.behavior_execution_collector status \
  --directory runtime/execution-collector --base-url http://127.0.0.1:18080
```

API 인증이 필요한 경우 `EXECUTION_COLLECTOR_API_KEY`를 수집기 프로세스 환경에 설정한다.
키 값을 명령 인수나 출력에 넣지 않는다. `send-once`는 한 건을 시도하는 명령으로 상시 실행 데몬은
아니다. 재시도 가능 시각 전에 다시 호출하면 `idle`을 반환할 수 있다.

HTTP는 루프백 주소만 허용한다. 원격 연결에는 `--tls-profile`로 명시한 mTLS 설정과 동일한 HTTPS
호스트 및 포트를 사용해야 한다. 프록시, 리다이렉트나 HTTP 우회는 허용하지 않는다.
기존 mTLS 서비스의 경로 허용 목록에 새 API가 자동으로 추가되지는 않는다. 해당 프로필에
`POST /detections/context/execution-evidence`와 분석가 이상의 API 권한을 별도로 검토해 연결해야 한다.
이 변경을 기존 Docker 전체 mTLS 환경의 통합 완료로 해석하지 않는다.

## 접수와 재전송

서버에서는 행동 수집을 먼저 접수한 다음 실행 증거를 접수한다. API는
`POST /detections/context/execution-evidence`이며 분석가 이상의 인증을 요구한다.
HTTP 201 응답은 `evidence_id`, `input_digest`, `duplicate`를 반환한다. 이는 증거 저장 영수증이며
정상 판정이나 접근 허용이 아니다. 이후 `POST /detections/context/evaluate`로 같은 수집 건을 판정한다.

수집기는 서명한 요청을 SQLite 큐에 저장한 뒤 전송한다. 응답 유실이나 재시작에는 같은 서명과
내용을 재전송하고, 수신 ID와 입력 해시 및 중복 표시가 맞아야 전송 완료로 저장한다.
같은 ID의 내용이 달라지면 충돌로 거부하며 자동으로 새 ID를 만들어 우회하지 않는다.

이미 수락된 요청의 응답만 유실된 경우, 현재 출처와 키가 유효하면 만료 후에도 같은 요청의 중복
영수증을 받을 수 있다. 처음 접수하는 만료 증거는 거부된다. 수집기는 오래된 관측을 새로운 시각으로
재서명하지 않는다. 중복 영수증을 받았더라도 해당 만료 증거는 현재 정상 판정에 사용할 수 없다.

HTTP 401, 403, 409, 422는 자료를 지우지 않고 `rejected`로 보존한다. 통신 실패와 검증되지 않은
응답은 `pending`으로 남기고 재시도 간격을 최대 60초까지 늘린다. 등록 키를 사용할 수 없으면 전송을
중단한 채 자료를 보존한다. 큐는 최대 10,000건과 저장한 요청 합계 32 MiB로 제한하며 한도 초과 시
이력을 지우지 않고 새 접수를 거부한다. 기존 관측 수집기의 큐와 파일 회전 정책은 변경하지 않는다.

## 검증과 평가 자료

```bash
./.venv/bin/python -m pytest -q \
  tests/test_behavior_execution_trust.py \
  tests/test_behavior_execution_integration.py \
  tests/test_behavior_execution_collector.py
```

수집기 시험은 실제 API와 저장소를 사용해 정보 누락, 정상 영수증, 응답 유실, 재시작, 동일 요청
재전송, 만료, 충돌, 잘못된 영수증, 출처 폐기, 파일 권한과 저장 한도를 확인한다. 테스트의 로컬
상위 관측은 통제된 실험 자료이며 실제 프로세스 센서의 정확도를 측정한 결과가 아니다.

기존 240건 회귀와 새 세션 평가 결과는 별도
[평가 결과 JSON](../runtime/m7/behavior-execution-evaluation/report.json)에 연결한다.
수치와 오탐 및 미탐 원인은 [평가 해석](behavior-execution-evaluation.md)에 정리했다.
이 문서의 입력 계약과 기능 검증을 탐지 성능 수치로 대체하지 않는다. 필수 정보가 없어 위협을
보류한 경우도 미탐 집계에서 제외하지 않는다.
