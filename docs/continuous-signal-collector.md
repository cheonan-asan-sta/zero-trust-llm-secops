# 로컬 관측의 지속 수집

[지속 관측 수집기](../scripts/continuous_signal_collector.py)는 append-only JSONL 파일의 새 줄을 읽어 SQLite에 보존하고, 서명한 관측을 기존 M3 수신 API로 계속 전달한다. 한 수집기는 하나의 관측 종류와 명시한 주체만 담당한다. 실제 IdP·EDR 센서가 아니며 데이터는 합성·허용된 로컬 시험 자료를 사용한다.

```text
input.jsonl 새 줄 → 관측·입력 커서를 SQLite에 함께 저장
                 → 서명 봉투 저장 → POST /zero-trust/signals/inbox
                 → 확인된 202 영수증 → 수집기 acknowledged
                    별도 서버 worker → 정책 제한·회수 → 다음 업무 접근 거부
```

수집기의 `acknowledged`는 **서버가 입력을 내구 접수했다는 뜻**이다. 서버 worker의 `completed`, 정책 반영 또는 실제 보호 자원 전달 결과와 다르다. 서버가 이미 `failed`로 보관한 입력도 유효한 접수 영수증일 수 있으므로 [M3 영수증 조회](m3-durable-signals.md#http-입력응답)와 세션·접근 결과를 별도로 확인한다.

## 초기화와 서버 연결

프로젝트 Python 환경에서 다음처럼 새 디렉터리를 초기화한다. 기존 파일은 덮어쓰지 않는다.

```sh
python -m scripts.continuous_signal_collector init \
  --directory runtime/continuous-collector \
  --tenant local --source-id local-identity-observer \
  --kind identity --subject demo-user
```

| 파일 | 용도 |
|---|---|
| `config.json` | tenant·source·key·종류·허용 주체 |
| `private.pem` | 수집기 전용 Ed25519 개인키. API·worker에 전달하지 않음 |
| `sources.json` | 해당 관측 출처의 공개키·종류·주체 권한 등록 |
| `input.jsonl` | 새 관측을 끝에 추가할 입력 파일 |
| `state.sqlite3` | 첫 run/status 때 생성하는 입력 커서·보관 관측·서명 봉투·접수 확인 상태 |
| `collector.lock` | 실행 중 단일 수집기 프로세스의 OS 잠금 |

`--subject`를 반복하면 같은 종류의 여러 주체를 허용한다. 기기 수집기는 별도 디렉터리·별도 키로 `--kind device --subject demo-device`처럼 만든다. 처음 발급한 서명키의 등록 유효기간은 7일이며 이 수집기가 서명키를 자동 교체하지는 않는다.

서버에는 다음 조건을 맞춘다.

1. 기존 서버 출처가 있으면 새 `sources.json`의 `sources` 항목을 **서버 공개 등록에 합친다**. 기존 등록을 새 파일 하나로 덮어쓰지 않는다. 같은 테넌트·source ID 중복과 다른 출처 간 공개키 공유를 피한다. 새 키는 `observation_kinds`가 지정된 관측 전용이며 기존 전체 세션 증명이나 MFA 성공을 주장할 수 없다.
2. API와 서버 worker의 `TRUSTED_SIGNAL_SOURCES_PATH`를 합친 공개 등록으로 맞춘다. 두 서버 프로세스의 `ZERO_TRUST_DB_PATH`도 같아야 한다. 환경변수·마운트 설정을 바꿨다면 해당 프로세스를 재시작한다. 기존 mTLS 프로필을 사용하는 경우 그 프로필의 관리 절차를 따른다.
3. 호스트의 같은 사용자로 실행하는 새 격리 시험에서는 생성한 `sources.json`을 직접 읽을 수 있다. Docker에서는 **공개 등록 파일만** 비관리자 UID 10001이 읽을 수 있도록 준비하고 읽기 전용으로 마운트한다. 초기 파일은 접근을 제한해 생성하므로 컨테이너에 마운트할 공개 사본의 읽기 권한도 확인한다. 개인키 디렉터리는 공유하지 않는다.
4. HTTP API 키 인증을 쓰면 수집기 환경변수 `SIGNAL_COLLECTOR_API_KEY`에 기존 analyst 권한 키를 제공한다. 그 키의 테넌트는 수집기 설정과 같아야 한다. 키를 명령 인자·입력 JSONL·보고서에 쓰지 않는다. 로컬 인증 비활성 환경의 기본 테넌트는 `local`이다.

기존 로컬 API·worker 실행 방법은 [M3 명세](m3-durable-signals.md#별도-worker-실행과-앱-지표)를 따른다. 새 수집기를 켜는 것만으로 서버 worker가 시작되거나 세션이 생성되지는 않는다. 관련 세션이 없는 시험에서는 관측이 정상 접수돼도 변경 세션 수가 0일 수 있다.

## 입력·실행·상태 확인

`input.jsonl` 끝에 UTF-8 JSON 한 줄과 줄바꿈을 추가한다. 다음은 identity 입력 형식이며 `observed_at`은 실제 관측 시각으로 바꾼다. 시각에는 시간대가 있어야 하고 미래 시각은 거부한다.

```json
{"event_id":"identity-disabled-001","observed_at":"2026-11-04T00:00:00Z","observation":{"kind":"identity","subject_id":"demo-user","active":false,"authentication_result":"failure"}}
```

기기 수집기의 `observation` 형식은 다음과 같다.

```json
{"kind":"device","subject_id":"demo-device","managed":true,"security_posture":"compromised"}
```

identity는 `active`와 `authentication_result`(`success/failure/unknown`), device는 `managed`와 `security_posture`(`healthy/at_risk/compromised/unknown`)를 받는다. 입력에는 `event_id`, `observed_at`, `observation`만 넣으며 tenant·출처·서명·발급 시각은 수집기가 설정으로 결합한다.

서버 주소에 맞춰 실행한다. 아래 주소는 예시이며 기본값도 `http://127.0.0.1:18080`이다.

```sh
python -m scripts.continuous_signal_collector run \
  --directory runtime/continuous-collector \
  --base-url http://127.0.0.1:18080 --poll-seconds 0.5
```

새 줄이 추가되면 계속 처리한다. SIGINT/Ctrl+C 또는 SIGTERM으로 종료하며 같은 디렉터리와 대상 설정으로 다시 실행하면 저장된 커서와 미확인 관측을 이어간다. 끝의 줄바꿈이 없는 부분 줄은 아직 기록 중인 것으로 보고 커서를 전진시키지 않는다.

```sh
# 실행 중에도 같은 대상 설정으로 보관 상태 조회
python -m scripts.continuous_signal_collector status \
  --directory runtime/continuous-collector --base-url http://127.0.0.1:18080

# 입력 한 줄 포착과 전달 한 번만 시도
python -m scripts.continuous_signal_collector run \
  --directory runtime/continuous-collector --base-url http://127.0.0.1:18080 --once
```

`status`는 고유 관측 수 `captured`, `acknowledged`, `pending`, 입력 바이트 `offset`, 제한된 `last_error`를 출력한다. 서명·관측 본문·개인키·API 키는 출력하지 않는다. `--once`는 전체 입력이나 대기열을 배출하는 명령이 아니며 종료 코드 0도 서버 정책 완료를 뜻하지 않는다. 재시도·상한에 걸리면 1을 반환한다.

## 전달·재시작 계약

| 상황 | 수집기 동작 |
|---|---|
| 포착 직후 종료 | 관측과 커서를 같은 SQLite 트랜잭션에 저장해 재시작 후 이어감 |
| POST·응답 유실 | 저장한 `issued_at/expires_at/signature`와 관측 내용으로 먼저 재전송 |
| HTTP 202 | tenant·event ID·영수증 상태·중복 필드를 검사한 뒤 접수 확인 기록 |
| 오래된 봉투의 HTTP 401 | 발급 후 60초 초과 또는 만료일 때만 같은 event ID·관측 시각·주장을 보존한 새 서명 변형을 추가해 시도 |
| HTTP 409 | 저장한 기존 서명 변형을 대조하고 그중 하나의 정확한 202로만 확인. 충돌을 성공 처리하거나 새 ID로 우회하지 않음 |
| 키 폐기·종류/주체 권한 거부·전송 실패 | pending과 제한된 오류를 보존하고 지수 지연 후 재시도. 접근 허용을 복원하지 않음 |
| 같은 ID·다른 관측 | 입력 충돌로 중단. 기존 관측을 덮어쓰지 않음 |

전달은 최소 한 번이며 서버의 이벤트 중복 방지와 함께 사용한다. 관측마다 서명 변형을 최대 16개 보존하고 소진하면 `ENVELOPE_LIMIT` 상태로 pending을 유지한다. 로컬 공개 등록과 서버 등록의 현재 권한을 모두 확인하며, 새 서명이 서버의 출처·키 거부를 우회하지 않는다.

설정·입력의 절대 경로·대상 URL·TLS 프로필 경로·서명키는 spool에 연결한다. `run`과 `status`에는 같은 대상 URL과 TLS 프로필을 사용한다. 기존 spool을 다른 테넌트·키·입력·목적지로 바꾸거나 DB를 삭제해 미확인 관측을 잊는 자동 복구는 하지 않는다. 재시작 뒤 이미 읽은 앞부분이 바뀌거나 파일이 저장된 커서보다 짧아졌으면 오류로 중단하며 커서를 0으로 초기화하지 않는다.

## 전송과 크기 제한

기본 HTTP 전송은 loopback origin만 허용하며 환경 프록시·redirect·내부 자동 재시도를 사용하지 않는다. HTTPS는 기존에 허용된 mTLS 클라이언트 프로필을 `--tls-profile /absolute/collector-client.json`으로 지정한다. `--base-url`의 host·port가 그 프로필과 같아야 하며 서버 인증·pin 검증 실패에 HTTP로 전환하지 않는다. 기존 TLS 클라이언트 키와 관측 서명키의 역할은 별개이고 이 실행기가 TLS 권한을 추가하지 않는다.

| 제한 | 값과 의미 |
|---|---|
| 입력 파일 | 최대 16MiB, 이미 읽은 내용도 포함 |
| 한 줄 | 줄바꿈을 포함해 최대 64KiB |
| `--max-pending` | 기본 1000, 미확인 관측의 포착 상한 |
| `--max-records` | 기본 10000, 확인된 관측까지 포함한 전체 보관 상한 |
| `--poll-seconds` | 기본 0.5초, 허용 범위 0.01~60초 |
| 포착·전달 실행자 | 같은 디렉터리에서 OS 잠금을 가진 프로세스 1개 |

상한에 닿으면 새 줄의 커서를 전진시키지 않고 `backpressure`를 표시한다. 접수 확인된 관측도 자동 삭제하지 않으므로 전체 보관 상한은 ACK만으로 비워지지 않는다. 파일 회전·아카이브·spool 이전·키 교체는 별도 절차가 필요하다. 매 포착 때 읽은 입력 앞부분과 보관 레코드를 검사하는 로컬 구현이며 대용량 처리량이나 운영 보존 체계의 검증 결과가 아니다.

## 검증과 범위

이 문서는 사용 계약과 재현 절차다. 실제 시험 결과·통과 수·팀장 환경의 재현 여부는 해당 PR의 실행 기록을 따른다. 시험 대상은 입력/커서 원자성, 실제 별도 프로세스 종료·재시작, POST 전후 응답 유실, 서명 변형 충돌, 권한·전송·상한 거부와 서버 정책 반영의 구분이다.

수집기는 local/test 전용이다. 정상·heartbeat 관측으로 MFA·새 grant·권한 복구를 증명하지 않고 기존 위험 제한을 자동 해제하지 않는다. 신호가 새로 오지 않았다는 이유만으로 세션을 만료·회수하는 watchdog도 이번 범위에 포함하지 않는다. 실제 IdP/EDR 연동·자동 운영 장애 복구·독립 팀원 재현·탐지 품질 개선과 구분한다.

기본 `runtime/continuous-collector/`와 검증용 `runtime/collector-validation/`은 Git에서 제외하며 Docker build context에서도 `runtime`을 제외한다. 개인키·spool DB·비공개 입력을 통째로 공유하지 않고 공개 설정·비밀값을 제거한 결과와 실행 커밋만 인계한다.
