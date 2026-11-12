# 앱 전체 JSONL 저장 계약과 정비 복원

기존 [SQLite 정비 복원](app-state-recovery.md)에 사건·분석 감사·연동 outbox를 함께 묶는 선택형 저장 계약이다. 모든 기록자를 정지·봉쇄한 로컬 정비 경계에서 사용한다. 온라인 백업, 외부 전송의 exactly-once, 임의 시점의 전원 손실이나 전체 관리 저장소 rollback 방어를 보장하지 않는다.

## 저장 모드와 명시적 초기화

SQLite 전용 모드와 전체 모드를 유지하며, 두 모드 모두 정상 작업 기준선과 승인 기록 DB를 함께 보존한다. 전체 모드는 별도 관리 영역을 `init --full-state`로 초기화하고 anchor에 모드를 고정한다. 이후 checkpoint/backup/restore에서 이를 확인하며, 모든 JSONL 파일을 지워도 SQLite 전용 모드로 자동 하향하지 않는다. 기존 SQLite 전용 관리 영역을 임의 편집해 승격하지 않는다. 복구 코드와 앱의 지문이 바뀌면 현재 버전에 맞는 새 체크포인트와 백업을 준비해야 한다.

전체 원본 `data/`에는 다음 파일이 모두 있어야 한다.

| 파일 | 의미 |
|---|---|
| `app.sqlite3` | 정책·세션·토큰 소비·회수·Inbox 및 압축 이력 |
| `app-behavior-context.sqlite3` | 정상 작업 기준선, 승인, 취소, 수집 자료와 판정 이력 |
| `sources.json` | 설정한 경우 현재 공개 출처·키 등록 |
| `storage.json` | 아래 고정 전체 저장 계약 |
| `audit.jsonl` | 기존 AuditStore의 분석·검토 이력 |
| `cases.jsonl` | 기존 CaseStore의 사건 버전·증거·상태 이력 |
| `integration-outbox.jsonl` | CloudEvent ID·본문·전송 상태·시도·다음 재시도 시각 |

`storage.json`의 허용 내용은 다음과 같다. 다른 경로·추가 항목·다른 backend는 거부한다.

```json
{"schema":"app-jsonl-storage-1","files":{"audit":"audit.jsonl","cases":"cases.jsonl","outbox":"integration-outbox.jsonl"}}
```

빈 로그도 실제 빈 파일로 존재해야 한다. 파일 누락·symlink·구형 무체인 감사 자료를 정상 빈 저장소로 처리하지 않는다. 운영자는 실제 앱 설정과 원본 파일을 대조한 후 정지된 경계에서 배치해야 한다. 이 작업이 기존 임의 경로의 기록자를 자동 발견하거나 온라인으로 파일을 이동하는 기능은 아니다.

기준선 DB를 아직 사용하지 않은 원본은 이 파일이 없어도 된다. 이 경우 원본에 파일을 만들지 않고
격리 사본에 검증된 빈 저장소를 만든다. 복원 사본에는 서명으로 고정한 DB가 반드시 있어야 하므로,
복원 후 파일 삭제를 미사용 상태로 취급하지 않는다. 정상 종료 후 남은 SQLite sidecar가 없는 경계를
요구하며 `-journal`, `-wal`, `-shm`이 있으면 원본을 수정하지 않고 거부한다.

```powershell
# 모든 앱·worker·watchdog·사건/outbox 기록자를 정지·봉쇄한 뒤 실행한다.
# data/에 실제 원본과 storage.json, 세 JSONL이 준비되어 있어야 한다.
python -m scripts.app_state_recovery init --full-state --directory runtime/week3/full-recovery
python -m scripts.app_state_recovery checkpoint --directory runtime/week3/full-recovery
python -m scripts.app_state_recovery backup --directory runtime/week3/full-recovery
# backup 출력의 backup_id를 사용한다.
python -m scripts.app_state_recovery restore --directory runtime/week3/full-recovery --backup-id BACKUP_ID
```

관리 키·anchor·현재 승인 pin은 백업과 일반 앱 데이터 밖에서 보호한다. 실패한 checkpoint나 복원 뒤 옛 승인 사본으로 서비스를 재개하지 않는다.

## 검증과 보존

- 각 JSONL은 원래 바이트와 SHA-256·행 수·마지막 chain hash를 보존한다. 중복 JSON key, 불완전한 마지막 줄, 빈 중간 줄, 잘못된 envelope·hash chain·모델을 거부한다.
- 사건·outbox의 버전과 이력은 연속이어야 한다. 이전 이력의 재작성, outbox 이벤트 본문/최대 시도 변경, terminal 상태 이후 재시도는 거부한다.
- outbox는 같은 테넌트의 실제 사건·해당 버전에서 결정적으로 생성한 CloudEvent와 같아야 한다. 불명 사건·다른 테넌트·다른 버전의 내용 혼합을 거부한다.
- 사건 저장 직후 outbox 저장 전에 종료된 합법적인 간극은 `missing_case_events`로 기록한다. 복원 중 새 이벤트를 조용히 만들지 않는다. 기존 reconciler를 실행하면 같은 결정적 ID로 누락분만 생성하며 완료·실패 보관·재시도 중인 기존 이벤트는 재생성하지 않는다.
- 백업에는 SQLite·등록과 세 로그를 같은 인증된 암호문에 넣는다. JSONL은 DB 복사 전후 바이트를 대조한다. 이는 정지·봉쇄 조건을 대체하지 않는다.
- 복원은 새 격리 디렉터리에만 쓴다. 모든 기존 세션을 회수한 뒤 JSONL과 Inbox가 바뀌지 않았는지 다시 검증하고 승인 서명/pin을 발행한다.
- 복원 중 종료·저장 실패에는 이전 승인 pin이 무효화된 상태로 남는다. 부분 사본은 승인되지 않으며, 같은 백업을 재시도하면 새 격리 사본을 검증해 발행한다.
- 기준선 DB는 SQLite 무결성, 정확한 스키마와 전체 해시 체인을 검사해 함께 보존한다. 승인 취소와 정상 판정 이력을 복원 전과 같은 내용으로 유지하므로, 복원으로 승인 사용 횟수가 초기화되지 않는다. 기존 세션 회수는 이 기록을 변경하지 않는다.

수신함 접수 상태와 outbox 전송 상태는 서로 다른 저장 계약이다. `DELIVERED`·`DEAD_LETTER`·`RETRY_SCHEDULED`·`PENDING`, 시도 횟수와 다음 시각을 원래대로 보존한다. 외부 수신자가 처리한 뒤 ACK가 유실된 경우의 중복 전달 가능성은 원래 전달 계약대로 남으므로 수신자도 같은 CloudEvent ID로 중복을 판별해야 한다. 이번 검증은 실제 외부 SIEM/ITSM 전송이 아닌 기존 simulation 상태 기록을 사용한다.

## 기동 승인과 이후 쓰기

전체 모드의 `serve_recovered_app`은 API 키 인증·규칙 분석기와 `AUDIT_BACKEND=jsonl`을 요구한다. SQLite·registry뿐 아니라 `AUDIT_LOG_PATH`, `CASE_LOG_PATH`, `OUTBOX_LOG_PATH`가 승인한 동일 데이터 디렉터리의 위 파일과 정확히 일치해야 한다. 임시 빈 로그나 DynamoDB로 경로를 바꾸면 HTTP를 열기 전에 거부한다.

기준선 DB는 같은 디렉터리의 `app-behavior-context.sqlite3`를 사용한다. 명시적으로 설정한
`BEHAVIOR_CONTEXT_DB_PATH`도 이 경로와 일치해야 한다. 기동 시 서명한 기준선 DB의 기록 수,
바이트 수와 마지막 해시까지의 이력이 보존되는지 확인한다. 승인된 이후 새 기록을 덧붙이는 것은
허용하지만 기존 기록 삭제, 축소, 재작성이나 다른 사본으로의 교체는 거부한다.

서명한 JSONL prefix의 바이트 길이와 hash를 기동 시 확인한다. 정상적인 이후 append는 전체 chain·모델·사건/outbox 관계를 다시 검증해 허용한다. prefix 삭제·축소·재작성이나 다른 세대의 로그 혼합은 거부한다. 전체 모드의 서명된 앱 identity에는 앱과 복원/저장/기동 검사 코드 지문을 함께 결합하므로 SQLite 전용 구형 gate가 새 필드를 무시하고 승인할 수 없다. 코드만 downgrade하거나 변경된 검사 코드로 기존 전체 checkpoint를 재사용하지 않는다. 관리 키는 일반 앱에 마운트하지 않는다.

정상 운영 재개 후 다음 정비의 원본은 현재 활성 복원 사본이다. 모든 기록자를 다시 정지·봉쇄하고 새 최신 checkpoint를 만들어야 한다. 이전 원본이나 예전 백업을 되쓰지 않는다. 이번 실험기는 한 차례 정비·복원과 재시작을 검증하며 반복 정비의 운영 오케스트레이터를 추가하지 않는다.

## 크기와 호환 경계

- JSONL 파일별 8 MiB, 행별 1 MiB, 파일별 10,000행.
- 정책 SQLite와 기준선 SQLite는 각각 32 MiB 이하이며, DB 둘과 등록 파일 및 JSONL 원본의 합계도 32 MiB 이하로 제한한다. 최종 암호화 envelope는 64 MiB 이하이다. 어느 한도가 먼저 차도 삭제나 요약으로 우회하지 않는다. 라이브 기준선 저장소의 128 MiB 용량을 전부 백업할 수 있다는 뜻이 아니다.
- 구형 무체인 감사·DynamoDB·임의 스키마의 자동 변환은 지원하지 않는다. 별도 검토/이행 후 새 전체 관리 영역을 인수해야 한다.
- 기존 앱 저장소의 append/동시성·fsync 계약을 변경하지 않는다. 같은 파일에 다중 프로세스가 동시에 쓰는 환경을 허용한 것으로 해석하지 않는다.
- 전체 파일과 SQLite 상태를 읽어 검증하므로 대용량 성능·RSS 한도·무한 보관·원격 witness·운영 RTO/RPO를 보장하지 않는다.

## 재현

```powershell
python -m pytest tests/test_app_storage_recovery.py tests/test_app_state_recovery.py -q
docker build --file Dockerfile --tag app-full-recovery:local .
python -m scripts.test_app_recovery_runtime --full-state --image app-full-recovery:local --directory runtime/week3/full-recovery-reproduce01
```

실험은 새 소유 프로젝트만 만들고 정리한다. 보고서에서 `full_state: true`, `passed: true`, 모든 검사 true, 정리 컨테이너/볼륨 0을 함께 확인한다. 소스/실행 이미지 지문도 대조한다. 재현 시마다 새 directory를 사용한다.

기준선 DB에는 저장 검증용 합성 기록 4개를 넣는다. 기준선, 승인, 사용 판정, 승인 취소가 포함되며,
원본 DB 유실 뒤 복원한 사본의 기록 수와 해시가 같은지 확인한다. 보고서의 `context_records`가 4인지도
확인한다. 이 fixture의 보존 검사는 서명 검증이나 탐지 정확도 시험을 대신하지 않는다.

CI는 기존 앱 정비 복원 단계를 `--full-state`로 실행한다. SQLite 전용 호환 단위 시험도 유지한다. 팀장 보유 케이스의 독립 재현과 실제 운영 승인은 별도이며, 정확한 최종 실행 커밋·시험 수·결과는 PR 검증 기록에 남긴다.

## 2026년 11월 6일 로컬 검증 기록

- 구현 커밋 `b92042053dbb19ae2b1f371803bfd6cb6ba863a1`에서 집중 114개(기존 정비 복원 51개 + 신규 63개)와 Ruff를 통과했다.
- 최종 Mac Python 3.14 전체 회귀는 **2,111 passed / 기존 skip 2 / 기존 경고 1**, 123.58초다. 첫 sandbox 실행은 loopback 바인딩 제한과 macOS 임시 경로 별칭 때문에 실패했고, 허용된 실제 HTTP 실행과 정규 임시 경로로 전체를 다시 검증했다.
- 고정 Linux amd64 시험 이미지의 Ruff와 집중 **114개**도 통과했다(117.76초). Apple Silicon/QEMU 환경이다. 추가 Linux 전체 회귀는 맥 여유 공간 감소 때문에 소유 컨테이너를 명시적으로 중단했으며 종료 137을 성공으로 처리하지 않는다. 전체 Linux/CI 결과는 원격 업로드 후 별도로 확인한다.
- 원본 Dockerfile·고정 Linux amd64 런타임으로 실제 전체 복원 **24/24**를 통과했다. 원본 DB와 세 로그 유실, 복원 중 실제 종료 73, 새 격리 사본 재시도, 잘못된 outbox 경로의 기동 거부, 인증된 HTTP 403과 사건/outbox 테넌트 경계, 두 번 재개한 reconciler의 중복 방지를 확인했다.
- 실행 소스는 위 커밋의 tracked-clean 상태이며 앱 digest와 복원 관련 스크립트 6개의 실행 이미지/로컬 지문을 대조했다. SQLite 49,152 bytes와 JSONL 76,953 bytes·정책 journal 18개를 보존하고 기존 세션 3개를 회수했다. 시험 컨테이너/볼륨 잔여는 **0/0**이다.
- 실제 복원 보고서 SHA-256은 `feaf623dacafde0cc34929dabb0d997c930f4c1f687e72bf1babafda7c15cd53`다. 실행 환경과 합성 fixture를 포함하는 private runtime 전체를 공개 저장소에 올리지 않는다.
- 초기 legacy Docker 빌드는 BuildKit cache mount 미지원으로 중단됐다. 기존 설치된 Buildx를 시험 전용 설정으로 연결한 뒤 원본 Dockerfile을 그대로 빌드했다. 기존 Colima는 이미지 저장소 I/O 오류가 있어 변경하지 않았고, 별도 시험 프로필에서 실행했다.
- 이 기록의 시간은 로컬 시험·가속/실패 주입·정리 비용을 포함하며 운영 성능이나 RTO/RPO 보장이 아니다. 뒤에 추가하는 검증 문서 변경은 구현/실행 소스의 변경과 구분한다.
