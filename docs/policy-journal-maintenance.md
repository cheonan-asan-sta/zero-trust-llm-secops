# 정책 저널 보관 이관

정책 journal의 오래된 행을 같은 SQLite DB의 압축 segment로 옮겨 활성 행 공간을 확보한다. 각 행의 원래 `seq`, canonical payload 문자열, 이전 hash와 record hash를 보존한다. 읽을 때 archive와 활성 tail을 모두 검증·복원하여 기존 정책 로직에 전체 이력을 제공한다.

세션 이력·최신 판단, 평가 이벤트 중복, 누적 위험 제한, 허용 소비·회수, 관측 결과와 worker의 ACK 복구 표식은 계속 같은 논리 이력에 남는다. 이관 자체는 세션 버전을 늘리거나 허용·권한을 발급하지 않는다. 수집기 spool의 tombstone 정리 및 서버 inbox 영수증 보관은 별도 저장 계약이다.

## 실행

local/test 환경의 프로젝트 Python과 **앱·worker·watchdog가 실제로 공유하는 DB**를 사용한다. `--database`를 생략하면 `ZERO_TRUST_DB_PATH` 설정을 따른다. 네트워크·개인키·API 키는 필요하지 않으며 production 환경에서는 CLI를 거부한다.

```sh
python -m scripts.policy_journal status --database runtime/zero-trust.sqlite3
python -m scripts.policy_journal compact --database runtime/zero-trust.sqlite3 --limit 5000
```

예시 DB 경로를 실제 경로로 바꾼다. Docker named volume 안의 DB는 호스트의 같은 이름 파일과 다르므로 해당 볼륨을 공유한 승인된 실행 환경에서 명령을 수행한다. DB 파일을 다른 위치로 복사하여 정리한 뒤 실행 중인 원본에 덮어쓰지 않는다.

`compact`의 `--limit`은 한 번에 옮길 최대 행 수이며 허용 범위는 1~10000이다. 생략하면 기본 batch 5000을 사용한다. 현재 행 수·남은 archive 용량·segment 크기에 따라 그보다 적게 옮길 수 있다. 빈 활성 tail은 0개를 반환한다. `status`와 `compact`는 기존 전체 이력을 먼저 검증하며, 첫 실행에서는 아래의 legacy 스키마 이행이 일어날 수 있다.

app·worker·watchdog와의 경합은 별도 OS lock 대신 SQLite `synchronous=FULL`, `BEGIN IMMEDIATE`로 직렬화한다. 사전 검증·segment 저장·활성 행 삭제·checkpoint 갱신을 같은 트랜잭션에서 수행한다. 저장·검증·용량 오류나 뒤따르는 도메인 작업의 실패에는 트랜잭션 전체를 롤백한다. 완료된 이관을 다시 실행하면 남아 있는 다음 활성 prefix를 대상으로 한다.

## 자동 이관과 상태

새 쓰기의 사전 용량 검사에서 활성 행 상한을 넘을 때 기본 5000개를 이관하여 필요한 공간을 확보한다. 여러 판단과 관측 표식을 쓰는 작업도 같은 트랜잭션을 사용한다. 공간·byte 한도를 확보할 수 없으면 새 쓰기를 거부하며, 일부 세션만 성공한 것으로 기록하지 않는다. 같은 한도 안에서 이미 보관한 기록은 읽을 수 있다.

| 상태 필드 | 의미 |
| --- | --- |
| `active_records` | 현재 `journal` tail 행 수 |
| `archived_records` | 압축 segment에 보관한 행 수 |
| `archive_segments` | 보관 segment 수 |
| `total_records` | archive와 tail을 합친 전체 논리 행 수 |
| `active_bytes` | 활성 payload의 UTF-8 byte 합 |
| `archive_bytes` | 압축을 푼 segment JSON의 byte 합. 행 메타데이터 포함 |
| `max_active_records`, `archive_batch_size`, `max_archive_records`, `max_archive_segments` | 이번 실행의 행·segment 한도 |
| `max_entry_bytes`, `max_segment_bytes`, `max_total_bytes` | 고정 byte 한도 |

`compact`는 위 상태에 `compacted`, `segments_created`를 추가한다. CLI는 본문·원문 토큰·개인키·DB 경로를 출력하지 않는다. 실패 시 종료 코드 1과 `CONFIG_OR_STORAGE_UNAVAILABLE`을 반환한다. Python 인터페이스는 `ZeroTrustOperations.journal_status()`와 `compact_journal(limit=...)`이다. 운영 HTTP 관리 endpoint를 추가하지 않는다.

## 보관 한도

| 항목 | 기본값 | Python `JournalLimits`의 허용 상한 |
| --- | --- | --- |
| 활성 행 | 10000 | 100000 |
| 자동 이관 batch | 5000 | 100000 |
| archive 행 | 100000 | 1000000 |
| archive segment | 1000 | 10000 |

행·batch·segment 수는 양수이며 archive 행에만 0을 지정해 자동·수동 이관을 비활성화할 수 있다. CLI와 기본 앱은 기본 한도를 사용한다. 사용자 지정 한도는 Python `JournalLimits` 설정이며 이 CLI의 추가 옵션이 아니다. 기존 보관량보다 한도를 낮추면 기록을 삭제·요약하지 않고 초기화·읽기를 거부하므로 자료에 맞는 원래 한도를 복구해야 한다.

고정 한도는 payload 한 행 1MiB, segment 원문 16MiB, segment 압축값 16MiB+64KiB, archive 원문과 활성 payload 합 128MiB다. 행·segment 수, SQL byte 합·최대 크기를 먼저 제한하고 압축 해제의 출력·종료·후속 데이터를 검증한다. 어느 한도든 먼저 도달할 수 있어 기본 archive 100000행을 항상 저장할 수 있다는 뜻은 아니다. 이 값은 프로세스 RSS·전체 SQLite 파일 크기의 상한이나 처리량 보장이 아니다.

## 스키마·무결성과 복구 경계

기존 `PRAGMA user_version=0`의 journal은 같은 SQLite 트랜잭션에서 version 2 메타데이터와 archive 표를 추가한다. 기존 순번·payload·체인을 검증한 뒤 이행하며, 기존 legacy 행이 10000개 또는 현재 활성 한도를 넘으면 이행 전체를 거부한다. version 2에서 필수 표·메타데이터가 사라졌거나 version 0에 새 archive 표가 섞여 있으면 새 DB로 재초기화하지 않는다.

전체 archive와 tail의 연속 순번, segment 순서·크기·digest, checkpoint, payload canonical 표현, 원래 hash 체인을 매 읽기에서 검증한다. archive에만 남은 소비·회수·중복·관측 표식도 정책 조회와 판단에 포함한다. 비용과 복원 메모리는 전체 이력에 따라 증가하므로 O(1) 조회·대용량 성능 개선으로 해석하지 않는다.

업그레이드 전에는 정책·공개키 등록·감사와 DB의 일관된 사본을 보호한다. 이행·이관한 DB를 옛 코드에 연결하는 downgrade는 지원하지 않는다. 옛 백업을 덮어써 이미 회수·소비한 허용을 되살리지 않는다. 이관은 앱 DB의 백업·운영 복원 절차를 구현한 것이 아니며, 전체 DB 교체·과거 상태 복원·특권 호스트 변조를 막는 원격 anti-rollback 증명도 아니다.

압축은 논리 이력을 계속 보관한다. SQLite 빈 page를 재사용할 수 있으나 `VACUUM`, 파일 축소나 보안 소거를 보장하지 않는다. 프로세스 중단의 트랜잭션 원자성과 물리 호스트·전원 손실의 복구 보장을 구분한다.

[서버 inbox 영수증 보관 이관](server-inbox-maintenance.md)은 별도로 기본 hot 10000행과 유한 terminal archive를 관리한다. 일반 세션 평가는 버전 200까지이며 후속 [보안 전용 전이](session-security-transitions.md)만 최대 204까지 허용한다. 수집기 tombstone·회전 한도는 유지한다. C04 자동 갱신이 새 mTLS runtime에 통합되지 않은 정적 신뢰 재료의 수명, 승인된 위험 제한 해제와 앱 DB 백업·복원도 남은 과제다. 따라서 이번 이관으로 무한 지속 운영이 완성됐다고 판단하지 않는다.

## 검증 범위

archive에만 남은 세션 이력·소비된 허용·회수·평가 중복·누적 관측 제한·worker ACK 표식을 대조한다. 용량·byte·segment 상한, 손상·누락·스키마 이행 실패, 이관 전후 프로세스 종료·다중 실행 경합과 실제 보호 자원 차단을 함께 확인해야 한다. 실제 실행 커밋·설정·결과·실행 환경과 팀원 독립 재현은 해당 검증 기록으로 구분한다. 예상 검사 수나 이전 프로필의 결과를 이번 이관의 실제 성공 수로 재사용하지 않는다.

### 2026-11-05 검증 기록

- 최신 `aitest` `6a4adac` 통합본의 macOS / Python 3.14에서 전체 **1546개** 통과, 기존 Starlette 의존성 경고 1건. 신규 시험은 storage 61개, 정책·실제 HTTP 11개, CLI 7개로 총 79개다. Ruff와 diff 검사도 통과했다.
- 실제 mTLS Docker 검증: **26/26 통과**, 소스와 이미지 대조 성공, 시험 컨테이너·볼륨·네트워크 잔여 각각 0. Docker Engine 29.5.2 / Linux arm64의 별도 시험 전용 Colima 환경을 사용했다.
- 실제 DB에 합성 접근 감사 **10020행**을 적재해 archive 5000행·활성 5020행을 확인했다. 이는 저장 경계 시험이며 10020 HTTP 요청의 처리량 측정이 아니다. 이후 실제 mTLS 문서 요청에서 소비된 토큰은 `GRANT_ALREADY_USED`와 403, 미소비 회수 토큰도 403·자원 전달 0회를 확인했고, 수동 이관·앱 재시작 후에도 세션 이력과 차단이 유지됐다.
- 단위·통합 시험에서는 INSERT·DELETE·checkpoint·commit 실패의 전체 롤백, 실제 프로세스 종료 5개 지점, legacy 이행 도중 종료, 잠금 경합·중복/충돌·응답 유실 후 worker 복구를 검증했다. 물리 호스트·전원 손실 시험 및 팀장 환경의 독립 재현은 포함하지 않는다.
- 로컬 검증 통합 커밋은 `af4e092`이며 실행 소스·설정의 SHA-256을 현재 게시 코드와 대조해 불일치 0건을 확인했다. 원본 시험 산출물은 로컬 runtime에 보관하며 PR에는 판정·수치·검증 범위를 요약한다.
