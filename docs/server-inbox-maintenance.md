# 서버 inbox 영수증 보관 이관

`SignalInbox`의 완료·실패 영수증을 같은 SQLite DB의 압축 archive segment로 옮겨 hot 공간을 확보한다. 원래 payload·결과·오류·내용 지문·tenant/event ID·접수 및 완료 시각·시도 횟수를 보존한다. 조회·중복 검사·무결성 검사는 hot과 archive를 함께 읽는다.

`pending`·`processing`과 lease·재시도 상태는 이관하거나 초기화하지 않는다. archive는 terminal 영수증의 저장 위치이며 새 처리 상태가 아니다. `failed`도 그대로 보존하며 그 단어만으로 정책 효과가 없었다고 단정하지 않는다. 이관은 새 관측 적용·허용 발급·접근 복구를 수행하지 않는다.

## 실행

local/test 환경에서 앱·worker가 실제로 공유하는 DB를 지정한다. `--database`를 생략하면 `ZERO_TRUST_DB_PATH`를 따르며 CLI는 기존 inbox 환경 설정과 기본 archive 한도를 사용한다. 개인키·API 키·네트워크는 필요하지 않다. production 환경에서는 실행을 거부하며 새 HTTP 관리 endpoint는 추가하지 않는다.

```sh
python -m scripts.signal_inbox status --database runtime/zero-trust.sqlite3
python -m scripts.signal_inbox compact --database runtime/zero-trust.sqlite3 --limit 5000
```

예시 경로는 실제 `ZERO_TRUST_DB_PATH`로 바꾼다. Docker named volume의 DB는 호스트의 같은 이름 파일과 다르므로 해당 볼륨을 공유한 승인된 실행 환경에서 명령을 수행한다. 실행 중인 DB를 복사·정리한 뒤 원본에 덮어쓰지 않는다.

`compact --limit`은 한 번에 옮길 최대 terminal 행 수이며 1~10000을 허용한다. 기본 batch는 5000이다. 후보·남은 archive 용량·segment 크기에 따라 더 적게 옮길 수 있다. terminal 후보가 없으면 `compacted: 0`, `segments_created: 0`으로 정상 종료한다. 후보가 있지만 archive 한도가 찼으면 기록을 그대로 두고 실패한다. 처리 대기 중인 관측을 지워 공간을 만들지 않는다.

유효한 CLI 인자를 받은 뒤 설정·저장·용량 검증이 실패하면 종료 코드 1과 제한된 `CONFIG_OR_STORAGE_UNAVAILABLE`을 반환한다. 잘못된 명령 인자는 argparse 오류로 종료 코드 2다. 본문·토큰·DB 경로·예외 원문을 출력하지 않으며 HTTP 429는 새 접수 API의 용량 거부 응답이다.

상태 조회와 이관은 같은 저장 계약을 먼저 검증한다. app·worker·watchdog와의 경합은 SQLite `synchronous=FULL`, `BEGIN IMMEDIATE`로 직렬화한다. 별도 장기 OS lock으로 서비스를 정지시키는 방식이 아니며, segment 저장·hot 삭제·메타데이터 갱신은 같은 트랜잭션이다. 새 접수 중 자동 이관과 새 행 저장도 함께 commit하거나 롤백한다.

## 자동 이관과 유한 보관

전역 또는 해당 테넌트의 hot 보관 한도에 새 접수가 걸리면 terminal 후보를 이관해 필요한 공간을 확보한다. 해당 테넌트 hot 한도가 찼으면 그 테넌트의 terminal을 우선하고, 전역 한도만 찼으면 접수 시각·tenant·event 순으로 골라 archive의 테넌트 한도가 찬 후보는 건너뛴다. pending·processing 한도는 그대로 검사한다. 이관 가능한 terminal 행이 없거나 archive·byte 상한에 걸려 공간을 확보하지 못하면 새 접수를 저장하지 않고 기존 429/backpressure를 유지한다. 이미 보관한 정확한 재전송을 새 관측으로 계산하지 않는다.

| 항목 | 기본값과 의미 |
| --- | --- |
| hot 행 | 10000. pending·processing과 이관 전 terminal 행 포함 |
| pending·processing | 합계 1000. 이관으로 줄지 않음 |
| archive 행 | 전역 100000. 테넌트별 기본 archive 상한도 전역 상한과 같음 |
| archive segment | 1000 |
| 이관 batch | 5000 |
| payload·result JSON | 각각 최대 1MiB |
| 원문 한 행 | 최대 5MiB |
| segment 원문 | 최대 16MiB |
| segment 압축값 | 최대 16MiB+64KiB |
| archive 원문·hot 자료 | 합계 최대 128MiB |

hot byte는 내부 전체 행의 canonical JSON byte 합, archive byte는 압축을 푼 행 목록 JSON byte 합이다. DB 파일 크기·프로세스 RSS 한도가 아니다. Python 설정의 허용 상한은 hot 100000행, archive 1000000행, segment 10000개, batch 100000개이며 CLI `--limit`의 상한 10000과 구분한다.

archive 행 한도 0은 이관을 비활성화한다. 압축 archive도 유한하며 terminal 영수증을 자동 삭제하지 않는다. 기본 hot 한도 10000을 전체 논리 영수증 수의 상한으로 읽지 않는다. 반대로 archive 100000행을 크기와 무관하게 항상 보관할 수 있다는 뜻도 아니다.

HTTP 요약의 `pending`, `processing`, `completed`, `failed`, `total`과 완료 지연 표본은 해당 테넌트의 hot·archive 전체를 포함한다. 추가된 `active_records`는 terminal을 포함한 hot 행 수이며 `archived_records`는 archive 행 수다. `active_records`를 pending·processing 합계로 해석하지 않는다. 전역 보관 상태는 로컬 `storage_status()`와 `status` CLI에서 확인한다. Python 이관 인터페이스는 `compact(limit=...)`다.

로컬 상태에는 전역 `active_records`, `archived_records`, `archive_segments`, `total_records`, 행·segment·batch 한도, `active_bytes`, `archive_bytes`와 고정 byte 한도가 나온다. `compact`는 같은 상태에 `compacted`, `segments_created`를 추가한다. 사용자 지정 Python 한도를 썼다면 같은 DB의 실행자들도 맞춰야 한다. 기존 보관량보다 낮춘 한도는 자동 삭제로 맞추지 않고 초기화·읽기를 거부하므로 자료에 맞는 한도를 복구한다.

## 조회·재전송과 정책 효과

이관된 event ID도 `GET /zero-trust/signals/inbox/{event_id}`에서 같은 공개 영수증을 반환한다. 원본 payload·서명·접수자·lease 토큰을 HTTP 응답에 추가로 노출하지 않는다. 다른 테넌트 조회는 계속 404다. archive에는 전체 private 행을 보존하므로 압축 파일을 공개 결과물로 배포하지 않는다. 압축은 암호화·익명화가 아니다.

정확한 재전송은 최초 신선도 기간이 지나도 같은 영수증과 `duplicate=true`를 받을 수 있다. **현재 출처·키·종류/주체 범위·호출자 역할·테넌트와 서명 검증은 계속 필요하다.** 이 검증을 통과해도 같은 ID에 변경한 서명 봉투를 보내면 기존 409이며 새 ID로 바꿔 성공 처리하지 않는다. 폐기된 키의 재전송을 이관 때문에 승인하지 않는다.

worker는 archive의 terminal 영수증을 다시 claim하지 않는다. 이전 정책 효과의 ACK 기록을 잃은 경우에는 기존 journal 표식을 대조해 완료 영수증만 복구할 수 있다. 이 경로는 현재 키가 나중에 폐기됐더라도 이미 기록한 효과를 확인할 뿐 새 정책 효과를 만들지 않는다. 수집기의 `acknowledged`는 서버의 내구 접수이며 서버 worker의 정책 완료·보호 자원 차단과 구분한다.

## 스키마 이행과 운영 경계

inbox의 독립 format marker와 영구 `PRAGMA application_id=0x5A544932`를 사용한다. 정책 journal이 사용하는 `PRAGMA user_version=2`는 변경하지 않는다. legacy inbox의 원래 행을 검증한 뒤 같은 SQLite 트랜잭션에서 새 archive·메타데이터·format을 초기화한다. 외부 application ID, 알 수 없는 형식, marker·필수 표·메타데이터의 누락·불일치는 신규 DB로 재초기화하지 않고 거부한다.

업그레이드 전 앱·worker·watchdog 및 같은 DB의 관리 CLI를 중지하고, DB·정책·공개키 등록·감사의 일관된 사본을 보호한다. 이후 같은 DB에 접근하는 모든 프로세스·관리 도구·컨테이너 이미지를 새 형식 지원 코드로 맞춘다. 구형 worker나 CLI를 섞어 실행하거나 코드만 downgrade하지 않는다. 현재 mTLS runtime의 같은 directory `up`은 이미지 재빌드·재발급 명령이 아니므로 기존 이미지를 재시작한 것만으로 업그레이드했다고 판단하지 않는다.

매 저장 연산은 보관한 hot·archive를 검증하므로 비용과 복원 메모리는 전체 보관량에 따라 증가한다. O(1) 조회·처리량 향상·무한 지속 운영을 보장하지 않는다. SQLite 빈 page를 재사용할 수 있으나 `VACUUM`, 파일 축소·보안 소거를 보장하지 않는다. 해시·메타데이터 검증은 전체 DB 교체·과거 DB 복원·특권 호스트 변조를 막는 원격 anti-rollback 증명이 아니다.

[정책 journal 이관](policy-journal-maintenance.md), [수집기 tombstone·입력 회전](continuous-signal-collector.md)은 별도 저장 경계다. 세션 버전 200, 유한 journal·spool 한도, 정적 신뢰 재료의 수명과 C04 미통합, 승인된 위험 해제·앱 DB 백업/복원은 여전히 남는다. 옛 백업을 덮어써 이미 소비·회수한 허용을 되살리는 복구를 하지 않는다.

## 검증 범위

hot·archive의 동일 공개 영수증·중복/충돌·tenant 격리, terminal만 이관, 현재 권한·키 폐기, 전역·테넌트 용량과 byte 한도, schema 이행·누락·손상 거부를 확인한다. segment 저장·hot 삭제·checkpoint·새 접수 commit의 실패·프로세스 종료·경합에서도 pending·lease·시도·ACK 복구와 정책 효과의 중복 방지가 유지되어야 한다. 실제 실행 커밋·환경·결과와 팀원 독립 재현은 해당 검증 기록으로 구분하며 예상 시험 수를 성공 결과로 사용하지 않는다.

### 2026-11-05 검증 기록

- 시험 fixture를 수정한 `c34677e` 기준 전체 pytest **1626개 통과**, 기존 Starlette 의존성 경고 1건, 110.15초를 확인했다. 이 수정에서 앱·스크립트 코드는 바뀌지 않았다.
- 실제 mTLS Docker 검사는 clean 소스 `752df45`에서 **30/30 통과**했다. 실행한 app·scripts·설정의 SHA-256은 현재 코드와 일치한다. terminal 이관 전후 pending·processing·lease 보존, 이관 영수증의 정확한 재전송 202·내용 충돌 409, 앱·worker 재시작 후 처리 복구와 회수된 접근의 차단을 확인했다. 시험 컨테이너·볼륨·네트워크 잔여는 각각 **0**이다.
- 별도 프로세스·HTTP 시험의 **10002개**는 terminal 자료를 단일 SQL 트랜잭션으로 대량 적재한 뒤 실제 HTTP 접수·재시작·조회·누적 지표를 대조한 저장 경계 사례다. 10002회 HTTP 요청의 처리량·성능 시험이 아니다. 물리 호스트·전원 손실과 팀장 환경의 독립 재현은 포함하지 않는다.
