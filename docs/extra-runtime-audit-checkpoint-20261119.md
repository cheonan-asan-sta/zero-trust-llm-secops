# 실행 중 감사 DB의 checkpoint 최소 이력 검증

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합 없음.

## 바뀐 동작

기존 SQLite 체인 검증만으로는 정상적으로 생성된 **과거 DB 전체**를 되돌린 경우를 구분하지 못한다. 선택형 runtime guard는 운영자가 별도로 신뢰한 checkpoint의 seq/digest가 현재 DB에 포함돼야 읽기·쓰기·분석을 허용한다. checkpoint보다 낮은 head와 같은 위치의 다른 이력을 모두 거부한다.

```dotenv
AUDIT_BACKEND=sqlite
AUDIT_DB_PATH=<기존_검증된_DB>
AUDIT_CHECKPOINT_PATH=<기존_checkpoint.json>
AUDIT_CHECKPOINT_SHA256=<외부에_기록한_파일_SHA256>
```

두 checkpoint 설정은 함께 필요하며 SQLite만 지원한다. 기본값은 미설정이다. 초기 DB를 별도 생성하고 기존 `checkpoint` 명령으로 기준을 수집한 뒤, 파일 SHA를 신뢰하는 별도 기록에서 받아 앱에 설정한다. 경로만 지정하거나 다른 backend에 지정하면 설정 검증에서 실패한다. guarded store는 기존 DB만 읽기 전용으로 열어 시작하며 없는 DB 생성·스키마 복구·unguarded fallback을 하지 않는다. 기준을 높일 때는 [단조 갱신](extra-audit-checkpoint-progression-20261119.md)으로 새 파일을 수집하고 검토한 pin으로 앱을 재시작한다. 자동 승격·hot reload는 없다.

## 검증 경계

전체 체인/모델/검토 전이를 확인하는 기존 `_read`를 유지하고 **동일 SQLite snapshot**에서 checkpoint prefix를 확인한다. 매번 파일의 pin·형식·파일 안정성을 새로 확인하며, 전체 scan 후에도 다시 읽어 철회/변조를 거부한다. 오래된 DB를 열어둔 채 메모리에 저장한 과거 성공 결과로 통과시키지 않는다.

저장은 기존 `BEGIN IMMEDIATE`·CAS 검토 동작을 유지한다. 쓰기 전에 검증하고, INSERT/head UPDATE 후 **commit 전**에도 checkpoint를 다시 확인한다. 이 시점에 파일이 철회되면 해당 트랜잭션 전체를 rollback한다. `backup_sqlite`에 guarded store를 넘겨도 복사한 snapshot의 검증에서 이 최소 이력을 유지한다. 독립 CLI는 기존처럼 명시적 `--checkpoint/--checkpoint-sha256`를 받아야 한다.

`integrity()`/readiness에는 `checkpoint_guard.configured`, `minimum_head_verified`만 운영 검증 상태로 표시하고 경로·pin은 노출하지 않는다. `latest_live_state_verified=false`, `independent_storage_verified=false`도 명시한다. 목록·상세·통계·페이지·readiness는 무결성 실패 시 503이고 liveness는 유지된다. 일반 `/analysis`는 기존 API의 provider-error 계약에 따라 502이지만, 모델 호출 전 무결성 검사에서 차단되고 새 감사 결과도 저장하지 않는다. 모든 endpoint의 오류를 503으로 변경했다고 표현하지 않는다.

현재 전체 DB가 기준을 만족하면 과거 시점 cursor 조회와 검토 CAS는 계속 사용할 수 있다. 과거 cursor 자체의 prefix가 구 DB에 맞더라도 현재 운영 최소 이력이 충족되지 않으면 거부한다. 이것은 과거 감사 조회와 현재 운영 허용 여부를 구분하기 위한 것이다.

## 검증 자료

신규 26개 로컬 사례: 완전한 설정과 factory 선택, 설정 오류, guard 없는 직접 생성 거부, 없는/빈/오래된/다른 체인 DB 시작 거부와 원본 보존, 실행 중 파일 철회/변조/pin 오류, scan 중 철회, INSERT 후 commit 전 철회와 실제 rollback, 모든 storage 경계의 정상 구 DB 거부, 기존 검토·cursor 호환, 암호화 backup/restore의 guard 유지, 실제 ASGI 목록/상세/통계/페이지/readiness 503·liveness 200, 분석 전 provider 0회 차단을 포함한다.

실제 systemd/ptrace·공유 참조·HTTP worker 3개 kill/restart·암호화 백업/복원 인수는 **53조건 통과**했다. 세 번째 worker를 head3 checkpoint로 시작하고, 첫 두 분석만 있는 유효한 head2 DB로 되돌렸다. 기존 체인 검증은 정상이어도 runtime guard는 과거 cursor와 readiness를 거부했다. checkpoint 파일 변조도 차단하고 정확한 기존 DB/파일 복원 후 조회가 회복되는 것을 TCP로 확인했다. 새 모델 호출·권한 발급은 없고 시험 소유 프로세스/unit/private 상태/임시 cursor key를 정리했다.

최종 관련 검증은 **Windows 256건 통과·3건 제외, Linux 257건 통과·2건 제외**다. Windows 제외는 POSIX 권한 계약 1건과 JSONL 전용 page 사례 2건, Linux 제외는 그 page 사례 2건이다. XML/소스 지문은 [기계 판독 결과](infrastructure-results/extra-runtime-audit-checkpoint-20261119.json), 실제 조건과 정리 상태는 [systemd 결과](infrastructure-results/extra-runtime-audit-checkpoint-20261119-systemd.json)에 기록한다. OS별 중복 사례를 합산하지 않는다.

```sh
python -m pytest tests/test_runtime_audit_checkpoint.py tests/test_audit_checkpoint_progression.py tests/test_audit_checkpoint.py tests/test_audit_transfer.py tests/test_sqlite_audit.py tests/test_audit_paging.py tests/test_audit_paging_http.py tests/test_audit_query_admission.py tests/test_http_worker_restart.py tests/test_native_analysis_http.py -q
python -m scripts.run_exec_history_controls --directory <새_시험_폴더> --worker-paging
```

## 남은 한계와 다음 작업

설정된 최소 기준보다 최신 상태 전체를 증명하지 않는다. 빈 head0 checkpoint는 모든 체인의 공통 prefix여서 비어 있지 않은 이력의 rollback 방지를 제공하지 않는다. DB와 checkpoint 파일/pin을 함께 제어하는 관리자의 공격, 독립 WORM 보관, 여러 호스트의 원자적 pin 배포는 미완료다. 매 경계의 파일 검사 직후에도 외부 변경이 가능하므로 파일과 SQLite 사이에 원자적 commit이 있다고 주장하지 않는다. 이미 성공한 이전 트랜잭션을 나중에 자동 삭제하지 않는다.

분석 중 근거/감사 상태 변화와 backup 게시 시점의 외부 기준 재확인은 [후속 검증](extra-analysis-audit-boundary-20261119.md)에 기록했다. 위53조건은 이 문서 작성 시점이며 최신 인수는 후속 문서를 본다. 실사용자 SSO·호스트 전체 수집·전원 단절·다중 호스트·연기한 8시간 시험은 별도 미완료다. 이번 시험은 인프라 무결성 시험이며 모델·판정·평가 원본/정답/예측·F1·오탐/미탐을 변경하거나 재평가하지 않았다.
