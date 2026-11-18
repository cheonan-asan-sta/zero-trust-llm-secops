# JSONL 모델 호출 전·append 직전의 writer prefix 검증

2026-11-19 · extra · 유료 API/AWS/push/CI/병합 없이 로컬 구현·시험.

## 문제와 변경된 순서

기존 JSONL 캐시가 head2를 기억한 채 디스크가 정상 head1로 되돌아가거나 다른 writer가 유효한 행을 추가해도, 캐시 head로 새 행을 덧붙일 수 있었다. 성공 응답 후 확인만으로는 불필요한 모델 호출과 잘못된 parent의 append를 예방하지 못했다. 수정 전8개 비교에서 **7실패·1통과**를 기록했다. 기존 federation은 등록 파일 누락을 이미 모델 전에 거부했다.

이제 process가 로드한 전체 파일 bytes의 SHA-256 상태를 보존하고, 자기 append 성공 때만 갱신한다. byte 지문·head digest·hashed/legacy 행 수가 현재 디스크와 모두 일치해야 한다. 같은 행 수의 legacy prefix 변경이나 다른 writer의 정상 append도 자동으로 받아들이지 않는다. 명시적으로 새 reader를 열거나 검증된 복구 절차를 택해야 한다.

1. 모델 호출 전: `writer_integrity()`가 bounded disk scan과 캐시 prefix 일치를 확인한다. 실패 시 기존 `/analysis`의502, provider0회다. 이 읽기만으로 파일을 만들거나 고치지 않는다.
2. 실제 append 직전: 같은 process의 disk `RLock` 안에서 다시 검증한다. 모델 수행 도중 파일이 바뀌었으면 새 행을 쓰지 않는다. 실패한 append 경로는 기존 fail-closed 규칙에 따라 writer를 중단하며 부분/불확실 bytes를 삭제하지 않는다.
3. 열린 대상 확인: 검증 때의 descriptor/path signature와 실제 append FD의 device/inode/size/mtime을 대조한다. 없는 새 파일은 exclusive create, 기존 파일은 create 없이 열고 regular file·path 동일성을 확인한다. 가능한 OS에서는 `O_NOFOLLOW`/`O_NONBLOCK`을 사용한다.
4. 쓰기와 전달: UTF-8/LF binary append를 짧은 OS write가 모두 끝날 때까지 수행하고 file `fsync`한다. 최종 크기/경로가 일치할 때만 캐시 head·byte 지문·행 수를 갱신한다. 이후 기존의 응답 행 보존 확인과 근거 재검증을 유지한다.

readiness도 live writer 검증을 사용해 `writer_head_verified=false`와 audit failure를 표시한다. liveness는 유지한다. 과거 호환 API인 plain `integrity()`의 캐시 의미 자체를 바꾼 것은 아니다.

## 시작 시 읽기와 상한

bootstrap은 regular file·symlink 거부·descriptor/path 안정성을 확인하고 최대128MiB+1까지만 읽는다. 10만 행/행2MiB 상한을 모델 파싱 전에 적용한다. append도 row/file/행 수 상한을 **출력 파일 생성·확장 전** 확인한다. 기존 CRLF prefix는 읽은 bytes 그대로 지문을 보존하며 새 행은 LF로 덧붙인다. source를 재포맷하지 않는다.

POSIX FIFO는 bootstrap과 live reader에서 regular-file 검사 및 nonblocking open으로 거부한다. 이 검증을 모든 저장장치·네트워크 파일시스템의 I/O에 강제 종료 deadline이 생겼다고 설명하지 않는다. `settled_io`는 시작한 I/O가 완료/실패할 때까지 슬롯을 유지한다.

## federation의 검토 의미

federation의 원본과 검토는 다른 writer 파일에 있을 수 있다. head 소유권 검사는 전체 byte/prefix·모델·chain을 확인하고, 응답 행 proof는 기존 전역 snapshot의 identity/revision 병합 확인 뒤 자기 파일의 행을 확인한다. 자기 파일에 원본이 없는 정상 cross-file 검토 때문에 이후 분석 writer를 막지 않도록 했다.

이것은 SQLite의 동일 트랜잭션 내 review transition/CAS와 같지 않다. federation은 기존 cross-file 병합 규칙을 유지하며 global review lifecycle이나 원자적 다중 writer transaction을 새로 증명하지 않는다. standalone JSONL과 기존 strict paging의 local review 검사는 유지한다.

## 검증 근거

신규27건: 변경 전 비교8건, 같은 행 수 legacy 변경2건, 명시적 새 reader 재개1건, 모델 중 rollback2건, 검증 뒤 동일 bytes 파일 교체2건, short write1건, fsync 실패/이력 보존·후속 쓰기 차단1건, append capacity3건, bootstrap byte cap2건, bootstrap row/행 수 cap2건, POSIX FIFO1건, cross-file 정상 검토1건, standalone orphan 검토 거부1건이다.

최종 관련 **Windows414건 통과·4건 제외, Linux416건 통과·2건 제외**다. 제외는 POSIX FIFO/키 권한의 Windows2건과 기존 JSONL 전용 page2건이며 OS 중복을 합산하지 않는다.

기존 실제 HTTP process2건도 강화했다. JSONL/federated 각각 정상 분석을 디스크에서 확인한 뒤 파일을 비우고 재요청하면502·추가 provider0회·readiness503·liveness200·파일 보존을 확인한다. 이2건은 기존 사례의 확장이므로 신규27건에 중복 합산하지 않는다. [묶음 결과·수정 전 XML·소스 지문](infrastructure-results/extra-jsonl-writer-boundary-20261119.json), [최신 systemd54조건 회귀](infrastructure-results/extra-jsonl-writer-boundary-20261119-systemd.json).

```sh
python -m pytest tests/test_jsonl_writer_boundary.py tests/test_jsonl_row_preservation.py tests/test_http_worker_restart.py tests/test_audit_cancellation.py tests/test_federated_audit.py tests/test_api.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 한계와 다음 작업

지문은 이 process가 로드한 파일을 기준으로 한 실행 중 일치 확인이다. 파일과 process 전체를 함께 되돌리거나 재시작 때 이미 손상/재작성된 유효 체인을 제공하는 특권 공격자의 독립 최신성 증명은 아니다. 같은 process의 자기 writer만 잠그며 여러 process가 같은 plain JSONL을 동시에 쓰도록 지원하지 않는다. 최종 검사 직후 외부 변경 가능성도 남는다. 공유 트랜잭션·외부 checkpoint가 필요한 SQLite 경로와 구분해야 한다.

file fsync 성공은 host 전원 단절·디렉터리/스토리지 전체 내구성 시험을 대신하지 않는다. flush 실패 bytes는 보존하고 자동 재시도·자동 head 승격·자동 활성화를 하지 않는다. 전체 scan 추가로 행 수에 비례한 I/O가 늘며 SLA/RSS/처리량은 이번 시험의 지표가 아니다.

다음은 일반 분석의 호출 계정 철회/만료 경계를 검토한다. 원격 witness/WORM·실사용자 SSO·다중 호스트·전원 단절·연기한8시간 soak는 미완료다. 모델 판정·평가 원본/정답·F1·오탐/미탐 수치를 변경하거나 재측정하지 않았다.
