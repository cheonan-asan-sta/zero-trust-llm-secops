# 감사 checkpoint 파일 보관과 복원 최소 head 연결

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 구현

기존 backup/restore의 `--minimum-seq/--minimum-head`를 사람이 복사하는 것 외에, 검증한 감사 head를 별도 private JSON 파일로 내보내고 **운영자가 기록한 외부 SHA-256 pin**으로 읽는 경로를 추가했다. timestamp나 backup 안의 head를 최신 신뢰 기준으로 자동 채택하지 않는다.

`checkpoint`는 기존 SQLite를 read-only로 열어 schema·전체 chain·모델·검토 이력·durable head를 검증한다. 파일에는 schema, timezone-aware 수집 시각, source 경로 locator의 hash, seq/digest만 넣는다. 사건 payload·사용자·키·원본 경로를 담지 않는다. 수집 시각은 설명용이며 최신성을 인증하지 않는다.

새 파일만 private stage와 exclusive link/fsync로 게시한다. 원본 DB나 기존 checkpoint를 덮어쓰거나 없는 DB를 초기화/복구하지 않는다. 읽기는16KiB 상한·regular file·link 제한·전후 fd/path stat·외부 pin·엄격한 JSON/schema/head 검증을 거친다. POSIX에서는 소유자와 private mode도 확인한다. Windows ACL 검증을 입증한 것은 아니다.

## 사용 순서

```sh
python -m scripts.audit_storage checkpoint --database <기존_DB> --destination <새_checkpoint.json>
```

반환된 `checkpoint_sha256`를 신뢰하는 별도 기록으로 보관한다. checkpoint 파일과 그 옆의 임의 hash 파일을 함께 신뢰하는 것만으로 독립 보관이 증명되지는 않는다.

```sh
python -m scripts.audit_storage backup --database <기존_DB> --destination <새_암호화백업> --key-file <private32바이트백업키> --key-sha256 <키pin> --checkpoint <checkpoint.json> --checkpoint-sha256 <운영자_기록pin>
python -m scripts.audit_storage restore --package <암호화백업> --destination <새_후보_DB> --backup-sha256 <별도_백업pin> --key-file <private32바이트백업키> --key-sha256 <키pin> --checkpoint <checkpoint.json> --checkpoint-sha256 <운영자_기록pin>
```

file와 pin은 모두 필요하다. 수동 minimum head와 checkpoint 파일을 동시에 지정하면 모호한 기준을 선택하지 않고 exit2로 거부한다. 잘못된 checkpoint/pin은 private backup key를 읽기 전에 거부한다. 무결성/복원 실패는 exit1이며 후보를 게시하지 않는다. 기존 scan/migrate·수동 minimum head 방식은 유지한다.

## 보장 범위

복원은 선택한 minimum seq 이상이어야 하고 그 위치의 digest도 일치해야 한다. 따라서 더 오래된 **정상 인증 백업**과 같은 seq의 다른 정상 체인도 거부한다. 새 후보 파일만 생성하며 `automatic_activation_allowed=false`다. runtime 설정·원본 DB·접근 grant를 변경하지 않는다.

반환되는 `freshness_check`는 minimum 검증 여부·기준 출처·비어 있지 않은 history 존재·checkpoint pin을 기록한다. `independent_storage_verified=false`, `latest_live_state_verified=false`를 명시한다. 프로그램은 운영자가 **최신** checkpoint를 선택했는지, 외부 pin이 별도 신뢰 저장소에 있는지를 자동 증명하지 않는다.

운영자가 과거 checkpoint를 명시적으로 선택하면 그 과거 minimum까지만 확인한 역사적 후보 복원이 가능하다. 이것을 현재 live 상태 검증으로 표시하지 않는다. seq0은 모든 체인의 빈 prefix이므로 고유 history 기준이 없으며 `checkpoint_has_history=false`다. 운영 복원에서 최신 trusted checkpoint/pin 보관이 필요한 이유다.

## 검증

신규32개 사례는 readonly/private export·원본/기존 출력 보존·missing/foreign/corrupt source 무수정·변조/잘못된 schema/중복 JSON/범위/링크/권한·잘못된 외부 pin의 key 접근 전 거부를 확인한다. CLI로 오래된 정상 백업 거부와 최신 후보 복원을 수행하고, 과거/빈 checkpoint를 과장하지 않는 결과도 확인했다. 독립 writer가 추가하는 동안 capture된 head가 일관된 prefix인지 검증했다.

**Windows 관련141건 통과·1건 제외, Linux 확대225건 통과·2건 제외**. Windows 제외는 POSIX mode 계약, Linux 제외2건은 기존 SQLite에 적용하지 않는 JSONL page 사례다. OS별 공통 사례를 합산하지 않는다.

실제 systemd/ptrace·공유 참조·HTTP worker 재기동·감사 백업/복원에 새2조건을 더한 **49조건 통과**. 복원 후보의 HTTP 검토 후 head를 readonly checkpoint로 내보내고 외부 pin의 변조 거부를 확인한 뒤, 그 head로 기존 오래된 백업 거부를 수행했다. 이는 후보 검토 head를 보관한 시험이며 live 전체 시스템의 최신 상태 입증이 아니다. 시험 process/unit/private 상태·임시 의존성은 정리됐고 원래 앱 권한·실행 evidence·원래 감사 DB도 보존됐다.

[기계 판독 결과·XML/소스 지문](infrastructure-results/extra-audit-checkpoint-20261119.json), [실제 systemd run](infrastructure-results/extra-audit-checkpoint-20261119-systemd.json).

```sh
python -m pytest tests/test_audit_checkpoint.py tests/test_audit_transfer.py tests/test_sqlite_audit.py tests/test_native_analysis_http.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

다음은 checkpoint 갱신 시 이전 trusted prefix와의 단조 증가 확인과 운영 상태 비교다. 원격 WORM·독립 보관·전원 단절/다중 호스트·자동 활성화·연기한8시간 시험은 완료로 처리하지 않는다. 모델/프롬프트·탐지·평가 원본·정답·예측·F1·오탐/미탐은 바꾸지 않았다.
