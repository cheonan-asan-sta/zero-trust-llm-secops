# 분석의 감사 저장소 고정과 백업 게시 직전 재검증

2026-11-19 · extra · 무료 로컬 시험. 유료 API/AWS/push/CI/병합 없음.

## 확인한 문제와 변경

일반 분석 파이프라인은 처음 검사한 전역 감사 저장소와 저장 시점의 저장소가 다를 수 있었다. 분석 중 저장소를 교체하거나, 커밋 직후 checkpoint를 철회/DB를 기준 아래로 되돌려도 성공 응답이 나가는 사례를 재현했다. 백업은 복사본 최초 검증 이후 암호화 중 checkpoint가 철회돼도 게시되는 사례가 있었다. 수정 전 비교는 **7실패·3통과**이며 [원래 비교 XML 지문](infrastructure-results/extra-analysis-audit-boundary-20261119.json)을 보존했다.

분석 시작 시 선택한 감사 저장소 객체를 고정한다. preflight scan 전후·저장 전·최종 전달 전에 현재 serving 객체가 같은지 확인하며 다른 저장소로 쓰기를 전환하지 않는다. 저장 후에는 선택한 로컬 저장소의 무결성/최소 checkpoint를 다시 확인한다. 이미 성공한 커밋은 이후 철회/취소 때문에 지우지 않고, 성공 응답 전달을 거부한다. 기존 `/analysis`의 실패 계약은 502로 유지한다.

추가 전체 scan도 `settled_io`로 실행해 event loop를 막지 않고, 취소되더라도 진행 중 디스크 I/O가 끝날 때까지 원래 분석 슬롯을 유지한다. 이 scan이 느릴 수 있으므로 **기존 실행 근거 source 재검증을 그 뒤에 유지**해 scan 중의 source 철회/만료 확인 순서가 밀리지 않도록 했다. 최종 source 재검증 후 저장소 객체 동일성도 다시 확인한다.

백업은 암호화/파일 hash 계산 후, 게시 전에 **그 복사본**을 선택한 store로 다시 검증한다. runtime guard가 설정됐다면 파일 철회·pin 변조도 다시 확인한다. 복사 후 원본 DB의 정상 append는 snapshot 의미를 바꾸지 않는다. 재검증 실패 시 새 백업을 게시하지 않고 임시 디렉터리를 제거하며 원본을 보존한다.

## 검증

신규13개 사례: preflight/model/commit 후 저장소 교체 3건, model/commit 후 checkpoint 철회/정상 구 DB rollback 4건, 정상 결과 1건, commit 후 scan 취소/슬롯·이력 유지 1건, 추가 scan 뒤 source 재검증 순서 1건, 암호화 중 checkpoint 철회/변조 2건, 암호화 중 원본 정상 append와 고정 복사본 복원 1건이다. source 순서 사례는 제어한 내부 callback의 회귀 시험이며 실사용자 SSO 증명은 아니다.

관련 **Windows223건 통과·POSIX 권한1건 제외, Linux224건 통과**. SDK 로컬 transport·근거 callback·native HTTP·실제 worker 재기동·기존 backup/restore/checkpoint/CAS를 묶었다. 이전 문서의 더 넓거나 다른 파일 묶음과 시험 수를 전체 누적/감소로 비교하지 않는다. OS 중복도 합산하지 않는다.

실제 systemd/ptrace→공유 실행 참조→HTTP worker3개 kill/restart→SQLite 감사→암호화 백업/복원 **54조건 통과**. checkpoint 변조 때 실제 TCP `/analysis`는 502, provider stub 호출은0임을 새로 확인했다. process/unit/private 상태와 임시 cursor key 정리, 원래 권한/실행 이력 보존도 확인했다. [기계 판독 결과](infrastructure-results/extra-analysis-audit-boundary-20261119.json), [실제 인수](infrastructure-results/extra-analysis-audit-boundary-20261119-systemd.json).

```sh
python -m pytest tests/test_analysis_audit_binding.py tests/test_guarded_backup_publication.py tests/test_async_audit_io.py tests/test_audit_preflight.py tests/test_runtime_audit_checkpoint.py tests/test_async_evidence_io.py tests/test_verified_sdk_retry_boundary.py tests/test_analysis_source_admission.py tests/test_native_analysis_http.py tests/test_http_worker_restart.py tests/test_audit_checkpoint.py tests/test_audit_checkpoint_progression.py tests/test_audit_transfer.py tests/test_sqlite_audit.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 비용과 한계

분석 성공 경로와 백업 게시 경로에 각각 전체 검증 scan이 추가된다. SQLite는 bounded compact scan을 유지하지만 시간은 행 수에 비례해 증가한다. 이번 시험을 처리량/지연 SLA 측정으로 해석하지 않는다.

최소 checkpoint는 고정된 과거 기준이다. 기준 이후의 새 결과만 제거하고도 기준을 만족하는 DB를 만들 수 있다. **응답할 analysis 자체의 SQLite 보존 확인은 [후속 구현](extra-analysis-row-preservation-20261119.md)**에서 연결했다. 위54조건은 이 문서 시점의 기록이며 후속 재검증과 구분한다. 일반 JSONL `integrity()`는 기존 메모리 상태 의미를 유지하며 이를 디스크 전체 재검증으로 과장하지 않는다. 파일·DB·근거 source 사이의 원자적 공동 snapshot이나 최종 검사 이후 모든 외부 변경의 차단을 주장하지 않는다. 독립 원격 witness/WORM·최신 기준 자동 선택·실사용자 SSO/호스트 전체 수집·다중 호스트·전원 단절·8시간 soak는 미완료다.

모델/판정·평가 원본/정답/예측은 변경하지 않았다. 새 F1·오탐/미탐 평가가 아니며 독립 목표95% 달성 증거도 아니다.
