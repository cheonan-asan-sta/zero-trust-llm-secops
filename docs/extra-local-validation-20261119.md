# extra 로컬 통합 검증과 인수 기록

2026-11-19 오전. 구현 기준은 `3165fc1f483fc90e45543da2bc8456dc002230cf`다. 이후 변경은 테스트 기대값·신규 통합 시험·문서이며 `app/` 구현은 동일하다. 무료 로컬 Python·WSL·loopback HTTP·systemd만 사용했다. push·CI·병합·AWS·유료 API와 미뤄둔 실제 8시간 soak는 실행하지 않았다.

## 결과를 읽는 방법

| 실행 | 결과 | 해석 |
|---|---|---|
| Linux 전체, 고정된 3165fc1 소스 | 8,411 통과 / 2 실패 / 4 제외, 약 15분 | 원본 실패를 그대로 보존했다. 전체 재실행을 모두 통과했다고 표현하지 않는다. |
| Windows 관련 확대 | 870 통과 / 2 실패 / 34 제외 | 같은 두 테스트 기대값 문제. Windows 전체 저장소 통과의 근거가 아니다. |
| 기대값 수정 후 Linux 관련 재검증 | 53 통과 | 전체 실행의 실패 노드 두 건이 포함되어 통과했는지 이름으로 대조했다. 신규 실제 TCP 시험도 포함한다. |
| 기대값 수정 후 Windows 관련 재검증 | 75 통과 / 1 제외 | POSIX worker fixture는 명시적으로 제외. JSONL source 관련 사례를 포함한다. |
| 실제 systemd·ptrace·HTTP worker 복구 인수 | 54조건 통과 | provider는 stub. 소유 unit·private state·HTTP worker 정리 확인. 모델 정확도 시험과 합산하지 않는다. |

[기계 판독 결과·실패 노드·원본 XML 경로와 SHA-256·소스 지문](infrastructure-results/extra-local-validation-20261119.json), [실제 systemd 원본 결과](infrastructure-results/extra-local-validation-20261119-systemd.json).

원본 XML도 저장소에 포함했다: [Linux 전체](infrastructure-results/extra-final-full-native-linux-20261119.xml), [Windows 확대](infrastructure-results/jsonl-query-source-windows-20261119.xml), [수정 후 Linux](infrastructure-results/http-review-contract-linux-final-20261119.xml), [수정 후 Windows](infrastructure-results/jsonl-read-contract-windows-final-20261119.xml). 실패 XML을 성공 XML로 덮어쓰지 않았다.

전체 실행의 실패는 `test_failures_return_no_success_and_release_capacity[corrupt]`와 `[write_error]`였다. 기존 테스트는 손상되거나 쓰기 결과가 불확실한 JSONL에서 `recent()`가 빈 목록을 반환하길 기대했다. 새 계약은 **감사 기록을 확인할 수 없으면 조회 불가 예외**를 반환한다. 실패 응답·모델 호출 횟수·용량 반환·원본 보호 검증은 유지하면서 이 두 기대값을 수정했다. 운영 로직을 되돌리거나 보안 검증을 완화하지 않았다. 수정 후 전체를 새로 재실행하지 않았으며 관련 재검증 결과를 별도 보존한다.

Linux 전체의 제외 4건 중 2건은 SQLite 별도 사례로 대체된 JSONL prefix 매개변수이고, 2건은 patched Linux 이미지 내부에서만 실행하는 runtime/pip 검사다. 이번 host 회귀가 새 Docker 이미지 검증을 완료했다는 뜻은 아니다.

이전에 실행한 Windows 전체는 POSIX 파일 권한·flock·signal·peer credential 등의 플랫폼 차이와 당시 fixture 문제로 실패했다. 최신 Linux 전체와 Windows 관련 재검증은 그 기록을 삭제하거나 Windows 전체 성공으로 대체하지 않는다. 초기 WSL 임시 경로 설정 실패와 중단된 mounted 경로 실행도 성공 수치에 넣지 않았다.

## 추가한 실제 HTTP 시험

[`test_http_review_preconditions.py`](../tests/test_http_review_preconditions.py)는 실제 loopback 서버에 동일 ETag로 16개 검토 요청을 동시에 보낸다. 정확히 하나만 성공하고 적어도 하나는 stale 버전으로 412를 반환해야 한다. 나머지는 412 또는 용량 제한 503만 허용한다. 클라이언트가 주장한 reviewer 대신 인증된 주체를 기록하고 감사 head는 한 번만 증가해야 한다.

소유 worker를 강제 종료한 뒤 같은 SQLite로 새 worker를 띄운다. 이전 성공 ETag가 복구되고, 오래된 화면의 ETag는 412로 거부되며 새 ETag 검토는 성공하는지 확인한다. 검토를 분석 건수에 중복 계산하지 않는지, 잘못된 API key는 401인지도 확인한다. 소유 worker는 종료·wait한다. 실제 kernel 실행이나 기업 SSO를 이 새 시험에서 검증한 것은 아니다.

## 구현 상태와 한계

감사 공동 쓰기·이관/암호화 백업/복원·checkpoint·실행 참조·현재 caller 검증·조회/분석 자원 제한에 더해, HTTP 조건부 검토와 실제 JSONL 디스크 검증을 연결했다. [현재 구현과 남은 목록](extra-development-status-20261119.md)을 시작점으로 읽으면 된다.

다음 우선순위는 자체 대시보드가 검토 ETag/If-Match와 새 감사 페이지 API를 사용하도록 연결하는 것이다. `AUDIT_REVIEW_REQUIRE_IF_MATCH`는 기본 false이며 모든 client가 전환하기 전에 무조건 켜지 않는다. 조건부 검토는 SQLite가 지원하고 JSONL/federated가 묵시적으로 무시하지 않는다.

외부 기업 SSO/MFA·online revocation, 관리자와 독립된 최신성 witness/WORM, 다중 호스트·실제 전원 단절·실제 8시간 soak는 남아 있다. JSONL 전체 검증은 I/O 비용이 있어 대규모 조회 성능 개선으로 보고하지 않는다.

## 탐지 성능은 기존 수치 유지

기존 실제 API **합성 개발 360건**은 TP 163·FP 6·FN 17·TN 174, 정밀도 **96.45%**, 재현율 **90.56%**, F1 **93.41%**, 오탐률 **3.33%**다. [기존 평가 보고서](llm-operation-evidence-20261117.md). 이번 작업은 모델·prompt·판정·평가 원본/정답/예측을 변경하거나 모델 성능을 다시 측정하지 않았다. 독립 운영 평가에서 95% 목표를 달성한 상태로 표현하지 않는다.

## 재현

키 환경변수를 해제하고 `AWS_EC2_METADATA_DISABLED=true`, `AUDIT_BACKEND=jsonl`로 실행한다. WSL에서는 소스와 임시 디렉터리를 지속되는 Linux home 아래에 두고 `--basetemp` 부모를 먼저 생성한다.

```sh
python -m pytest -q --tb=short --junitxml=full.xml
python -m pytest tests/test_native_analysis_http.py tests/test_http_review_preconditions.py -q --junitxml=review-recheck.xml
python -m pytest tests/test_native_analysis_http.py tests/test_jsonl_query_source.py tests/test_http_review_preconditions.py -q --junitxml=query-review-recheck.xml
```

첫 명령은 전체 재현용이며 관련 재검증이 새 전체 통과를 대신한다는 뜻이 아니다. POSIX 전용 fixture와 OS별 제외를 구분해서 보고한다.

## 임시 자원 정리

시험 프로세스가 종료된 것을 확인하고, 이번 실행이 소유한 Linux home 아래 두 `--basetemp`의 `tmp` 디렉터리만 제거했다. 약720MiB의 합성 fixture이며 원본 XML·소스·평가 원본/정답/보고서는 보존했다. 실제 systemd unit/private state도 해당 runner가 정리했다. Docker 자원을 새로 만들지 않았고 다른 프로젝트 자원이나 공유 venv는 삭제하지 않았다. WSL 파일 삭제가 Windows 가상디스크를 즉시 축소했다는 뜻은 아니며 별도 compact는 실행하지 않았다.
