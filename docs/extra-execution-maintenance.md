# 실행 mTLS 보관 작업의 안전한 단계별 진단 — v78

2026-11-15 · 기준 aitest `c976de7d4300fe86277bb34a3782bd19eaed2483` · [v77 선택 진단](extra-selection-diagnostics.md) 후속 인프라 작업.

## 이전 실패와 이번 범위

PR72 병합 후 첫 CI에서 trusted_signal_enforcement_timing 뒤 보관 검증 구간이 runtime_command_failed_2로 실패했다.
실패 로그 SHA256은 `242129017c29b679496d502943b6ce2ac194fd581df2d689860ea0882f56a9f6`다. 실패 작업을 동일 커밋에서 한 번 재실행한 뒤 최종16개 성공을 확인했다.
14개 성공 실행 보존과 실행 mTLS/최종 집계2개 재실행을 시작·완료 시각으로 구분했다. job ID만으로 재실행 수를 판단하지 않았다.
과거 실패의 정확한 child/원인은 **미확인**이다. 비차단 collector 잠금 경합은 가능한 설명이며 소급 확정하지 않는다.

이번에는 인수 도구의 보관 호출만 보강했다. 탐지·LLM·라벨·PDP/PEP, 수집기의 잠금/보관 구현과 권한·mTLS 기준은 변경하지 않았다.
성능 개선이나 경합 문제 해결로 계산하지 않는다. 진짜 경합이 나오면 여전히 인수 실패로 남는다.

## 구현 명세와 선정 이유

- 고정 child [execution_maintenance_probe](../scripts/execution_maintenance_probe.py)가 기존 observer 압축→원본 이동과 서버 보관→상태 조회를 호출한다. 경로/서비스/모듈은 호출자가 바꿀 수 없다.
- observer_init/observer_compact/observer_retire 및 server_init/server_compact/server_status를 구분한다. 초기화의 실제 spool 잠금 실패도 별도로 남긴다.
- collector_busy·sqlite_busy·sqlite·io·invalid_state·registry/context_unavailable·timeout·internal 등 고정 분류를 사용한다. 예외 메시지/클래스명·경로·원문 stdout/stderr·헤더/본문·키/토큰은 직렬화하지 않는다.
- SQLite busy는 고정 에러 코드로만 분류한다. 문자열에 busy가 들어 있다고 추정하지 않는다. 세부 원문이 필요한 원인은 별도의 비밀 보호 조사가 필요하다.
- 부모는 기존 소유 프로젝트/서비스 검사를 거쳐 고정 docker exec를 한 번 호출한다. 작업 전 operation을 저장하고, 종료 코드와 엄격히 검증한 영수증을 정리 전에 저장한다.
- 기존 Pydantic StrictModel/중복 키·비유한 수 거부 decoder를 재사용한다. 실제 boolean, operation/단계 결속, 수 범위와 완료 일관성·추가 필드 거부를 검사한다. 성공 JSON이어도 비정상 종료는 실패다.
- 압축 뒤 원본 이동이 실패하면 이미 확인한 compacted 수만 보존한다. 실패한 단계를0건 성공으로 바꾸지 않는다. 정상 기준인 compacted/retired≥5·서버 archived>0은 그대로다.
- 로컬/test 환경과 기존 DB·심볼릭 링크 거부를 유지한다. 새로운 자격·권한·원격 API·우회 경로를 만들지 않았다. 자동 재시도나 잠금 대기·timeout 확대도 추가하지 않았다.

동적 오류 텍스트를 공개하는 방식보다 고정 typed receipt를 선택한 이유는 키·관측 본문 유출 없이 동시성/스토리지 문제를 분리하기 위해서다.
입력1KiB, 게시 허용 영수증32KiB, 기존 명령30초를 유지한다. stdout은 비공개 RAM에서 포착하므로 전체 출력에 대한 OS 메모리 하드 한도는 아니다.
Docker CLI timeout도 원격 exec 취소 보장이 아니다. 실패 후에는 소유 시험 자원을 정리한다.

## 실제 검증 결과와 근거

| 범위 | 결과 |
|---|---|
| 집중 시험 | 90통과·0실패/skip, 전체 시험의 부분집합 |
| 전체 로컬 pytest | 5,528통과·0skip, Ruff+RUF100 통과 |
| 실제 Linux 잠금 fixture | 실제 생성자/압축 flock 경합을 각각 분류, 근거 파일·상태 불변, 잠금 해제 뒤 압축·이동 성공 |
| 실제 Docker mTLS 인수 | 25조건 통과, observer/server 보관 영수증2건 정상, 기존 권한/차단/복원 기준 유지 |
| 실제 보관 수 | observer 압축9건·입력 이동10개, 서버 보관30건 |
| 기존 판정 비교 | 1,681,815건 결정 SHA 동일, 새 FP0·기존 TP 손실0·정답 재열람0 |
| 비용·정리 | AWS·유료 API0, 소유 시험 자원 purge·단위 컨테이너 정리 |

로컬 source_commit은 기준 커밋이며 source_dirty=true인 개발 트리다. 파일/아카이브 SHA로 고정하고 같은 소스를 원본 Dockerfile 이미지에 넣어 시험했다.
단위 Docker는 network none·비root·read-only·cap drop을 유지했다. 실제 mTLS 시험의 공개 의존성 빌드/이미지 확인과 내부 통신 네트워크를 구분한다.
fixture 잠금 경합과 과거 자연 CI 실패는 서로 다른 근거다. 이번 실행을 과거 원인의 재현/해결로 표시하지 않는다.

```text
python -m pytest tests/test_execution_maintenance_probe.py tests/test_execution_diagnostics.py tests/test_execution_retention.py tests/test_behavior_execution_collector.py -q
python -m scripts.test_execution_mtls_runtime --directory runtime/c02/새-실행-인수
```

집중 시험은 비밀 문자열·잘못된 타입/추가 필드·중복 JSON/초과 보고서·비정상 종료/timeout·부분 완료·실제 Linux 잠금·원본 보존과 잠금 해제 복구를 검증한다.
[공개 결과·소스/판정 지문](infrastructure-results/extra-execution-maintenance-v78-20261115.json)에 실제 실행과 개발 판정 비교를 함께 남긴다.

## 남은 범위

과거 PR71 선택 실패와 PR72 실행 보관 실패의 원인은 여전히 미확인이다. 향후 자연 실패에서는 이번 단계·고정 분류·부분 수를 근거로 조사한다.
실제 systemd 작업자 CPU/메모리 재측정·한도 집행,8~12시간 장기 시험, 운영 SLO/RTO/RPO와 운영 키/외부 pin·백업 일정/경보·원격 보관·최종 인수는 남아 있다.
공유 감사 F1 0%·FP24/FN6, 웹 감사70.77%·FP37/FN1, 인증95.08%·FP0/FN3는 그대로다. 새 독립 성능 평가나 목표 달성으로 계산하지 않는다.
채희주 요청에 따른 Codex 보조 구현·실행이며 팀원 독립 검토나 운영 승인으로 기록하지 않는다.
