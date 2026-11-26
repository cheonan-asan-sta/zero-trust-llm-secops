# 전체 체인을 유지하는 감사 무결성 검사의 메모리 절감

2026-11-19 · extra · 무료 로컬 검증. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 변경

기존 SQLite 무결성 검사는 모든 분석의 최신 Pydantic 결과 객체를 보관했다. 신규 분석 전·readiness·DB 열기·백업/복원 head 확인 등 결과 객체 자체가 필요 없는 경로에서도 큰 payload가 메모리에 남았다.

이 경로는 이제 분석별 마지막 검증 행 번호만 보관한다. 모든 행의 순서·부모 digest·payload hash·모델 형식·원본 없는 검토 거부·최종 durable head는 그대로 검증한다. 검토를 만나면 같은 SQLite read transaction에서 해당 분석의 이전 검증 행을 다시 읽고 기존 모델 동등성·허용 상태 전이·엄격한 이후 시각을 검사한다. 내용 요약 hash나 캐시로 검증을 대체하지 않았다.

`get/recent/metrics`와 쓰기 CAS의 결과 materialization은 유지한다. DB schema·row/payload 상한·기존 마이그레이션/복원 활성화 규칙도 바꾸지 않았다. 따라서 단일 목록/통계 조회의 모든 메모리 비용까지 해결한 것은 아니다.

## 기능 회귀

신규10개 사례는 두 분석이 섞인 검토→완료→재개→완료 이력을 두 검증 경로에서 대조한다. 기존 Python 모델의 dict 순서/수치 동등성도 보존한다. 원본 없는 검토·불변 필드 변경·오래된 검토 시각·허용되지 않은 상태 반복·head/chain 변조·모델 위반·용량 초과를 모두 거부하며 원본 DB bytes는 변하지 않는다.

초기 Windows 확대 시험의1실패/131통과는 새 정상 fixture가 빠른 실행에서 분석/검토 시각을 같게 만든 문제였다. 저장소의 `review_updated_at > previous_time` 조건은 유지하고 fixture에 명시적인 순차 시각을 부여했다. 보정 후 **Windows132건·Linux211건 통과**. 최신 실제 systemd/ptrace·공유 참조·독립 HTTP worker 강제 종료/재기동·TCP HTTP·감사 백업/복원 **41조건**도 통과했다. source 권한/실행 이력·원래 감사 DB 불변과 시험 소유 process/unit/private 상태 정리를 확인했다. [검증 기록](infrastructure-results/extra-compact-audit-integrity-20261119.json), [실제 인수](infrastructure-results/extra-compact-audit-integrity-20261119-systemd.json)에 기록한다. OS별 중복 사례를 독립 시험 수로 합산하지 않는다.

## 로컬 Python 메모리 측정

`scripts/benchmark_audit_integrity.py`는 새 private 폴더에만 합성 SQLite 저장소를 만든다. 모든 payload는 모델 검증과 hash chain을 갖는다. 평가 로그/정답을 사용하거나 수정하지 않는다. 같은 고정 DB에서 기존처럼 결과를 보관하는 호환 경로와 compact 경로를 순서를 바꾸어 각각3회 측정했다. 표는 **tracemalloc의 Python 최대 할당량 중앙값**이며 전체 프로세스 RSS·HTTP 처리량·운영 SLA가 아니다.

각 fixture는1,024행·행별4,096바이트 padding이다. unique는1,024개 분석, review는342개 분석과682개 검토 이력이다.

| OS/fixture | 보관 경로 peak bytes → compact | 절감 | 검사 시간 중앙값(초), 보관 → compact |
|---|---:|---:|---:|
| Windows/unique | 9,190,182 → 174,826 | 98.10% | 0.1117 → 0.0898 |
| Linux/unique | 9,206,494 → 174,834 | 98.10% | 0.5036 → 0.4912 |
| Windows/review | 3,215,807 → 138,611 | 95.69% | 0.1505 → 0.1972 |
| Linux/review | 3,226,217 → 138,617 | 95.70% | 0.5630 → 0.6993 |

검토가 많으면 이전 행을 다시 파싱하는 비용으로 **이 fixture에서는 시간이 약24~31% 늘었다**. 메모리 절감을 무조건적인 속도 개선으로 표현하지 않는다. compact도 분석 ID별 위치를 보관하므로 상수 메모리는 아니며, 실제10만행·운영 동시 부하에서의 상한 측정은 미완료다. CPU/디스크/타 프로세스 부하와 tracemalloc 자체의 영향이 있으므로 다른 장비에 이 시간을 적용하지 않는다. Linux 측정은 이 PC의 WSL에서 Windows 마운트 경로를 사용했으며 OS 고유 성능 순위로 해석하지 않는다. 각 OS는 같은 생성 규칙의 별도 fixture를 사용했고, 두 모드끼리는 정확히 동일한 DB를 읽었다.

네 원본 측정 JSON과 소스/DB SHA는 [검증 기록](infrastructure-results/extra-compact-audit-integrity-20261119.json)에 연결한다. 두 모드의 검증 행 수·head가 같고 측정 전후 DB SHA도 같다.

```sh
python -m pytest tests/test_compact_audit_integrity.py tests/test_sqlite_audit.py tests/test_audit_transfer.py -q
python -m scripts.benchmark_audit_integrity --directory <새_폴더> --rows 1024 --padding-bytes 4096 --repetitions 3
python -m scripts.benchmark_audit_integrity --directory <다른_새_폴더> --rows 1024 --padding-bytes 4096 --repetitions 3 --reviews-per-analysis 2
```

기존 폴더/파일은 덮어쓰지 않는다. JSON 내 peak 절감률은 저장소 검증의 할당량이며 F1/오탐률 수치가 아니다. 이번 단계에서 분류·평가 원본·정답·예측은 바꾸지 않았다. 새 페이지 조회와 복원 checkpoint 보관, 다중 호스트·원격 WORM·전원 단절·연기한8시간 시험은 후속이다.
