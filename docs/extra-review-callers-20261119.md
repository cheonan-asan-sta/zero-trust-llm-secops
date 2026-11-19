# 기존 검토 호출 경로 이관과 필수 정책 적용 준비

2026-11-19 · `extra` 로컬 개발. 실제 운영 설정, 외부 배포, GitHub 업로드·CI·병합은 변경하지 않았다.

## 변경 내용

남아 있던 `audit_recovery_controls.py`와 `http_worker_controls.py`의 검토 요청을 `scripts/local_review_intent.py`로 연결했다. 이 어댑터는 별도 검증 규칙을 복제하지 않고 기존 `AuditReviewClient.prepare/review`를 재사용한다. 인증 신원 조회 → 결과 상세 조회 → 인증 신원 재조회로 스냅샷을 만들고, 시험이 예상한 결과와 일치할 때만 검토한다. 제출 직전 신원을 다시 확인하고 관측한 `If-Match`와 `X-Review-Identity`를 전송한다. 응답의 분석 본문·검토 내용·작성자·ETag·신원도 기존 클라이언트가 검사한다.

자동 재조회 후 덮어쓰기, 실패한 PATCH의 재시도, 헤더 생략으로의 우회는 없다. 자격 증명은 전달된 로컬 transport의 메모리에서만 사용한다. 로컬 어댑터의 `testserver` 허용은 ASGI 시험 전용이며 외부 주소 연결 기능이 아니다. 일반 HTTPS/mTLS 운영 CLI는 기존 구현을 그대로 사용한다.

재시작 시험은 같은 event를 두 번 분석한다. 초기 이관 시험에서 첫 번째 결과와 두 번째 현재 결과가 다르다는 이유로 새 어댑터가 검토를 거부했다. 두 번째 분석의 실제 응답을 검토 기준으로 명시해 해결했다. 임의의 최신 GET으로 기준을 자동 교체하지 않는다. 복원 시험의 신규 fixture에는 명시적인 합성 실행 문맥과 별도 analysis/event ID를 사용했다. 기존 결과의 분석 내용을 같은 ID로 수정하는 쓰기는 기존 SQLite 보호가 거부하며 이 보호는 유지했다.

## 저장소 내 경로와 배포 준비

| 경로 | 현재 상태 |
|---|---|
| 자체 대시보드 `dashboard-operations.js` | 기존 관측 버전·서버 신원 연결 유지 |
| 워크벤치 `app.js` | 기존 관측 버전·서버 신원 연결 유지 |
| `scripts/audit_review_client.py` | snapshot v2·실제 HTTPS/mTLS 지원 유지 |
| 로컬 복원 검토 harness | 공통 클라이언트 재사용으로 이관. 필수 정책 켠 ASGI·실제 SQLite 복원 검증 |
| 로컬 재시작/페이지 harness | 공통 클라이언트 재사용으로 이관. 시험 소유 worker 1·2에 필수 정책 적용 |
| 서버 동작·호환·거절 시험의 직접 PATCH | 의도적인 raw 요청을 유지. 제품 호출자 이관 대상으로 오인하지 않음 |
| 실제 조직의 외부 스크립트·이전 배포본 | 목록·배포 여부를 저장소만으로 확인할 수 없음. 실환경 인수 미완료 |

`owned_worker(..., review_policy="caller_bound")`는 격리된 시험 프로세스에 두 필수 설정을 켠다. `optional` 기본값과 과거 control 파일 호환은 유지한다. 잘못된 정책과 SQLite 이외의 강제 정책 조합은 기동 전에 거부한다. 실제 `.env.local`이나 서버 설정을 바꾸는 기능은 아니다.

운영 전에는 외부 writer 목록과 버전 확인 → SQLite·인증·두 필수 설정으로 격리 검증 → 모든 worker의 동일 설정 배포 → 누락428·신원403·stale412 경보 확인이 필요하다. 선택 정책 worker가 남아 있으면 서비스 전체 강제를 주장할 수 없다. 배포 순서와 상태 코드 상세는 [필수 검토 정책 문서](extra-server-review-policy-20261119.md)를 따른다. 실제 조직의 정책 전환 완료로 표시하지 않는다.

## 무료 로컬 검증

최종 실행 원본과 소스 지문은 [manifest](infrastructure-results/extra-review-callers-20261119.json)에 기록한다. Windows에서는 POSIX 전용 실제 worker 두 사례가 제외되며 Linux에서 확인한다. 별도 OS에서 같은 사례를 반복한 횟수를 독립 사례 수로 합산하지 않는다.

최종 결과는 Windows11통과·2제외, Linux21통과·제외0이다. Ruff와 `git diff --check`도 통과했다. 초기 불일치 및 fixture 실패 원본을 삭제하지 않고 manifest에 함께 보존했다. 전체 프로젝트 회귀 통과를 의미하지 않는다.

신규 기능 시험은 실제 필수 정책에서의 검토, 예상 결과 불일치 시 저장0, 신원 변경·철회·버전 경합 거부, legacy 요청428, 암호화 백업→복원 후보 검토를 다룬다. 기존 실제 CLI subprocess/TCP 신원 변경 시험과 실제 Linux worker 재시작·페이지/보관 최소 head 검증을 함께 실행한다. 모의 provider만 사용하고 유료 API·AWS·Docker를 호출하지 않는다.

```powershell
python -m pytest tests/test_local_review_intent.py tests/test_audit_review_client_binding_process.py tests/test_audit_review_client_process.py -q
# Linux에서 별도 앱 worker 경로도 함께 실행
python -m pytest tests/test_local_review_intent.py tests/test_audit_review_client_binding_process.py tests/test_audit_review_client_process.py tests/test_http_worker_restart.py -q
```

전체 회귀 결과 정리와 8시간 soak는 이번 단계에서 실행하지 않았다. 모델·프롬프트·정답·평가 예측을 변경하지 않아 기존 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·오탐률3.33%는 그대로다. 이번 기능 시험은 탐지 지표 평가가 아니다. 다음 개발은 별도 감사 보관/검증자의 로컬 구현이며 같은 호스트를 실제 독립 운영 보관으로 표현하지 않는다.
