# 감사 조회·검토의 동시 실행 제한과 현재 호출자 확인

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 재현과 변경

감사 `/results`, 상세 조회, `/metrics`는 요청별 전체 체인 검증을 수행할 수 있다. 기존 sync route의 task를 취소해도 디스크 작업은 남을 수 있었으며, 조회/검토 전용 동시 실행 제한이 없었다. 또한 조회를 기다리는 중 API 키 권한이 바뀌어도 최초 Principal만으로 응답을 전달했다. 검토 역시 조회 후 계정 변경을 확인하지 않고 append할 수 있었다. 유효한 요청으로 구성한 변경 전10개 회귀에서 이 경계를 재현했다. 별도로 readiness 감사 검사도 같은 제한을 우회하는1개 실패를 재현했다.

이제 조회·통계·검토 저장·readiness는 프로세스별 공통 query 슬롯을 사용한다. 기본2개이며 포화 시 짧게 기다린 뒤503/Retry-After:1로 제한한다. 디스크/DB 작업은 `settled_io`에서 수행한다. 취소된 요청은 이미 시작한 작업이 끝나기 전까지 슬롯을 반환하지 않는다. 검토는 조회부터 append 완료/실패까지 한 슬롯을 유지한다. 기존 분석 전 무결성 검사는 별도 분석 슬롯의 제한을 유지한다.

인증된 조회와 검토는 저장소 객체를 고정하고 I/O 전후에 현재 serving 저장소와 대조한다. API 키의 요청별 revalidator와 OIDC 인증 만료 시각을 다시 확인한다. 오래된 저장소 응답이나 철회/만료된 호출자의 결과는 전달하지 않는다. 검토는 append 직전과 직후에도 확인한다. tenant 필터·전체 체인 검증·검토 CAS·원래 분류는 유지했다.

## 커밋과 응답의 구분

계정 철회가 조회 중 발생하면401이며 검토 append는0회다. 이미 검토가 커밋된 뒤 철회되거나 요청이 취소되면 과거 기록은 보존하고 성공 전달을 거부한다. 이 기록을 되돌리거나 새 접근 권한을 발급하지 않는다. 인증원과 감사 DB가 하나의 원자적 트랜잭션인 것은 아니므로, 경계 사이에 일어난 철회를 커밋 자체의 무효화로 주장하지 않는다.

## 설정

```dotenv
AUDIT_QUERY_MAX_CONCURRENCY=2
AUDIT_QUERY_QUEUE_TIMEOUT_SECONDS=0.05
```

동시 실행은1~8, 대기는0.01~2초의 유한 값만 허용한다. 앱 시작 때 프로세스별 semaphore를 만든다. 프로세스 수만큼 전체 한도가 늘며 다중 호스트 전역 한도가 아니다. `.env.example`에 기본값을 추가했고 기존 실행 설정을 자동 변경하지 않았다.

## 검증 내용

신규21개 시험은 실제 로컬 API 키·SQLite 감사와 로컬 OIDC의 실제 서명/JWKS HTTP를 사용한다. provider나 AWS를 호출하지 않는다. 주요 사례는 다음과 같다.

- 목록/상세/통계의 취소: 작업 완료 전 슬롯 유지, 추가 조회503, liveness200, 완료 후 정상 조회·tenant 격리.
- 혼합8요청/슬롯2: DB 읽기2개만 실행,6개503. 진행 중 두 요청을 취소해도 후속 검토503, 완료 후 슬롯2개 복구·감사 이력 불변.
- 조회 중 키 변경/저장소 교체, 검토 조회 후 철회, 검토 커밋 후 철회·취소 시 기록과 전달의 분리.
- 실제 로컬 OIDC가 조회/검토 도중 만료되면401. 검토 전 만료는 append0회, 커밋 후 만료는 이력 보존.
- readiness 검사 취소도 같은 풀을 유지하며 단순 liveness는 응답. 무한·범위 밖 설정은 시작 설정 검증에서 거부.

신규21개를 포함해 **Windows 관련175건·Linux 확대242건 통과**. 실제 systemd/ptrace·공유 참조·독립 HTTP worker 종료/재기동·TCP HTTP·감사 암호화 백업/복원 **41조건도 최신 코드로 통과**했다. worker/unit/private 상태/임시 의존성은 정리했고 원래 권한/실행 이력·감사 DB를 보존했다. XML/소스 지문은 [검증 기록](infrastructure-results/extra-audit-query-admission-20261119.json), 실제 인수는 [systemd 결과](infrastructure-results/extra-audit-query-admission-20261119-systemd.json)에 정리한다. OS별 중복 시험을 독립 사례로 합산하지 않는다.

```sh
python -m pytest tests/test_audit_query_admission.py tests/test_api.py tests/test_sqlite_audit.py tests/test_federated_audit.py tests/test_audit_preflight.py -q
```

## 한계와 후속

ASGI task 취소와 로컬 JWT/JWKS 만료 검증이다. 실제 TCP 연결 단절이나 기업 SSO의 계정 폐기/토큰 introspection을 검증한 것은 아니다. readiness는 부하 시503이 될 수 있으며 liveness와 분리한다. 영구 정지한 I/O의 강제 종료는 하지 않는다.

전체 체인을 건너뛰거나 검증 결과를 캐시하지 않았으므로 단일 대규모 조회의 비용은 남아 있다. SQL payload/row 상한과 기존 최근100개 응답 제한도 유지한다. 새 페이지 조회와 메모리/검증 비용 개선, 복원 checkpoint의 운영 보관을 후속으로 진행한다. 평가 원본·정답·예측·F1·오탐/미탐 수치는 바꾸지 않았다. 다중 호스트/전원 단절/원격 WORM/연기한8시간 시험은 미완료다.
