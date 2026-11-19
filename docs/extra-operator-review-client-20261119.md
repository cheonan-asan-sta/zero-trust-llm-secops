# 운영자 검토 CLI: 읽은 버전·호출 신원·TLS 연결

> 후속 안내: 이 문서는 `c0a8108` 당시 CLI 범위를 보존한다. 이후 자체 대시보드 검토는 [별도 구현·검증 보고서](extra-dashboard-review-20261119.md), audit cursor 소비는 [페이지 후속](extra-dashboard-paging-20261119.md)에서 완료했다. 아래의 UI 미완료 표현은 CLI 작업 시점이며 legacy workbench/다른 client 이전은 여전히 남아 있다.

2026-11-19 오전08:00 개발 마감 뒤의 별도 후속 작업이다. `extra` 전용 로컬 구현이며 GitHub 업로드·CI·main/aitest 병합·AWS·유료 API 호출은 하지 않았다. 구현 기준은 `c0a8108`이다.

## 해결한 빈 연결

서버는 SQLite 검토의 strong ETag/If-Match를 지원하지만, 운영자가 그 값을 실제 검토 요청에 연결하는 명령은 없었다. [`scripts.audit_review_client`](../scripts/audit_review_client.py)를 추가해 **조회와 검토를 별도 명령**으로 실행한다. 대시보드 UI 연결을 완료한 것은 아니다.

1. `prepare`가 `/auth/me`와 결과 상세를 읽고 신원·tenant·반환 ETag·결과 내용을 확인한다. 조회 뒤 신원이 바뀌지 않았는지도 다시 확인한다.
2. 확인한 결과 전체와 ETag, 호출 신원, 명시적 서버 origin을 새 snapshot 파일에 저장한다. 기존 파일을 덮어쓰지 않고 자격 증명을 파일에 넣지 않는다.
3. 운영자가 파일 내용을 확인한 뒤 `review`를 별도로 실행한다. 결과 내용/ETag 변경, 다른 origin, 다른 호출자/tenant는 제출 전에 거부한다.
4. 조회 당시의 ETag를 `If-Match`로 전송한다. 서버가 오래된 버전을 412로 거부하면 새 버전을 자동 조회해서 덮어쓰거나 자동 재시도하지 않는다.
5. 성공 응답도 원래 분석 core·대상·선택한 상태/메모·서버 reviewer·응답 ETag가 맞는지 확인한다.

ETag는 본문 전체를 서버가 표현한 버전에 묶는 값이다. 독립 서명이나 사람이 실제로 읽었다는 증명은 아니다. 로컬 snapshot과 해당 서버/기록을 함께 통제하는 관리자에 대한 외부 최신성 증명을 제공하지 않는다.

## 운영 연결 조건

| 조건 | 동작 |
|---|---|
| 원격 연결 | HTTPS만 허용. 서버 CA와 hostname 검증을 끄는 옵션 없음 |
| 로컬 재현 | literal loopback IP 또는 localhost의 HTTP만 예외 허용 |
| mTLS | `--ca-file`, `--cert-file`, `--key-file`로 별도 구성. client cert/key는 함께 제공 |
| 호출자 인증 | 환경변수의 API key 또는 Bearer token. 인증 비활성 identity는 사용하지 않음 |
| redirect/proxy | HTTP redirect를 따라가지 않고 환경 proxy를 상속하지 않음. 다른 origin으로 자격 증명 전달 금지 |
| snapshot | 최대2MiB, 중복 JSON key·NaN/Infinity·symlink·비정규 파일 거부. POSIX 생성 권한0600 |
| backend | 조건부 review를 지원하는 extra SQLite 서버 필요. JSONL/federated 503에서 무조건 쓰기로 우회하지 않음 |

mTLS client 인증은 전송 연결의 신원 확인이다. CLI의 사람/서비스 신원은 서버가 검증하는 API key/OIDC identity이며, client 인증서를 기업의 실사용자 신원으로 자동 간주하지 않는다. Windows snapshot의 ACL을 별도 하드닝하거나 기업 SSO를 새로 연동한 작업은 아니다.

## 사용 예

저장소 checkout과 기존 프로젝트 Python 환경에서 실행한다. 기본 자격 증명 환경변수는 `SECOPS_API_KEY`이며 이 도구가 dotenv를 읽거나 키를 발급하지 않는다. 아래 서버와 인증서 경로는 예시다. 실제로 실행한 것은 격리된 시험 fixture뿐이다.

```powershell
python -m scripts.audit_review_client --base-url https://localhost:8443 --ca-file runtime/tls/root.crt --cert-file runtime/tls/operator.crt --key-file runtime/tls/operator.key prepare --event-id EVENT_ID --snapshot runtime/review-observed.json
```

저장된 파일의 `identity`, `result`, `etag`를 확인한 뒤 같은 명시적 origin과 자격 증명으로 제출한다.

```powershell
python -m scripts.audit_review_client --base-url https://localhost:8443 --ca-file runtime/tls/root.crt --cert-file runtime/tls/operator.crt --key-file runtime/tls/operator.key review --snapshot runtime/review-observed.json --status IN_REVIEW --note "조회한 실행 근거를 확인하고 검토를 시작함"
```

Bearer 사용 시 공통 인수에 `--bearer --credential-env SECOPS_OIDC_TOKEN`을 추가한다. 출력에는 검토 상태와 서버가 확정한 reviewer만 포함하며 오류에서 원격 body·키·인증서 경로를 그대로 출력하지 않는다.

서버 strict 모드는 `AUDIT_BACKEND=sqlite`, `AUDIT_REVIEW_REQUIRE_IF_MATCH=true` 조합이다. **이번 작업에서 전역 기본값을 바꾸지 않았다.** 기존 UI가 헤더를 보내지 않으므로 모든 검토 client의 이전·검증 전에는 strict를 무조건 켜지 않는다. 이 CLI는 헤더 없는 fallback을 하지 않는다.

## 오류 뒤 처리

- 412: 다른 검토나 새 분석으로 버전이 바뀌었다. **새 파일명**으로 prepare한 뒤 내용을 다시 확인한다. 과거 snapshot을 최신 버전으로 자동 덮어쓰지 않는다.
- 401/403 또는 신원 불일치: 현재 인증·역할·tenant를 확인한다. 다른 주체의 검토 파일을 그대로 제출하지 않는다.
- 503·네트워크 오류·짧게 끊긴 HTTP 응답: 검토가 서버에 이미 저장됐을 수 있다. 현재 검토 상태와 감사 기록을 먼저 확인한다. CLI 실패가 서버 rollback이나 미실행을 뜻하지 않는다.
- 누락/약한/중복 ETag 또는 결과와 ETag 불일치: snapshot을 만들지 않는다. ETag가 없는 기존 main 서버에 연결했다고 조건을 생략하지 않는다.

## 로컬 검증과 남은 항목

최종 관련 묶음은 **Windows157통과·POSIX3제외, Linux160통과·제외0**다. 신규 client46건은 Windows44통과·POSIX2제외, Linux46통과이며 서로 다른 OS의 동일 사례를 합산하지 않는다. 나머지는 기존 검토/행 보존/초기 인증/native HTTP 회귀다. 기존 dependency deprecation 경고는 Windows3개·Linux2개이며 실패로 집계하지 않았다.

[OS별 JUnit 원본·소스 지문·검증 범위](infrastructure-results/extra-operator-review-client-20261119.json)에 결과를 보존한다. 실제 app의 인증·SQLite review 경로를 사용하는 사례와, 실제 loopback HTTP 별도 worker/CLI subprocess, 별도 실제 TLS/mTLS 서버를 구분한다. HTTPS 성공, 신뢰하지 않는 CA·다른 hostname·client cert 누락의 실패, 올바른 mTLS client 인증과 redirect 자격 증명 차단을 확인한다.

신규 client 검증은 caller/tenant/키 철회·조회 중 신원 변경·snapshot 변조·중복 ETag·오래된 검토/재전송·다른 응답 메모·성공 commit 뒤 응답 유실·부분 HTTP 응답도 다룬다. 불확실한 응답에서 감사 이력을 지우거나 자동 재전송하지 않는지 검사한다.

기존 관련 서버 회귀를 함께 실행했지만 새 전체 저장소 시험은 아니다. 기존 전체 Linux의 두 기대값 수정과 후속 재검증은 [이전 인수 기록](extra-local-validation-20261119.md)에 보존돼 있다. 이번에 기존 전체 실패 XML을 새 성공으로 바꾸지 않았다.

다음 작업은 UI의 ETag/If-Match와 audit cursor 연결이다. 기업 SSO/online revocation, 독립 witness/WORM, 다중 호스트·전원 단절·실제8시간 soak는 남아 있다. 모델·prompt·분류기·평가 정답/예측은 변경하지 않았으며 기존 합성 개발360건 F1 **93.41%**, 재현율 **90.56%**, 오탐률 **3.33%**는 그대로다. 새 모델 성능 개선이나 독립95% 목표 달성으로 해석하지 않는다.
