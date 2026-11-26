# 검토 CLI의 서버 측 호출 신원 연결

> 후속: [기존 워크벤치의 감사 페이지 탐색](extra-workbench-paging-20261119.md)을 완료했다. 아래 워크벤치 페이지 미완료 표현과 수치는 당시 기록이다. 전체 자유 검색·다른 목록 이전·실제 조직 배포/독립 성능 인수는 남아 있다.

> 후속: [서버 caller binding 필수화 선택 정책](extra-server-review-policy-20261119.md)을 추가했다. 아래 서버 정책 미완료 표현은 CLI 연결 시점이다. 기본값은 false이며 실제 조직 client 이관/전체 worker 배포는 남아 있다.

2026-11-19 · 로컬 `extra` · 구현 `a293c80`. 기존 대시보드·워크벤치 다음으로 운영자 CLI도 서버의 caller binding 검사를 사용하도록 연결했다. 서버·UI·모델은 바꾸지 않았다. 유료 API·AWS·Docker 자원 생성·push·CI·main/aitest 병합은 하지 않았다.

## 개선 전 실제 재현

기존 CLI는 제출 직전에 `/auth/me`를 확인했지만 PATCH에는 ETag만 보냈다. 그 확인 응답 뒤 같은 API 키가 같은 tenant의 다른 subject로 재매핑되면, 서버는 새 주체로 검토를 저장할 수 있었다. CLI는 응답 reviewer가 달라졌음을 나중에 감지했지만 이미 저장된 검토를 되돌리지는 못했다.

기준 HEAD `0f4165a`에 새 재현 시험1건을 추가해 이 경합을 확인했다. 기대 감사 행은2개였지만3개로 늘어 실패했다. 새 시험은 당시 untracked였으며 clean baseline 전체 실행이 아니다. [변경 전 실패 XML](infrastructure-results/cli-binding-before-20261119.xml)을 보존했다.

현재 CLI는 조회 당시의 `X-Review-Identity`를 스냅샷과 PATCH에 연결한다. 같은 경합에서 서버가 저장 전에403으로 거부하고 감사 행2개를 유지한다. 서버의 기존 검사를 실제 client가 소비하도록 바꾼 작업이다.

## 달라진 계약

| 단계 | 현재 동작 |
|---|---|
| prepare | 전후 `/auth/me`와 상세 조회. strong ETag1개·caller binding1개·`X-Review-Mode: conditional`1개를 요구 |
| 신원 연결 값 | 서버 header가 subject·tenant·auth method의 기존 domain-separated SHA-256 표현과 일치하는지 확인 |
| 파일 | `operator-audit-review-snapshot-2`에 `review_identity`, `review_mode` 추가. 자격 증명은 저장하지 않음 |
| 제출 전 | 파일 필드·origin·결과/ETag·identity/binding·mode를 먼저 검증. 현재 `/auth/me`와도 일치해야 함 |
| PATCH | 조회한 `If-Match`와 `X-Review-Identity`를 함께 전송. 최신 결과를 다시 읽어 버전을 바꾸지 않음 |
| 성공 응답 | 기존 대상·analysis core·reviewer·상태·메모·ETag 외에 응답 caller binding도 검증 |
| 오류 | 신원 변경403·stale412·응답 유실에 자동 재시도/조건 생략/이력 삭제 없음 |

caller binding은 인증 토큰·서명이나 실제 사람이 읽었다는 증거가 아니다. 현재 인증된 서버 principal과 비교하는 의도 연결 값이다. 실제 API key/OIDC 인증·responder 권한·tenant·현재 계정/만료·SQLite CAS 검사는 기존 서버가 담당한다. 공유 계정의 서로 다른 사용자를 구분하거나 credential 세대/독립 최신성을 증명하지 않는다.

## 예전 스냅샷 처리

**v1 파일은 그대로 보존하지만 새 CLI의 review 입력으로는 거부한다.** 파일을 자동 수정하거나 기존 결과에 현재 신원 값을 채워 넣어 v2로 만들지 않는다. 새 파일명으로 prepare한 뒤 결과와 신원·버전을 다시 확인해야 한다. CLI 인수와 prepare/review 두 단계 명령은 유지한다.

```powershell
python -m scripts.audit_review_client --base-url https://localhost:8443 --ca-file runtime/tls/root.crt prepare --event-id EVENT_ID --snapshot runtime/review-observed-v2.json
python -m scripts.audit_review_client --base-url https://localhost:8443 --ca-file runtime/tls/root.crt review --snapshot runtime/review-observed-v2.json --status IN_REVIEW --note "조회한 실행 근거와 현재 검토 신원을 확인함"
```

예시의 credential은 기존 `SECOPS_API_KEY` 환경변수에서 읽으며 명령행에 키를 넣지 않는다. 실제로 실행한 것은 격리된 합성 시험뿐이다. Bearer의 `--bearer --credential-env ...`, mTLS의 `--cert-file ... --key-file ...`, 검증된 HTTPS만 사용하는 기본 계약은 유지한다. 평문 HTTP는 기존 literal loopback/localhost 예외만 허용한다. redirect·환경 proxy를 따라가지 않고 TLS 검증을 끄는 옵션을 추가하지 않았다.

스냅샷은 최대2MiB·중복 JSON key/비정상 숫자/비정규 파일 거부·기존 파일 덮어쓰기 금지·POSIX0600 계약을 유지한다. Windows ACL을 새로 하드닝한 작업은 아니다. 파일과 서버를 모두 통제하는 관리자에 대한 독립 witness나 서명 증거가 아니다.

## 지원 조건과 복구

상세 응답의 ETag·caller binding·conditional mode가 모두 필요한 CLI다. 오래된 서버나 JSONL 등 미지원 backend에 연결했다고 metadata 요구를 생략하지 않는다. 서버의 `AUDIT_REVIEW_REQUIRE_IF_MATCH` 기본값과 caller header 선택 정책은 그대로이므로 모든 다른 API client에 이 검사가 강제된 것은 아니다.

- v1/필드 불일치/스냅샷 binding 변경: HTTP 요청 전에 거부. 새 스냅샷을 만들고 내용을 확인한다.
- 403/401: 현재 키·주체·권한을 확인한다. 다른 주체의 스냅샷을 그대로 제출하지 않는다.
- 412: 다른 검토나 새 분석으로 버전이 바뀌었다. 명시적으로 새 prepare를 수행한다.
- 네트워크·부분 응답·성공 응답의 binding 불일치: 이미 저장됐을 수 있다. 현재 이력을 먼저 확인한다. CLI 실패가 rollback을 뜻하지 않는다.

## 무료 로컬 검증

새26건은 ASGI 실제 인증/SQLite에 대한24건과 **실제 CLI subprocess + loopback TCP**2건이다. 후자는 HTTP bridge가 실제 ASGI 앱으로 전달하며, 별도 앱 process 자체를 새로 구현한 시험은 아니다. 기존 Linux native HTTP worker/CLI subprocess 회귀도 함께 실행한다.

새 시험은 최종 who 직후 subject 변경·실제 PATCH의 두 header·v2 파일·v1 거부·누락/중복/잘못된 metadata·미지원 backend·snapshot 변조·commit 후 잘못된 응답 binding·재전송 금지를 확인한다. 실제 프로세스의 stdout/stderr와 파일에 자격 증명이 들어가지 않는지도 검사한다. 소유 TCP 서버·스레드는 종료/회수한다.

기존 CLI/TLS/mTLS·ETag/신원·API·release 입력 회귀를 OS별로 묶어 실행했다. 원본 XML·소스 지문·최종 집계는 [검증 원본 JSON](infrastructure-results/extra-cli-review-binding-20261119.json)을 따른다. 두 OS의 동일 사례나 새 시험과 그 회귀를 합산해 독립 사례 수로 표시하지 않는다.

| 실행 | 결과 | 해석 |
|---|---|---|
| 변경 전 경합 재현 | 1실패 | 신원 확인 직후 계정 변경으로 잘못된 주체의 검토가 이미 저장됨 |
| 최종 Windows | 217통과·POSIX3제외 | 같은220개 사례, 새26건 모두 통과 |
| 최종 Linux | 220통과·제외0 | native worker/CLI·POSIX 계약까지 포함, 새26건 모두 통과 |

이 묶음은 새 저장소 전체 시험이 아니다. 이번 변경에는 UI 수정이 없어 브라우저 묶음을 새로 실행한 것으로 보고하지 않는다.

기존 TLS/mTLS6건은 실제 암호화 전송·CA/hostname/client cert·redirect를 검증하는 회귀이며, 새 CLI 경합은 loopback HTTP/ASGI bridge와 기존 native worker 경로에서 검증했다. 새 전체 TLS 배포·기업 SSO 인수나 실제8시간 soak를 실행한 결과는 아니다.

```powershell
python -m pytest tests/test_api.py tests/test_audit_review_client_binding.py tests/test_audit_review_client_binding_process.py tests/test_audit_review_identity.py tests/test_audit_review_preconditions.py tests/test_audit_review_wire_identity.py tests/test_audit_review_preservation.py tests/test_audit_query_admission.py tests/test_audit_review_client.py tests/test_audit_review_client_transport.py tests/test_audit_review_client_process.py tests/test_http_review_preconditions.py tests/test_api_key_accounts.py tests/test_runtime_release.py -q --junitxml=runtime/cli-binding.xml
```

## 성능 지표와 남은 작업

모델·프롬프트·분류 규칙·평가 원본·정답·기존 예측은 변경하지 않았다. 기존 실제 API 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%는 그대로다. 이 작업을 탐지 성능 개선이나 독립95% 목표 달성으로 집계하지 않는다.

자체 대시보드·기존 워크벤치·새 CLI의 서버 caller binding 소비는 연결됐다. 다른 custom client의 목록화/이전과 서버 측 필수화 정책, 워크벤치 페이지/전체 자유 검색, 실제 조직 인증원·독립 witness/WORM·최신 전체 회귀·긴 운영/다중 호스트 장애 인수는 남아 있다.
