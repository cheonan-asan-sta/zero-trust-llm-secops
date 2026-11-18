# 일반·배치 분석의 현재 호출 권한 검증

2026-11-19 · extra · 무료 로컬 구현/시험. 유료 API/AWS/push/CI/병합 없음.

## 문제와 구현

일반 `/analysis`와 `/analysis/batch`는 입장 때 API 계정을 확인했지만, 모델 실행이나 감사 저장 중 그 계정이 철회돼도 성공 응답을 줄 수 있었다. 감사 조회·verified 분석에 있던 request-local 재검증 함수를 일반 파이프라인에도 연결했다. 수정 전 일반/배치8개 사례 모두 성공 응답이 나가 **8실패**로 재현했다.

현재 입장한 principal과 요청 전용 `authentication_revalidator`를 분석에 전달한다. 전역 설정이나 공용 analyzer에 사용자 자격증명을 넣지 않는다. API key callback은 기존처럼 plaintext key 대신 digest와 서버 principal만 사용하고, 계정 파일은 매번 다시 연다.

- 슬롯을 얻은 뒤, audit preflight 뒤 모델 직전, 저장 직전, 저장 뒤, 근거/보존 확인 뒤 성공 전달 전에 현재 권한을 확인한다.
- callback I/O는 `settled_io` 안에서 수행하고 시작한 읽기가 끝날 때까지 분석 슬롯을 유지한다. callback 뒤 현재 시각의 인증 만료와 ANALYST 유효 역할도 확인한다.
- 기다리는 동안 철회/만료됐거나 preflight 중 바뀌면 provider0회다. 모델 이후 저장 전 철회는 새 결과를 저장하지 않는다. 이미 커밋한 뒤 철회되면 이력을 보존하고 성공 전달을 거부한다. 쓰기 대기/실행 도중의 철회를 DB와 원자적으로 묶었다는 주장은 하지 않는다.
- 알려진 인증 철회·만료는401, 역할 부족은403, 계정 설정 파일 확인 불가는503으로 전달한다. 이 HTTP 오류를 provider502로 덮지 않는다. 실제 분석/저장 실패의 기존502와 capacity429는 유지한다.

배치도 각 항목에 같은 request-local 권한을 적용한다. 한 항목이 실패하면 미완료 형제를 취소하고 정리해 대기 작업이 응답 뒤 계속 실행되지 않도록 한다. 이미 성공한 감사 커밋은 지우지 않는다. 전체 배치 응답 전에도 분석 슬롯 안에서 마지막 권한을 확인한다. 그 최종 gate도 부하 시429가 될 수 있으며, 끝난 모델 작업을 없던 일로 만들지는 않는다.

## 인증원별 범위

API key는 현재 서버 계정 파일의 enabled/subject/tenant/roles와 기존 principal이 같아야 한다. 파일 삭제·잘못된 JSON·중복 키는 설정 오류503이며 legacy key로 우회하지 않는다. `auth_mode=disabled`로 입장한 로컬 요청도 서버가 인증을 켜면 같은 요청을 계속 허용하지 않는다.

OIDC는 초기 JWT 서명을 실제로 확인한 principal의 만료를 매 경계에서 확인한다. issuer/audience/JWKS URL/roles claim/tenant claim/auth mode의 서버 설정이 바뀌면 기존 요청을 거부한다. token을 재전송하거나 callback에 bearer plaintext를 보관하지 않는다. **같은 issuer의 로그아웃·실시간 token 폐기·같은 URL의 키 폐기·외부 SSO 상태를 introspection하는 구현은 아니다.** 실사용자 MFA/기업 SSO 완료로 표시하지 않는다.

API 계정 파일 reader는 POSIX 전용 상수 직접 참조를 제거해 Windows에서도 동작하도록 했다. 지원되는 NOFOLLOW/NONBLOCK/BINARY flag와 regular file·상한·FD/path read 전후 안정성을 확인한다. 도중 교체/변경을 한 번의 오래된 성공 결과로 숨기지 않고 해당 검증을 실패시킨다. 이 파일 경로는 서버가 관리하는 신뢰 설정이며 별도 원격 서명 attestation은 아니다.

## 검증과 근거

신규41건: API key 경계8건, 슬롯 대기 중 철회2건, 로컬 서명 OIDC의 제어 시각 만료8건, OIDC 서버 설정 변경6건, 계정 파일 변경/철회/설정 오류7건, disabled→인증 전환1건, 무관한 모델 설정 변경 허용1건, 내부 principal 만료/역할3건, caller I/O 취소·정리2건, 배치 형제 정리1건, 계정 파일 read 중 변경1건, 실제 독립 HTTP process1건이다.

OIDC 사례는 루프백 JWKS·실제 RSA 서명 token을 검증한 뒤 파이프라인 시각을 제어해 만료 경계를 시험한다. 60초를 실제 기다리는 soak나 외부 사람 인증으로 설명하지 않는다. 실제 HTTP process 사례는 provider stub이 시작한 marker의 PID를 소유 process와 대조하고, 응답을 대기시킨 사이 계정을 비활성화한 뒤 release한다. 응답401·stub1회·새 감사0행·liveness 유지·소유 process kill/wait를 확인한다. 이미 시작한 모델을 되돌렸다고 표현하지 않는다.

최종 관련 **Windows472건 통과·4건 제외, Linux474건 통과·2건 제외**다. 제외는 기존 POSIX FIFO/키 권한(Windows2)과 JSONL 전용 page2건이다. [OS별 묶음·수정 전8실패 XML·소스 지문](infrastructure-results/extra-analysis-caller-boundary-20261119.json), [최신 실제 systemd54조건 회귀](infrastructure-results/extra-analysis-caller-boundary-20261119-systemd.json). 새 HTTP1건은 별도 pytest이고 systemd 수에 합산하지 않는다. OS별 같은 사례도 합산하지 않는다.

```sh
python -m pytest tests/test_analysis_caller_boundary.py tests/test_http_caller_boundary.py tests/test_api_key_accounts.py tests/test_response_api_key_identity.py tests/test_api.py tests/test_audit_query_admission.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 다음 경계와 남은 한계

이번 일반 분석 검사는 **analyzer 호출 전후의 서버 경계**다. 이미 전송한 모델 요청·완료된 vendor 비용을 취소하지 못하며, ordinary SDK 내부 자동 retry마다 권한을 다시 확인하는 연결은 후속이다. verified context의 기존 SDK retry 제한과 구분한다. 초기 인증 dependency의 I/O admission과 `/evaluation/run` 같은 별도 장기 작업도 별도 검토 대상이다. 모든 API/백그라운드 작업에 같은 신규 경계를 적용했다고 주장하지 않는다.

권한·감사 DB·외부 source 사이의 원자적 공동 snapshot, 독립 WORM/witness·최신 전체 상태·기업 SSO·다중 호스트·전원 단절·연기한8시간 soak는 미완료다. 모델 판정·평가 원본/정답/예측·F1·오탐/미탐을 변경하거나 재평가하지 않았다.
