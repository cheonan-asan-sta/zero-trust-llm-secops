# 초기 인증 I/O 한도와 취소 후 자원 소유권

2026-11-19 · extra · 무료 로컬 시험. 원격 업로드·CI·병합·AWS·유료 API 없음.

## 문제와 구현

기존 초기 API key 계정 조회는 event loop에서 동기 실행됐다. 느린 계정 파일이 liveness까지 지연할 수 있었다. OIDC의 JWKS 조회는 thread로 옮겼지만 요청 취소가 실제 thread 종료보다 먼저 반환돼, 이후 요청이 추가 thread를 계속 만들 수 있었다. 변경 전 두 회귀 사례가 모두 실패한 XML을 보존했다.

초기 계정/JWKS 확인에 앱·프로세스별 한도를 추가했다. 기본 동시4개, 대기0.05초이며 포화 시503과 `Retry-After: 1`을 반환한다. 대기 자체는 executor thread를 만들지 않는다. `settled_io`가 실제 worker의 완료/실패까지 기다리므로 취소 후에도 해당 한도를 유지한다. 한도를 얻기 전 취소된 요청은 다른 요청의 자원을 반환하지 않는다. 소유한 정확한 limiter 객체를 반환해 app state 교체 중 잘못된 자원 반환도 막는다.

`AUTHENTICATION_MAX_CONCURRENCY`는1~16, 대기 시간은 유한한0.01~2초, bearer 최대 길이는 기본16,384자(1,024~131,072)다. limiter 크기는 앱의 첫 보호 인증 시 고정되며 재시작해야 바뀐다. 처리 중 설정 변경으로 별도 pool을 열지 않는다. 앱별 한도이며 여러 프로세스/호스트의 전역 한도가 아니다. 빠른 누락/과대 입력은 계정/JWKS I/O 없이401이다.

입장 후 최신 설정을 복사해 decoder가 섞인 설정을 읽지 않도록 했다. 초기 조회 직후에도 같은 slot 안에서 계정 철회·OIDC 만료·issuer/audience/JWKS URL 등 정책 변경을 확인한 뒤 `request.state.principal`을 공개한다. 대기 중 인증 mode 변경은 거부한다. disabled는 로컬 기존 동작을 유지하고 신원 I/O를 만들지 않는다. 복사 후 mode도 확인한다. callback은 기존처럼 digest/identity만 보관하며 raw API key나 bearer를 보관하지 않는다.

이 한도는 **초기 인증 I/O**다. 분석/감사 읽기의 후속 재검증은 해당 기존 한도에서 실행된다. 전체 서비스의 모든 디스크/네트워크 I/O를 하나로 제한했다는 뜻은 아니다.

## 시험과 근거

신규30건은 API key/OIDC 느린 성공·실패와 취소, 포화·복구·liveness, 대기 취소, 정확한 lease 반환, 대기 중 키/mode 변경, frozen decoder scope, 최종 신원 확인, 만료, 빠른 잘못된 입력5종, 서로 다른 event loop, 실제 RSA JWT와 loopback JWKS 지연/취소, 설정 경계와 잘못된 런타임 설정을 검증한다.

실제 loopback JWKS 시험은 서명 검증에 필요한 HTTP 응답을 멈추고 caller를 취소한다. 기존 worker가 유지되는 동안 두 번째 인증은503, liveness는200이다. 응답을 풀면 원래 취소가 완료되고 다음 인증은200으로 복구된다. 실제 로컬 인증원의 키 조회는1회이며 외부 SSO/MFA/online revocation 시험은 아니다.

최신 관련 Windows575건 통과·19건 제외, Linux592건 통과·2건 제외다. 원본 XML 지문은 [기계 판독 결과](infrastructure-results/extra-authentication-admission-20261119.json)에 기록한다. [실제 systemd 회귀54조건](infrastructure-results/extra-authentication-admission-20261119-systemd.json)은 별도 기존 시험이며 신규30건과 합산하지 않는다. OS 간 중복 사례도 합산하지 않는다.

```sh
python -m pytest tests/test_authentication_admission.py tests/test_security.py tests/test_verified_caller_authority.py tests/test_analysis_caller_boundary.py tests/test_api.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 한계와 다음 작업

멈춘 파일/JWKS thread를 강제 종료하지 않는다. 완료 전까지 bounded slot을 점유해 추가 작업을 제한하는 방식이며 OS 수준의 강제 I/O deadline/복구는 별도다. SDK 요청을 이미 보냈다면 취소/환불을 보장하지 않는다. 동일 JWKS URL에서의 online token revocation이나 실제 사람의 enterprise SSO/MFA는 구현 완료로 계산하지 않는다.

별도 장기 `/evaluation/run`의 관리자 권한 재확인·모델 호출 한도와 취소 후 남은 작업 정리는 다음 점검 범위다. 모델 prompt/판정·평가 원본/정답/결과·기존 F1/오탐/미탐을 바꾸거나 새로 측정하지 않았다. 독립 witness/WORM·다중 호스트·전원 단절·연기한8시간 soak도 남아 있다.

후속: [평가 API 관리자 권한·공용 한도·취소 정리](extra-evaluation-authority-20261119.md)를 추가했다. 위 수치는 해당 시점 기록이다.
