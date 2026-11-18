# 장기 평가 API의 관리자 권한·분석 한도·취소 정리

2026-11-19 · extra · 무료 로컬 시험, 원격 업로드·CI·병합 없음.

## 재현한 문제

`POST /evaluation/run`은 처음에 admin dependency를 통과한 뒤 전체 평가를 실행했다. 첫 사례에서 키를 철회해도200 응답과 나머지 모델 호출이 계속됐다. 공용 분석 한도를 모두 사용해도 평가 호출은 이를 우회했다. 서비스의 `gather`에서 한 사례가 치명적 예외로 끝나도 다른 사례는 실행 중인 채로 남았다. 수정 전3개 회귀 시험이 모두 실패했다.

## 변경

HTTP 평가의 각 사례는 요청별 평가 concurrency와 공용 `_analysis_slot`을 모두 얻어야 한다. 입장 직후 현재 신원과 admin 권한을 재확인하고, 사례의 모델 호출 동안 기존 Task-local `bind_analysis_authority`를 연결한다. 결과/예외 뒤에도 admin 신원을 재확인한다. 최종 summary 전달 직전에도 공용 slot에서 다시 확인한다.

따라서 평가의 OpenAIAnalyzer도 SDK 요청별 retries0 및 명시적 token retry의 현재 caller 검사 계약을 따른다. 공용 client 설정이나 standalone/offline 평가의 SDK 설정을 바꾸지 않는다. 아직 전송하지 않은 다음 요청을 막는 것이며 이미 전송된 vendor 요청의 취소·환불을 보장하지 않는다.

분석 한도 포화는429/`Retry-After: 1`이며 **평가 사례의 runtime 오류로 점수화하지 않는다**. 권한401/403이나 인증원503도 summary에 실패 사례로 숨기지 않고 요청 전체를 거부한다. 유효한 caller의 기존 timeout/provider/validation/runtime 오류 집계는 그대로다. synthetic ground truth와 기존 계산식을 변경하지 않았다.

평가 서비스는 각 사례 Task를 직접 소유한다. 치명적 예외/상위 취소 시 미완료 사례를 취소하고 모두 settle한 뒤 반환한다. 이 정리 중 다시 취소돼도 shield한 cleanup을 계속 기다린다. 사례가 `settled_io`를 실행하고 있다면 실제 worker가 끝나기 전 공용 slot을 반환하지 않는다. 중단 전에 실제로 전송한 모델 요청을 되돌리는 기능은 아니다.

## 검증

신규19건: 키 철회, 공용 한도 포화, fatal 시 sibling settle, role/tenant/subject/mode 변경4종, 대기 중 철회, 포화의 점수화 금지, 최종 전달 전 철회, 두 평가 요청의 공용 동시성, 반복 취소 중 thread 정리와 guard 종료, 실제 로컬 OIDC의 만료, authority 오류3종, 실제 SDK transient/출력제한 뒤 철회2종, 정상 token retry 유지다.

원래 synthetic8개 사례의 rule 평가는 기존 수치/사례 수를 유지한다. 평가 결과는 운영 분석 감사에 저장하지 않으므로 tenant별 운영 통계에 평가 사례를 섞지 않는다. SDK 시험은 실제 OpenAI SDK와 in-process MockTransport이며 외부 provider 요청은0이다. OIDC는 loopback 서명/JWKS이며 외부 SSO/MFA가 아니다.

최신 관련 Windows599건 통과·19건 제외, Linux616건 통과·2건 제외다. 원본 XML/소스 지문은 [검증 결과](infrastructure-results/extra-evaluation-authority-20261119.json)에 있다. [systemd54조건](infrastructure-results/extra-evaluation-authority-20261119-systemd.json)은 기존 로컬 회귀이며 신규19건과 합산하지 않는다. OS 간 중복도 합산하지 않는다.

```sh
python -m pytest tests/test_evaluation_authority.py tests/test_evaluation.py tests/test_caller_sdk_retry.py tests/test_analysis_caller_boundary.py tests/test_authentication_admission.py -q
```

## 남은 범위

이 변경은 평가의 **사례 실행과 summary 전달** 경계다. 요청별 analyzer 생성의 동기 설정/secret 조회와 요청 소유 SDK client 종료는 다음 작업이다. 모든 새 plugin/provider를 자동으로 sandbox하지 않는다. root pipeline의 provider stub 시험은 paid API 품질 재평가가 아니다.

새 F1·오탐·미탐 수치를 주장하지 않는다. 평가 원본/정답/기존 결과와 모델 prompt/판정은 그대로다. 실사용자 SSO/online revocation, 독립 witness/WORM, 다중 호스트·전원 단절·8시간 soak는 여전히 별도다.
