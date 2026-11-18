# 평가 요청이 소유한 client의 생성·정리와 작업 한도

2026-11-19 · extra · 무료 로컬 검증. 유료 API·AWS·업로드·CI·병합 없음.

## 문제와 적용 범위

평가 사례에 권한·공용 분석 한도를 연결한 뒤에도, 요청별 analyzer 생성은 event loop에서 동기 실행됐다. 설정에 따라 secret 조회나 client 생성이 느리면 liveness까지 막혔다. 평가 후 요청 소유 SDK client를 명시적으로 종료하지도 않았다. 변경 전 두 회귀 사례가 모두 실패했다.

`evaluation_runtime`이 **생성부터 모든 사례 종료·client 정리까지** 요청의 자원 소유권을 관리한다. 앱·프로세스별 기본2개 평가 작업, 대기0.05초다. 포화 시503/`Retry-After: 1`이며 factory를 실행하지 않는다. `EVALUATION_MAX_CONCURRENCY`는1~4, 대기는 유한한0.01~2초다. 앱 첫 사용 시 고정된 counter를 재시작으로 조정한다. 개별 사례의 기존 공용 analysis slot과 요청별 concurrency도 유지한다. 전체 평가 한도503과 개별 분석 한도429는 다른 계층이다.

동기 factory는 `settled_io`로 실행한다. worker가 만든 analyzer를 worker 내부에서 소유 목록에 기록하므로, 기다리던 요청이 취소돼도 반환값을 잃어 client를 방치하지 않는다. 생성 전·후 현재 admin 권한을 검사한다. 생성 중 철회됐으면 모델을 호출하지 않고 생성된 client만 정리한다. 기다리던 요청의 취소와 실제 worker 종료는 다르다. 실제 종료 전까지 작업 한도를 유지한다.

정상·오류·취소 모두 사례 Task가 settle한 다음 요청 소유 analyzer의 async `close()`를 기다린다. `settled_awaitable`로 반복 취소 중에도 이 정리를 기다린다. OpenAIAnalyzer는 SDK client를 닫는다. Hybrid는 자신이 생성한 LLM만 닫고 외부에서 주입된 adapter의 소유권은 넘겨받지 않는다. 캐시된 일반 분석 analyzer의 수명을 평가 종료로 바꾸지 않는다.

정리 중에도 시간이 흐르고 권한이 바뀔 수 있으므로 **정리를 마친 뒤** summary 전달 전 admin 권한을 다시 확인한다. setup/cleanup 예외는 상세 문자열을 HTTP 응답에 노출하지 않고503으로 응답한다. 정리 실패 뒤 정상 summary를 전달하지 않는다. 실패한 transport를 강제로 완전 종료했다는 주장은 하지 않는다.

기존 인증의 thread-safe counter를 `work_admission`으로 공통화했다. 인증·평가의 app state key와 한도는 분리한다. 기존 초기 인증 취소/포화/JWKS 시험도 함께 재검증한다. `settled_io`의 기존 thread 대기도 공통 async settle helper를 사용하며 반환/예외/반복 취소 계약은 유지한다.

## 시험 근거

신규24건은 느린 생성과 liveness, 정상1회 정리, 생성 성공/실패 중 반복 취소2종, async 정리 중 반복 취소, 대기 취소, setup 예외2종의 상세 비공개, cleanup 실패, cleanup 중 철회, setup 중 철회, 정확한 limiter 반환, 설정 경계6종, 잘못된 런타임 설정2종, OpenAI/Hybrid 실제 SDK client 종료2종, 주입 adapter 소유권 유지, 사례가 모두 끝난 뒤 정리 순서를 검증한다.

실제 SDK client/HTTPX transport를 사용하지만 HTTP 응답은 in-process MockTransport다. 외부 OpenAI 호출·과금은0이다. 실제 secret manager나 AWS를 호출한 것이 아니라 느린 factory와 실패를 통제해 검증했다. SDK client가 닫혔는지 실제 상태를 확인했다.

최신 관련 Windows623건 통과·19건 제외, Linux640건 통과·2건 제외다. 원본 XML/소스 지문은 [기계 판독 결과](infrastructure-results/extra-evaluation-runtime-20261119.json)에 기록했다. [systemd54조건](infrastructure-results/extra-evaluation-runtime-20261119-systemd.json)은 별도 기존 회귀다. OS 간 중복과 신규24건을 systemd 조건 수에 합산하지 않는다.

```sh
python -m pytest tests/test_evaluation_runtime.py tests/test_evaluation_authority.py tests/test_evaluation.py tests/test_authentication_admission.py tests/test_caller_sdk_retry.py tests/test_hybrid_analyzer.py tests/test_async_audit_io.py tests/test_async_evidence_io.py -q
```

## 한계와 다음 확인

멈춘 생성/close를 강제로 종료하지 않는다. 실제 종료까지 bounded 작업 한도를 유지하는 방식이다. OS 전역 executor, 다중 프로세스/호스트의 전역 자원 한도나 vendor 요청 환불을 구현하지 않았다. 새로운 provider adapter에는 async close와 ownership 계약을 연결해야 한다.

평가는 기존8개 synthetic 기본 사례와 기존 계산식을 유지한다. 새 성능 평가 자료가 아니며 F1·오탐·미탐 수치를 갱신하지 않는다. 실제 기업 SSO/online revocation, 독립 witness/WORM, 다중 호스트·전원 단절·미뤄둔8시간 soak는 남아 있다. 다음에는 일반 batch의 반복 취소 정리와 감사 조회/응답 경계의 회귀를 확인한다.

후속: [서버 공유 provider의 첫 생성·취소 경계](extra-cached-provider-setup-20261119.md)를 추가했다. 위 수치/남은 범위는 해당 시점 기록이다.
