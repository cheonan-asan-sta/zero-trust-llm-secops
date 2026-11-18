# 서버 LLM 호출의 권한 범위와 SDK retry 경계

2026-11-19 · extra · 실제 SDK + 로컬 MockTransport 시험. 유료 API/AWS/push/CI/병합 없음.

## 확인한 문제

일반 분석의 입장/저장/전달 권한을 검사해도, `analyzer.analyze()` 안에서 SDK가 첫 실패 뒤 자동 재요청할 수 있었다. 첫408/409/429/500/502/timeout/connection failure 때 계정을 철회한7개 사례에서 응답은 결국401이지만 **SDK 요청이2회**였다. 수정 전7실패를 기록했다. 응답 차단과 추가 모델 호출 예방은 다른 검증이다.

## 변경된 호출 범위

서버 분석은 analyzer를 실행하는 동안만 `bind_analysis_authority`로 요청 전용 현재 호출 권한 검사를 연결한다. Task-local ContextVar를 사용하므로 cached analyzer/client를 공유해도 서로의 callback·retry 설정을 바꾸지 않는다. 입력 event나 prompt, client가 제출하는 신뢰 근거 필드로 추가하지 않는다. callback 자체는 기존의 digest/principal 검사를 사용한다.

`OpenAIAnalyzer`는 이 범위가 있으면 dispatch 직전, 응답 및 오류 뒤에 권한을 재확인하고 **해당 SDK 호출에만 `with_options(max_retries=0)`**를 사용한다. 공용 client의 max_retries는 바꾸지 않는다. verified source가 함께 있으면 추가된 caller I/O 뒤 source도 다시 확인해 근거 검사가 더 오래된 채로 호출되지 않도록 한다. 여러 외부 source를 원자적으로 함께 검사했다는 뜻은 아니다.

원래 있던 `max_output_tokens` 부족에 대한 명시적 retry0~1회는 유지한다. 그 다음 dispatch도 다시 검증해야 하므로, 첫 truncated 응답 이후 계정 철회/OIDC 만료가 확인되면 두 번째 요청을 보내지 않는다. 처음부터 유효한 응답을 더 유리한 판정을 고르려고 재시도하지 않는다.

서버 범위 밖에서 직접 사용하는 standalone/offline SDK는 기존 설정을 유지한다. 가용성 변화도 있다. **서버의 transient API 실패는 검증 없는 SDK 자동 복구 없이 실패**하며, 기존 Hybrid의 유효 호출자 fallback/human-review 정책은 유지한다. 호출 권한이 철회됐다면 Hybrid fallback으로 성공 응답을 숨기지 않는다. checked transient retry를 새로 구현했다고 주장하지 않는다.

## 수명과 동시성

범위가 정상 종료·오류·취소로 끝나면 owner guard를 닫고 ContextVar를 reset한다. child Task는 context 값을 상속하므로 reset만으로는 충분하지 않다. 상속된 guard가 닫혔는지 callback 전후 모두 확인해, owner가 끝난 뒤 지연 실행하는 child가 추가 SDK dispatch를 하지 못하게 했다. 검증 중 owner가 닫힌 경우도 같은 방식으로 거부한다.

독립 Task의 정상 호출이나 standalone retry 정책으로 그 닫힌 guard를 대체하지 않는다. 이것은 이미 vendor에 전송한 요청을 취소하거나 요금을 되돌리는 기능은 아니다. 아직 dispatch하지 않은 다음 호출의 서버 경계다.

## 검증 근거

신규20건: 최초7개 실패 유형, 명시적 token retry의 유효/철회2건, Hybrid 유효/철회2건, 성공 응답 뒤 guard 철회1건, guarded/standalone client 공유1건, 서로 다른 guarded caller1건, 종료 후 child dispatch 거부1건, 검증 중 종료1건, 오류 reset1건, 취소 reset1건, caller I/O 뒤 source 철회1건, truncated 뒤 OIDC 만료1건이다.

실제 OpenAI SDK parser와 HTTPX MockTransport를 사용했다. URL이 vendor API여도 transport가 in-process mock이라 외부 요청/과금은0이다. OIDC는 실제 로컬 서명/JWKS와 제어한 pipeline 시각으로 검증했고 외부 SSO/MFA를 시험하지 않았다. 정상 첫 응답·출력 제한·shared client 설정·source expiry·감사 기록과 기존 rule/Hybrid 동작도 묶어서 확인했다.

최신 관련 **Windows538건 통과·4건 제외, Linux540건 통과·2건 제외**다. 제외는 기존 POSIX FIFO/키 권한의 Windows2건과 JSONL 전용 page2건이다. [묶음 결과·원래7실패·소스 지문](infrastructure-results/extra-caller-sdk-retry-20261119.json), [최신 systemd54조건 회귀](infrastructure-results/extra-caller-sdk-retry-20261119-systemd.json). systemd 시험의 provider는 별도 stub이며 새 SDK fault20건과 합산하지 않는다. OS별 같은 사례도 합산하지 않는다.

```sh
python -m pytest tests/test_caller_sdk_retry.py tests/test_verified_sdk_retry_boundary.py tests/test_openai_incomplete_retry.py tests/test_hybrid_analyzer.py tests/test_analysis_caller_boundary.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-paging
```

## 남은 범위

새 guard를 적용한 SDK 경로는 서버 분석의 OpenAIAnalyzer다. EvidenceReviewAgent는 기존의 SDK retries0과 live verified context 정책을 유지하며, 임의의 새 provider나 외부 plugin client를 자동으로 sandbox한 것은 아니다. 새 adapter는 이 호출 권한 계약을 따로 연결해야 한다.

초기 인증 dependency의 I/O admission, 별도 장기 `/evaluation/run`의 호출 범위는 후속이다. OIDC online revocation·실사용자 SSO, 독립 witness/WORM·전체 최신성·다중 호스트·전원 단절·연기한8시간 soak는 미완료다. 모델 prompt/판정·평가 원본/정답/예측·F1·오탐/미탐을 바꾸거나 재평가하지 않았다.
