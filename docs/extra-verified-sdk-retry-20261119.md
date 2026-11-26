# 검증된 실행·세션 근거의 SDK 자동 재시도 경계

2026-11-19 · extra · 실제 SDK/로컬 HTTP mock 검증. 외부 API/AWS/push/CI/병합은 하지 않았다.

## 발견한 경계

기존 OpenAI adapter는 명시적 불완전 응답 재시도를 끈 기본 설정에서 SDK transport 재시도2회를 허용했다. 이 재시도는 adapter 바깥의 HTTP 계층에서 실행되어 시도 사이에 source·권한을 재검증하지 않는다. 첫500 응답 또는 read timeout 직후 source를 철회하는 두 사례에서, SDK가 새 요청을 보내 정상 응답을 반환하는 동작을 변경 전에 재현했다. route의 마지막 확인이 성공 전달을 막더라도 이 추가 요청 자체는 이미 전송된 후다.

검증된 `VerifiedSessionContext`가 연결된 요청은 이제 호출별 SDK option `max_retries=0`을 사용한다. 원래 cached client의 설정이나 HTTP connection pool은 변경/종료하지 않는다. 따라서 검증된 요청과 일반 요청이 동시에 실행돼도 서로의 retry 설정을 바꾸지 않는다.

## 유지하는 재시도와 실패 동작

검증된 호출의 HTTP 오류·연결 오류·timeout은 즉시 기존 오류 경로로 전달한다. 불확실한 요청을 자동 재전송하거나 성공한 분석으로 간주하지 않는다. 과거 요청이 실제 제공자에서 처리·과금됐는지는 이 로컬 시험으로 증명할 수 없다.

사용자가 설정하는 불완전 structured response의 명시적 최대1회 재시도는 유지한다. 이 경로는 adapter loop에 있으므로 매번 source·expiry·event binding을 다시 확인하고, 철회·만료되면 다음 요청을 막는다. evidence agent는 기존부터 SDK retry0을 요구하며 그 제한도 유지한다. 서버 검증 근거가 없는 일반 분석은 기존 SDK 정책을 유지한다.

## 시험

408·409·429·500·502·read timeout·connection error의7종은 검증된 호출에서 HTTP 요청1회·source 확인1회 뒤 실패해야 한다. 추가 정상 응답을 준비해도 소비하지 않는다. 일반 분석은 첫500 뒤 두 번째 요청으로 성공하는 기존 동작을 유지한다. 같은 cached adapter의 검증/일반 동시 요청에서도 각각1회/2회이며 원래 SDK 설정2회와 열린 connection pool을 보존한다.

변경 전500/timeout 두 회귀는 실패했다. 새9개 사례를 포함해 **Windows 관련229건·Linux 확대231건 통과**. OS별 겹치는 사례를 합산하지 않는다. 명시적 불완전 응답 재시도와 취소·source 철회·기존 native HTTP 근거 회귀도 함께 확인했다. 최신 XML/소스 지문은 [검증 기록](infrastructure-results/extra-verified-sdk-retry-20261119.json)에 기록한다. SDK가 실제로 parsing하지만 HTTPX MockTransport가 모든 provider 요청을 로컬에서 처리한다. 실제 계정 키·유료 호출은0이다.

```sh
python -m pytest tests/test_verified_sdk_retry_boundary.py tests/test_openai_incomplete_retry.py tests/test_async_evidence_io.py -q
```

이 단계는 재시도와 권한 재검증 경계의 개선이다. 프롬프트/모델/분류·정답/예측을 변경하지 않았고 새 F1 측정도 없다. 이전 실제 systemd41조건은 이전 SDK I/O 변경 시점의 인수이며 이번 단계에서는 새 native 전체 인수를 주장하지 않는다. 최초 session/agent route 수집의 진입 제한, TCP 단절·호스트/다중 호스트 및8시간 연속 시험은 후속이다.
