# 세션·근거 검토 API의 최초 수집 진입 제한

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 변경 이유

native 분석 이후 남아 있던 `/analysis/verified-session`, `/analysis/evidence-review` 두 경로의 최초 source 수집을 보강했다. 기존에는 분석 슬롯을 얻기 전에 동기 수집했다. 포화 상태에도 source 조회가 실행되고, 느린 조회가 event loop를 막았다. 대기 전 수집한 근거와 실제 모델 호출 사이에 source가 철회되거나 serving 저장소가 교체될 수도 있었다. 성공 응답은 후속 재검증이 막았지만, 늦게 확인하는 구조와 불필요한 provider 진입은 남아 있었다.

변경 전 두 API의 포화·수집 취소·수집 중 저장소 교체·대기 중 source 철회 **8개 회귀가 모두 실패**했다.

## 새 처리 순서

인증·요청 형식 검증 이후 공통 분석 슬롯을 얻는다. 최초 수집은 `settled_io`에서 수행하고, 이미 얻은 슬롯 안에서 기존 분석·감사 저장·전달 전 재검증을 수행한다. 내부 함수를 분리해 같은 슬롯을 두 번 얻지 않는다. 새 비활성화 설정이나 메모리 fallback은 추가하지 않았다.

수집기가 사용할 운영 저장소와 필요한 실행 캡처 저장소를 처음에 고정한다. 수집 전후·각 재검증에서 serving 객체의 동일성을 확인한다. 최초 수집을 기다리는 동안 운영 저장소가 바뀌는 경우도 route에서 확인한다. 근거 검토 agent의 서버 이력 도구도 고정한 운영 저장소를 읽고 전후에 현재 serving 저장소와 대조한다. 다른 저장소의 이력을 근거에 섞지 않는다.

포화된 요청은 source/모델을 호출하지 않고429/Retry-After를 받는다. source 조회가 진행 중인 요청의 반복 취소는 조회 완료·실패까지 슬롯을 유지한다. 그동안 liveness는 응답하고, 후속 분석은429로 제한된다. 조회가 끝나면 취소를 전달하며 감사 성공 기록을 만들지 않는다. 정상 재요청은 같은 검증 경로를 거쳐 성공한다.

대기 중 source 철회 또는 최초 수집 중 저장소 교체는 이제 수집 단계의 인증/근거 거부401이다. 기존처럼 모델 이후의 일반502가 되는 것과 구분한다. 모델 도중 바뀐 근거에 대한 기존502와 감사 후 전달 거부는 유지한다.

## 검증

실제 로컬 API 키 인증·서명된 세션·정책 이력·SQLite 감사와 명시적 무료 provider double을 사용했다. 두 API별 포화/취소/저장소 교체/대기 중 철회8개와 실제 서명된 실행 캡처의 두 저장소 교체2개를 확인한다. 취소 시험은 ASGI task 취소이며 TCP 단절 시험은 아니다.

신규10개를 포함해 **Windows 관련223건 통과·15건 제외, Linux 확대285건 통과**. 기존 API·OIDC 만료·호출자 권한 변경·SDK 재시도·실행 근거·동시 tenant/부하/worker 회귀도 함께 확인했다. 최신 XML/소스 지문은 [검증 기록](infrastructure-results/extra-analysis-source-admission-20261119.json)에 기록한다. OS별 공통 사례는 독립 사례로 합산하지 않는다. 이번에는 native systemd 전체 인수를 새로 실행하지 않았으며 이전41조건과 구분한다.

```sh
python -m pytest tests/test_analysis_source_admission.py tests/test_session_analysis_evidence.py tests/test_execution_analysis_evidence.py tests/test_evidence_review_agent.py tests/test_verified_session_oidc.py tests/test_verified_caller_authority.py -q
```

## 한계와 후속

진입 제한은 각 서버 프로세스의 분석 경로에 적용한다. 최초 HTTP 인증과 요청 본문 파싱 자체까지 이 슬롯에 포함하는 것은 아니며, 다중 호스트 전역 제한도 아니다. 이미 시작한 디스크 작업의 강제 중단은 하지 않아 영구 정지한 I/O는 해당 슬롯을 점유할 수 있다. 실제 SSO/MFA·TCP 연결 단절·호스트 재부팅/전원 단절·원격 WORM·연기한8시간 시험은 미완료다.

이번 단계에서 모델·프롬프트·판정 규칙·정답/예측·평가 분모를 변경하지 않았다. 새 F1/오탐·미탐 결과가 아니며 과거 목표 미달 수치는 그대로다. 다음 범위는 감사 조회의 동시 부하·페이지 처리와 복원 checkpoint 보관이다.
