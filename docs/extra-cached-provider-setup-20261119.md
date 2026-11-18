# 서버 공유 provider의 첫 생성과 취소 경계

2026-11-19 · extra · 로컬 무료 시험. 원격 업로드·CI·병합·유료 API·AWS 없음.

## 확인한 문제

일반/배치 분석에서 `get_analyzer()`를 async 경로에서 직접 호출했다. 첫 client 생성이나 secret 조회가 느리면 event loop와 liveness가 지연됐다. Python `lru_cache`는 동시 miss의 중복 실행을 허용하므로 analyzer와 evidence agent 모두 두 첫 요청이 client를 각각 생성할 수도 있었다. 수정 전 일반/배치 liveness2건과 analyzer/agent 생성2건이 모두 실패했다.

## 구현

`single_cached_factory`가 cache 조회와 생성 전체를 같은 thread-safe lock으로 보호한다. 같은 프로세스에서 처음 호출하는 여러 worker가 하나의 생성 결과를 공유한다. 실패는 cache하지 않으며 이후 정상 구성으로 재시도할 수 있다. 기존 `cache_clear`와 `cache_info` 사용은 유지한다. 이것은 프로세스 공유 cache이며 다중 호스트의 singleton이 아니다.

일반/배치는 `_load_analysis_provider`가 공용 analysis slot을 얻고 현재 caller를 확인한 다음 `settled_io(factory)`를 실행한다. 완료/실패 뒤에도 caller를 다시 확인한다. 포화면429/`Retry-After: 1`이며 factory에 들어가지 않는다. 생성 중 취소된 요청은 실제 worker가 끝날 때까지 slot을 유지한다.

일반/배치는 provider 준비 slot을 반환한 뒤 기존 사례별 분석 slot을 다시 얻는다. 기존 분석·감사 preflight/저장/정확한 row proof·최종 caller 경계는 그대로다. 이 두 단계 사이에 권한이 바뀌거나 capacity가 없으면 다시 거부할 수 있다. batch 전체가 분석 slot 하나로 여러 모델 호출을 우회하지 않는다.

검증 세션·native·근거 검토 endpoint는 이미 잡은 analysis slot 안에서 `_load_analysis_provider_in_slot`을 실행한다. 중첩으로 slot을 다시 얻지 않는다. 기존 source proof와 정책 검증, endpoint별503 문구를 유지한다. 생성 실패 상세 문자열을 HTTP 응답에 노출하지 않는다. 중간 회귀에서 기존 검증 세션의503 문구 차이를 확인해 기존 계약을 복구했고 최종 회귀를 재검증했다.

완성된 공유 client의 소유자는 process cache다. 한 caller가 취소돼도 성공한 cache 결과를 버리거나 닫지 않으며, 유효한 다음 caller가 재사용한다. 평가 요청의 client는 별도 request 소유이며 이전 단계의 생성/close 계약을 유지한다. cache clear가 사용 중인 client를 강제로 종료하는 기능을 새로 추가한 것은 아니다. 정상 HTTP 경로의 factory 대기자는 기존 analysis 한도로 제한된다.

## 검증

신규20건: 일반/배치 liveness2, analyzer/agent 동시 첫 생성2, 일반/배치×생성 성공/실패 중 반복 취소4, 생성 성공/실패 뒤 caller 철회4, 포화 시 factory0회2, 두 cache의 생성 오류2종 후 복구4, 검증 세션·근거 검토의 실제 HTTP liveness2다. 취소 후 정상 cache는 추가 생성 없이 재사용하고, 실패한 cache만 새로 만든다. 실패한 요청은 모델/운영 감사 결과를 만들지 않는다.

최신 관련 Windows732건 통과·20건 제외, Linux750건 통과·2건 제외다. 원본 XML/소스 지문은 [검증 결과](infrastructure-results/extra-cached-provider-setup-20261119.json)에 있다. [systemd54조건](infrastructure-results/extra-cached-provider-setup-20261119-systemd.json)은 실제 로컬 systemd/ptrace·HTTP 재시작·백업/복원 회귀이며 provider는 stub다. 새20건 및 OS 간 중복을 합산하지 않는다. SQLite 다중 process 쓰기와 commit 전/후 kill, checkpoint·백업/복원 기존 시험도 이번 묶음에 포함했다.

```sh
python -m pytest tests/test_cached_provider_setup.py tests/test_analysis_caller_boundary.py tests/test_native_analysis_http.py tests/test_verified_caller_authority.py tests/test_session_analysis_evidence.py -q
```

## 한계

멈춘 factory/thread를 강제 종료하지 않고 bounded slot을 유지한다. HTTP 경로 밖에서 getter를 무제한 호출하는 외부 프로그램까지 admission하는 것은 아니다. 실행 중 공유 client의 설정 교체·graceful drain/shutdown은 별도다. 외부 SSO/MFA·원격 secret manager·유료 모델 품질을 검증한 것은 아니다.

판정 prompt·ground truth·평가 원본/결과와 기존 F1·오탐·미탐은 변경하지 않았다. 독립 witness/WORM·다중 호스트·전원 단절·연기한8시간 soak는 남아 있다.
