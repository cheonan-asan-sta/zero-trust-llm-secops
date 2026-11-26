# Native 실행 근거 조회 전 진입 제한

2026-11-19 · extra · 무료 로컬 개발. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 변경 이유와 동작

`/analysis/native-service`는 기존에 근거를 조회한 뒤 분석 슬롯을 얻었다. 따라서 포화 상태에도 서명·공유 DB·현재 정책 조회가 실행됐고, 동기 조회가 event loop를 막았다. 변경 전 포화·느린 근거 조회 두 회귀 사례에서 이 동작을 재현했다.

이제 인증·요청 형식 검증 후 슬롯을 얻고, 그 안에서 실행 참조 조회→현재 근거 확인→모델→감사 저장→전달 직전 재확인을 수행한다. 별도 내부 분석 함수로 분리해 동일 슬롯을 두 번 얻지 않는다. 근거 조회와 route의 재검증은 `settled_io`를 사용한다. 요청 취소 후에도 이미 시작한 조회가 끝나기 전에는 슬롯을 반환하지 않는다. 포화된 요청은 근거를 수집하거나 모델을 호출하지 않고429/Retry-After를 반환한다.

현재 serving registry/운영 저장소의 동일성은 source 재검증 전후 모두 확인한다. 재검증 중 registry가 교체되는 사례에서 불필요한 모델 호출1회를 재현했고, 이제 모델 이전에 거부한다. 이전에도 성공 응답은 거부됐지만, 이번에는 오래된 저장소를 근거로 모델을 호출하는 것까지 막는다.

공통 분석 슬롯은 시작할 때 잡은 semaphore를 끝날 때 반환한다. 대기 중 설정 참조가 바뀌어도 새 semaphore의 여유 슬롯을 잘못 늘리지 않는다.

## 호환성과 범위

대기 중 철회된 참조는 조회 시점에 없는 참조이므로404다. 이전에는 대기 전에 resolve했던 context의 무효화로502였다. 어느 경우에도 모델 호출·감사 성공 기록은 없다. 추론 도중 철회·변조와 감사 후 전달 전 철회는 기존 거부 동작을 유지한다.

진입 제한은 이 native route의 근거 수집부터 적용한다. 기존 verified-session/evidence-review route의 최초 수집까지 옮긴 것은 아니다. OpenAI SDK analyzer/agent 내부의 동기 source callback도 아직 별도 보강 대상이다. 프로세스별 제한이며 다중 호스트 전역 제한은 아니다. ASGI task 취소 검증과 실제 TCP 연결 단절은 구분한다.

최신 Windows 집중 **59건**, Linux 확대 **208건** 통과. 겹치는 사례를 합산하지 않는다. 초기 진입 제한 보강 뒤 확대 시험은 Windows128/skip16·Linux207건 통과했으며, 이후 source 검증 중 저장소 교체를 막는 보강을 더하고 최신 시험을 수행했다. 변경 전 두 실패와 저장소 교체 시 불필요한 모델 호출1회는 각각 별도 XML로 남겼다.

최신 코드로 실제 systemd/ptrace→공유 참조→실제 독립 HTTP worker 강제 종료/재기동→TCP HTTP→SQLite 감사 백업/복원 **41조건을 재실행해 통과**했다. 실제 worker 두 개는 각각-9 종료·소유 process wait 완료이며, source 권한/실행 이력과 원래 감사 DB 불변을 확인했다. 원래 근거 만료 전 철회 차단도 유지했다. 테스트 소유 unit·private 상태·임시 의존성은 정리했다.

원본 XML 지문·소스 지문은 [검증 기록](infrastructure-results/extra-native-admission-20261119.json), 실제 인수는 [systemd 결과](infrastructure-results/extra-native-admission-20261119-systemd.json)에 기록한다. 모델은 무료 로컬 stub이며 F1/오탐·미탐을 새로 측정하거나 개선했다고 주장하지 않는다. 평가 원본·정답·이전 결과는 유지한다.

```sh
python -m pytest tests/test_native_analysis_http.py tests/test_async_audit_io.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --worker-restart
```

두 번째는 로컬 root/systemd 환경의 실제 실행·HTTP worker 종료/재기동·감사 백업/복원 인수다. provider는 stub이고 실행 단위 및 임시 상태는 시험 소유 대상만 정리한다. 실사용 SSO·호스트 재부팅·전원 단절·원격 WORM 및 연기한8시간 시험은 완료로 처리하지 않는다.
