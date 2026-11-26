# LLM 내부 근거 재검증과 이력 조회의 취소 처리

2026-11-19 · extra · 무료 로컬 SDK/통합 검증. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 재현한 문제

이전 native route 보강 이후에도 OpenAI adapter 내부의 최초 호출·불완전 응답 재시도 전, evidence agent의 반복·최종 응답 전 source callback은 동기 실행이었다. agent의 서버 이력 도구도 동기 조회했다. 느린 조회가 event loop를 막아 요청 취소와 다른 작업이 대기하는 문제를 새 시험에서 **5실패/1통과**로 재현했다. 이력 조회 중 철회가 다음 모델 호출을 막는 기존 사례는 변경 전에도 통과했다.

## 변경

`VerifiedSessionContext.revalidate(event)`는 읽기 전용 source callback을 `settled_io`로 끝까지 기다린 뒤 현재 시간으로 이벤트 바인딩·유효기간을 다시 검사한다. 기존 동기 collector/publication API는 유지한다. async adapter/agent와 HTTP 분석의 모델 후·감사 후 확인은 이 경로를 사용한다.

agent 이력 도구도 별도 스레드에서 수행하며 조회 직후 현재 권한을 재검증한다. 모델은 여전히 서버가 고정한 현재 세션의 빈 인자 읽기 도구만 요청할 수 있다. 새로운 도구·경로·URL·쓰기·권한 발급은 추가하지 않았다. 프롬프트·모델·재시도 횟수·출력 예산·분류 규칙·강제 검토 정책도 바꾸지 않았다.

취소/timeout은 이미 시작한 파일·DB 읽기를 즉시 중단한다는 뜻이 아니다. 완료·실패를 확인할 때까지 요청과 분석 슬롯을 유지한 뒤 취소를 전달한다. 따라서 느린 디스크 작업은 설정된 timeout 이후에도 정리 시간이 필요할 수 있다. 디스크가 영구 정지하면 슬롯이 대기하며, 이를 우회해 성공 응답하거나 새 모델 호출을 시작하지 않는다.

## 시험 의미

신규 시험은 실제 OpenAI SDK의 parsing과 HTTPX `MockTransport`를 사용했다. 외부 네트워크나 실제 계정 키를 쓰지 않는다. adapter 최초/재시도 전과 agent 최초/최종 전 검증을 멈추고, event loop가 응답하며 반복 취소에도 작업 완료까지 task가 살아 있는지 확인한다. 취소 후 추가 SDK 요청은0회다.

agent 이력 읽기 중 취소도 완료 전까지 대기하고 다음 SDK 요청을 하지 않는다. 읽는 동안 권한이 철회되면 다음 요청을 거부한다. 실제 분석 슬롯·SQLite 감사를 연결한 추가 두 사례는 source 읽기의 정상 완료/실패 모두 취소 요청의 슬롯을 조기에 반환하지 않고 감사0행을 유지한다. 정상 복구 후 재요청은1회 모델 응답·감사1행이다. 이는 task 취소 시험이며 TCP 연결 단절을 직접 재현하지 않는다.

신규 집중 **8건**, Windows 관련 **225건 통과·15건 제외**, Linux 확대 **285건 통과**. 최신 코드로 실제 systemd/ptrace·공유 참조·독립 HTTP worker 종료/재기동·감사 암호화 백업/복원 **41조건**도 다시 통과했다. 생성한 unit/private 상태/임시 의존성/worker는 정리됐다. source 권한 이력과 원래 감사 DB를 변경하거나 새로운 grant를 발급하지 않았다.

XML/소스 지문은 [검증 기록](infrastructure-results/extra-async-evidence-20261119.json), 실제 인수는 [systemd 결과](infrastructure-results/extra-async-evidence-20261119-systemd.json)에 정리한다. OS별 중복 사례를 합산하지 않는다. 과거 F1/오탐·미탐은 변경하지 않았고 새 모델 성능 평가도 아니다.

```sh
python -m pytest tests/test_async_evidence_io.py tests/test_openai_incomplete_retry.py tests/test_session_analysis_evidence.py tests/test_execution_analysis_evidence.py tests/test_evidence_review_agent.py tests/test_native_analysis_http.py -q
```

## 후속 범위

verified-session/evidence-review route의 최초 근거 수집은 아직 슬롯 이전 동기 경로다. 이 구간의 진입 제한과 event loop 영향을 다음에 보강한다. 실사용 사람 SSO/MFA·다중 호스트 전역 제한·호스트 전원 단절·원격 WORM·연기한8시간 시험은 미완료다. 평가 원본/정답/이전 결과와 기존 서비스 설정은 유지한다.
