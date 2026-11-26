# 감사 I/O 대기·요청 취소와 실행 슬롯 유지

2026-11-19 · extra · 오전08:00까지 진행하는 로컬 개발의 후속 기록. 유료 API/AWS/push/CI/병합은 하지 않았다.

## 재현한 문제와 변경

감사 무결성 조회가 async 분석 함수 안에서 동기 실행되어 느린 디스크 조회가 event loop를 막았다. 또한 단순 `asyncio.to_thread`는 요청을 취소해도 이미 시작한 스레드를 중단하지 않는다. 취소 직후 분석 슬롯을 반환하면 이전 I/O가 끝나기 전에 새 요청이 진입할 수 있다. 변경 전 세 회귀 사례는 모두 실패했다.

`settled_io`로 디스크 작업을 별도 스레드에서 실행하고, 반복 취소가 들어와도 시작한 작업의 완료·실패를 확인한 뒤 취소를 전달한다. 분석 슬롯은 그동안 유지된다. SQLite 저장·검토와 연합 감사 shard 등록에도 적용했다. 취소는 이미 커밋된 감사 행을 되돌린다는 뜻이 아니다. 커밋된 행은 보존하고 요청에는 취소를 전달한다.

연합 감사의 등록 중 취소는 정상적인 빈 shard를 남길 수 있다. 처음 등록한 파일만 생성하며, 이미 등록된 파일의 삭제를 새 빈 파일로 복구하지 않는다. 다음 정상 저장은 같은 shard에 가능하다. 기존 삭제·변조 거부와 전체 체인 검증은 유지했다.

## 검증 결과

- 신규 집중 시험 6건 통과. 변경 전 세 실패를 포함하며, 실제 SQLite 쓰기 트랜잭션 도중 반복 취소와 별도 writer의 후속 저장을 확인했다.
- ASGI 요청 8개에 슬롯2개를 적용했다. 무결성 조회2개가 대기하는 동안 나머지6개는429, 추가 요청도429였다. 두 요청을 취소해도 작업 완료 전 슬롯은 반환되지 않았다. 그동안 liveness200, 디스크 조회2회 유지, 모델 호출0회였다. 해제 후 재요청은200이며 감사1행을 저장했다.
- Windows 관련 회귀: **142건 통과·1건 제외**(전체143건). Linux 관련 회귀: **205건 통과**. 공통 사례가 있으므로 두 OS 수를 독립 사례 수로 합산하지 않는다.
- Linux 범위에는 API·호출자 권한·실제 HTTP worker 종료/재기동·감사 이관 시험도 포함한다. 이 단계에서 새 native systemd 인수 전체를 재실행하지 않았다. 이전41조건 결과는 이전 변경 시점의 기록으로 남긴다.

[기계 판독 요약·XML/소스 SHA-256](infrastructure-results/extra-async-audit-io-20261119.json).

```sh
python -m pytest tests/test_async_audit_io.py tests/test_audit_cancellation.py tests/test_audit.py tests/test_federated_audit.py tests/test_sqlite_audit.py tests/test_audit_preflight.py tests/test_native_analysis_http.py tests/test_shared_native_analysis.py -q
```

## 범위와 남은 작업

이번 동시 취소 시험은 HTTPX ASGI transport의 요청 task 취소이며 실제 TCP 연결 단절을 재현한 시험은 아니다. 인증·source 근거 수집/재검증 등 다른 동기 경로까지 모두 비동기화한 것은 아니다. 디스크 자체가 영구 정지하면 해당 슬롯도 대기한다. 강제 thread 중단이나 감사 성공 응답은 하지 않는다. 용량 한도는 프로세스별이며 여러 worker의 전역 요청 제한을 증명하지 않는다.

다음은 source 근거 수집 전 진입 제한과 동기 검증의 event loop 영향, 감사 조회 비용/페이지 처리 및 복원 checkpoint 보관이다. 실제 호스트 재부팅·전원 단절·다중 호스트·원격 WORM과 연기한8시간 시험은 미완료다.

평가 원본·정답·예측을 바꾸지 않았고 새 LLM 성능 평가는 없다. 과거 합성 개발360건의 F1 93.41%·목표 미달 상태와 이번 I/O 안정성 시험은 별개다.
