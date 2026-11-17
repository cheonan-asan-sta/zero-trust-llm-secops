# LLM 응답 실패 진단과 후속 개선 — 2026-11-17

이 문서는 626b500 이후, 11월17일 오후7시까지 진행하는 로컬 후속 작업의 기록이다. 이전 [검증 근거 연결 결과](llm-verified-session-evidence-20261117.md)를 대체하거나 실패 사례를 삭제하지 않는다. 원래 성능 목표·평가 라벨·모집단을 유지한다.

## 응답 형식 실패를 구분하는 이유

이전 최종12개 시나리오 평가에서는 정상 `mfa_not_required`의 첫 반복이 SDK ValidationError로 실패했다. 정상 실패도 보수적으로 FP에 포함하여 검증 근거 사용 시 F1은 첫 반복92.31%, 두 번째100%였다. 원본 응답 상태와 사용량을 받기 전에 SDK 파서가 실패했으므로, 그 오류의 정확한 원인을 소급 확정할 수 없다.

새 공통 어댑터 `app/analyzers/structured_response.py`는 SDK 공개 `responses.with_raw_response.parse` 경로를 사용한다. 같은 요청의 응답 상태·incomplete 사유·토큰 사용량·거절 여부만 먼저 추출하고, 그다음 기존 SDK의 엄격한 schema 파서를 실행한다. 추가 요청·재시도·출력 schema 완화는 하지 않는다.

| 구분 | 동작 |
| --- | --- |
| incomplete / failed / cancelled / queued / in_progress | 분석 성공으로 반환하지 않음 |
| max_output_tokens / content_filter | 허용된 사유 코드만 기록 |
| 모델 거절 | 거절 문구 없이 고정 코드만 기록 |
| completed지만 schema 오류 | `structured_output_invalid`; 확인 가능한 사용량 보존 |
| 구조화 결과 없음 | `structured_output_missing` |
| 인증·권한·요청 제한 HTTP 오류 | SDK 예외 유형을 유지해 평가 중단 정책 적용 |

진단에는 프롬프트·응답 원문·토큰·헤더·요청 ID·오류 입력값을 저장하지 않는다. 동시 요청별 지역 변수로 분리한다. OpenAI 어댑터와 기존 평가/ASGI smoke 스크립트가 같은 경로를 사용하며, hybrid의 기존 규칙 탐지와 사람 검토 fallback을 유지한다. 실제 서비스 API의 성공 감사 기록에 실패 결과를 섞지 않는다.

## 검증 진행 기록

- 새 SDK MockTransport 시험을 포함한 집중 회귀81건 통과. 실제 SDK schema 변환·JSON 파싱을 실행하며 외부 API는 호출하지 않았다.
- 프로젝트 전체 테스트를 Windows에서 잘못 시작한 실행은 범위가 다른 실패가 섞여 중단했다. 이 실행을 전체 통과로 보고하지 않는다. 기존 LLM·인증·제로트러스트 회귀442건에 새 진단 시험15건을 추가하여 Windows457건·Linux457건이 모두 통과했다(기존 deprecation 경고 Windows3/Linux2건).
- 동결한12개 시나리오 × 두 입력 조건 × 두 반복, 실제 API48회를 완료했다. 검증 근거 연결은 두 반복 모두 TP6·FP0·FN0·TN6, F1 100%였다. 근거 없는 입력은 각각 TP2·FP1·FN4·TN5(F1 44.44%), TP1·FP1·FN5·TN5(F1 25%)였다. 오류/미실행/사용량 미확인0건이며 기존 탐지 손실·새 오탐도 없었다. 이12개 개발 시나리오의 관측 결과이며 독립 인수 성능이 아니다. 이전 형식 실패의 원인이나 개선의 인과효과가 확정된 것도 아니다.

## 비용과 미완료 범위

이번 오후 후속 작업의 추가 API 예산 상한은 합계5달러다. 개별 실행은 재시도0·순차 호출·요청 수/예약액 상한을 둔다. 계획과 비용 기록은 `runtime/llm/continuation-20261117/budget.json`에 보관한다. AWS 배포나 원격 push·CI·병합은 수행하지 않는다.

실제 기업 IdP 연결, 과거36건에 없던 승인/MFA 근거 소급 생성, 독립 성능 인수 완료는 이 변경으로 달성되지 않는다. 로컬 수집기 서명은 실제 사람의 MFA 수행을 독립적으로 증명하지 않는다.

실제 API 비용 추정은 이번48회 **$0.22193475**, 사용량 미확인0건이다. 공급자 청구서가 확정 비용의 기준이다. [실측·행별 결과·동결 소스 지문](infrastructure-results/llm-response-diagnostics-20261117.json), [Windows JUnit](infrastructure-results/llm-response-diagnostics-windows-20261117.xml), [Linux JUnit](infrastructure-results/llm-response-diagnostics-linux-20261117.xml)을 함께 보관한다. 두 OS의 시험은 동일 사례 반복이므로 합산해 독립 사례 수로 보고하지 않는다.
