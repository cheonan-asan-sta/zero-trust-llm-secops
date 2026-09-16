# 10주차: 리스크 스코어링·안전 조건·정책 예외 보완

## 계획 목표

자동 대응 제한 조건, 예외 처리, 위험 점수 일관성을 보완해 LLM 결과를 그대로 실행하지 않는 안전 계층을 완성한다.

## 구현 결과

- 위험 점수에 비해 낮은 위험 단계가 반환되면 보수적으로 상향한다.
- 신뢰도 0.5 미만, 고위험·심각 위험, 비활성 계정, 침해 기기, 역할 불일치는 사람 검토로 전환한다.
- `ALLOW`가 위험 맥락과 충돌하면 `HOLD_FOR_REVIEW`로 변경한다.
- 정책 예외에 승인자, 사유, 유효기간, 사용자·역할·자원·행위·최대 다운로드 범위를 포함했다.
- 만료되거나 사건 범위를 벗어난 예외는 이벤트 입력 단계에서 거부한다.
- 다운로드가 아닌 행위의 전송량, 실패 횟수 없는 MFA 실패, 잘못된 원격 접근 방식 등 교차 필드 오류를 차단한다.
- 적용된 예외와 안전 통제를 정책 결과에 감사 정보로 남긴다.

## 주요 안전 통제

- `simulation-only`
- `action-allowlist`
- `low-confidence-hold`
- `risk-score-consistency`
- `high-risk-human-review`
- `disruptive-action-human-review`
- `scoped-exception-validated`

## 코드·테스트 근거

- 교차 필드·예외 검증: `app/models.py`
- 안전 보정: `app/services/policy.py`
- 조건 평가: `app/services/scenario_evaluator.py`
- 검증: `tests/test_policy.py`, `tests/test_week04.py`, `tests/test_scenarios.py`

## 완료 조건

- [x] 위험 점수와 위험 단계의 하향 불일치를 방지함
- [x] 정책 예외의 기간과 범위를 검증함
- [x] 파괴적 권고 조치를 사람 검토로 제한함
- [x] 잘못된 보안 이벤트 조합을 입력 단계에서 거부함
- [x] 정책 통제 적용 내역을 응답에 포함함
