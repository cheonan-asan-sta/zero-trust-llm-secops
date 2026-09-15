# 3주차 요구사항과 추적표

## 1. 범위

이 요구사항은 3주차에 확정한 위협 시나리오 카탈로그와 보안 이벤트 계약만 다룬다. 실제 계정 차단, 클라우드 인프라, 성능 목표 달성은 범위 밖이다.

## 2. 기능 요구사항

| ID | 요구사항 | 완료 기준 | 구현·증빙 |
|---|---|---|---|
| FR-03-01 | 위협 시나리오 5종을 식별할 수 있어야 한다. | `ZT-S01`~`ZT-S05`가 중복 없이 존재 | `app/scenarios.py`, `test_catalog_contains_five_attack_mapped_threat_scenarios` |
| FR-03-02 | 각 위협 시나리오는 ATT&CK 기법을 하나 이상 가져야 한다. | 기법 ID·이름·공식 URL을 검증 | `AttackTechnique`, `ScenarioSummary.threat_requires_attack_mapping` |
| FR-03-03 | 시나리오는 관찰 신호와 정상 예외를 제공해야 한다. | 위협 시나리오별 각각 1개 이상 | `observable_signals`, `normal_exceptions` |
| FR-03-04 | 이벤트는 신원·기기·네트워크·자원·인증·행위 맥락을 표현해야 한다. | `SecurityEvent` 검증 통과 | `app/models.py`, `tests/test_models.py` |
| FR-03-05 | 평가 라벨은 분석 입력에서 제외되어야 한다. | `analysis_payload()`에 `ground_truth` 없음 | `test_ground_truth_is_removed_from_analysis_payload` |
| FR-03-06 | 시나리오 상세 기준을 API로 조회할 수 있어야 한다. | 정상 ID는 200, 알 수 없는 ID는 404 | `GET /scenarios/{scenario_id}`, `tests/test_api.py` |
| FR-03-07 | 시나리오 기준과 합성 이벤트의 평가 라벨이 일치해야 한다. | 모든 합성 이벤트의 risk·action 일치 | `test_event_ground_truth_is_derived_from_scenario_catalog` |

## 3. 안전·품질 요구사항

| ID | 요구사항 | 검증 방법 |
|---|---|---|
| NFR-03-01 | 실제 기업 로그와 개인정보를 사용하지 않는다. | 예시 ID·문서용 IP 대역·가상 지역만 사용 |
| NFR-03-02 | 입력 모델은 알 수 없는 추가 필드를 거부한다. | `ConfigDict(extra="forbid")` |
| NFR-03-03 | 모든 이벤트 시각은 시간대를 포함한다. | `timestamp_must_have_timezone` 검증 |
| NFR-03-04 | 위협 시나리오의 ATT&CK 매핑은 공식 도메인을 참조한다. | `AttackTechnique.reference_url` 패턴 검증 |
| NFR-03-05 | 대응은 실제 시스템 변경이 아닌 미리보기로 제한한다. | `PolicyDecision.mode = simulation` |
| NFR-03-06 | 시나리오 ID는 중복될 수 없다. | 모듈 로드 시 `SCENARIO_INDEX` 크기 확인 |

## 4. 보류 요구사항

| ID | 보류 사유 | 검토 예정 |
|---|---|---|
| TBD-01 | ATT&CK 매핑은 사건 분류용이며 직접 탐지 규칙이 아님 | 시나리오 리뷰 후 현장 신호 보강 |
| TBD-02 | 예외 승인의 승인자·적용범위·만료시간이 아직 없음 | 4주차 정책 필드 설계 |
| TBD-03 | 이벤트 필드 간 의미 검증이 제한적임 | 4주차 교차 필드 규칙 정의 |
| TBD-04 | 관찰 신호가 자동 실행 가능한 조건식이 아님 | 4주차 평가자 구조 검토 |
