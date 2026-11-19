# Witness 영수증 용량 소진의 상태·경보 보완

2026-11-20 · `extra`. 새 작업 선행 거부 f5d1a27, 경보 보완 b7d69c9. 오전08:00 지속 목표는 진행 중이다. 최대4096개·서명·외부 pin·정상 주기 유예·과거 정답/예측은 그대로 유지했다.

기존 코드는 확인한 마지막 영수증이 이미4096개 한계여도 새 pending을 먼저 기록하고 signer가 다음4097번째 영수증을 거부했다. 그러면 소진 상태가 pending으로 가려지고 처리할 수 없는 작업이 남았다. 이제 검증한 마지막 head가 가득 찼고 기존 pending이 없으면 새 작업을 기록하기 전에 거부한다. 이미 마지막 영수증이 서명된 뒤 응답만 유실된 pending은 그대로 재시도해 원래 서명/시각/bytes를 회수한다. 마지막 영수증의 재서명·보관 삭제·새 기준 자동 채택은 없다.

이전 버전에서 생긴 pending을 자동 삭제하거나 승인하지 않는다. 그 기록 또는 새 미수집 행 때문에 state가 pending/unobserved여도 남은 영수증이0이면 공개 action_required를 즉시1로 표시한다. 건강 상태0·실제 pending/미수집 수·원래 시각을 유지한다. 이미 가득 찬 signer는 정상 수집 주기 유예로 회복할 수 없으므로 경보 유예와 구분했다. 실제 경보 규칙 자체와 탐지 임계값을 완화하지 않았다.

| 확인 | 결과 |
|---|---|
| 첫 용량 재현 | 새 시도 후 state가 capacity_exhausted 대신 pending이 되는2건 실패 보존 |
| 선행 거부/마지막 응답 유실 복구 묶음 | Windows61통과/1제외·Linux62통과 |
| 이전 pending/미수집의 경보 유예 재현 | 정상 주기 안에서 action_required가0이 되는2건 실패 보존 |
| 최종 관련 묶음 | Windows63통과/1제외·Linux64통과. 앞 묶음과 중복 합산하지 않음 |
| 경보 규칙 | b77eceb의20개 제어 시나리오 통과. 소진한 pending/unobserved는 critical, 정상 주기 유예와 구분 |
| 실제 경보 흐름 재확인 | 같은 b77eceb에서22조건·장애4회 발생/해제 통과. 실제 소진 장애를 주입한 결과가 아니며 위 규칙 시험/진행 중4096개 시험과 구분 |
| 기본값 전체 용량 | 별도 고정af311242 소스에서 실제4096개 서명을 생성하는 Linux 시험 진행 중. 단위 시험 통과로 실제 한계 완료를 대신하지 않음 |
| 소스 검사 | ruff 최종0건. 보관한 실행기 원문은 .py.txt로 구분 |

단위 시험은 빠른 경계 검증을 위해 MAX_RECEIPTS를2로 줄인 합성 fixture를 사용했다. 실제4096개 시험은 그 상수를 바꾸지 않고 별도로 진행한다. 고정af311242는 f5d1a27의 pending 선행 거부를 포함하고 이후 b7d69c9 경보 보완은 포함하지 않는다. 실제 시험의 최종 raw/소스 불변/비공개 키 삭제 여부는 종료 후 따로 기록한다. 현재 완료한 것으로 표시하지 않는다.

중간 시험에서 public pending이 bool인데 None으로 비교한 단언을 바로잡았고, 잘못 입력한 시험 파일명으로0건 수집한 실행도 보존했다. 실제 최초 결함 재현은 pending state 자체의 차이였으며, 수정된 최종 단언은 pending:false를 확인한다. 오류 로그를 숨기거나0건 실행을 성공으로 계산하지 않는다.

운영상 기본60초 수집이면4096개는 약2.84일 분량이다. 이미 bootstrap 영수증 등이 있으면 남은 시간은 더 짧다. 현재는 소진 시 안전하게 거부하고 경보하는 모델이며, 무기한 운영이나 자동 epoch 교체를 구현했다고 주장하지 않는다. 운영자는 소진 전에 이력을 보존하고 별도 신뢰 기준을 검토해야 한다. 삭제/새 키 채택/외부 pin 교체는 이 작업에서 자동 실행하지 않는다. 실제 독립 호스트·외부SSO·원격WORM·운영 배포·8시간 soak도 별도 남은 항목이다.

원본·소스 커밋·SHA256·진행 중 실제 경계 시험의 실행기: [검증 명세](infrastructure-results/extra-witness-capacity-20261120.json). 구현은 app/services/audit_witness_observer.py의 _prepare와 scripts/f1_lab/witness_observer_status.py의 render_report다. 관련 pytest 파일은 test_audit_witness_observer.py, test_audit_witness_operations.py, test_witness_monitor_cadence.py, test_audit_witness_observer_process.py, test_witness_clock_boundary.py다.

기존 작성형 개발360건 LLM F1 93.41%·목표 미달은 변하지 않았다. 이번은 저장·경보의 기능 검증이며 독립 탐지 평가 표본이 아니다. 비용·AWS·Docker·업로드·CI·병합은 없다. 중간8d2 전체 회귀·6033 난수 시드 순서 시험·d45 시간 간격 시험은 각각 다른 소스의 결과이므로 최신 전체 통과로 합치지 않는다.
