# 새 F1 자료의 입력 검증과 검토지 준비

`scripts.prepare_f1_intake`는 **raw event 자료의 검토 준비 도구**다.
검출기/LLM을 실행하거나 운영 신호를 접수하는 API가 아니다. 데이터 수신·정규화·분할·검토 기록과
실제 출처/발급자 신뢰·사람의 독립성·최종 F1 평가를 구분한다.

```mermaid
flowchart LR
    A[관측·라벨·출처 별도 파일] --> B[외부 manifest 지문]
    B --> C[보안 필드 명시·정답 혼입 거부]
    C --> D[식별자·계열·순서·패턴 중복 점검]
    D --> E[빈 검토지·구조 보고서]
    E --> F[사람의 대조·불일치 합의·새 동결]
```

## 입력과 해석

입력 폴더는 아래4파일만 둔다. 파일/폴더 symlink, 파일별 크기 초과, 해시 변경과 중복 JSON 키를 거부한다.
사례 최대5,000·총 이벤트50,000·사례당1,000이벤트의 작은 검토 묶음용이다.

| 파일 | 내용 | 검출기 입력과의 관계 |
|---|---|---|
| `observations.jsonl` | `case_id`, `tenant_id`, `session_id`, 시간순 `events` | 관측만. `ground_truth`는 null이어도 거부 |
| `labels.jsonl` | 같은 case ID·split·family·normal/threat/unknown·기대 규칙·근거 event ID·이유·라벨 출처 주장 | 별도 정답/분할 메타데이터. 관측 객체 안에 넣지 않음 |
| `origin.json` | 출처 종류·생성자 주장·원본 위치·사용 조건·수집 방식·증분/스냅샷 주장·변환 내역 | 선언된 provenance이며 실제 조직 출처를 증명하지 않음 |
| `manifest.json` | 형식/분모/검토 전 단계·위3파일 SHA-256 | 이 파일의 SHA-256을 별도로 보관 |

원본이 아닌 식별자는 정답 이름에서 만들지 않고 opaque ID를 사용한다.
각 이벤트에는 신원/기기/네트워크/자원/인증/행동의 보안 필드를 명시해야 한다.
예를 들어 `user.active`, `device.managed/security_posture`, 인증 결과/MFA/실패 횟수,
자원 민감도/요구 역할, 다운로드 양 등을 누락했다고 정상 기본값으로 채우지 않는다.
정확한 명시 필드는 [코드의 MATERIAL_FIELDS](../scripts/prepare_f1_intake.py)를 따른다.
`SecurityEvent` 객체를 변환한다면 정답을 제거하는 `analysis_payload()`를 사용한다.

이미 원본에 명시된 unknown이나 nullable 역할은 별도 수로 보고한다.
이 도구가 보안 기본값을 채우지 않았다는 것과 원본 수집자가 값을 만들어 넣지 않았다는 것은 다르다.
출처·변환·실제 관측 의미는 사람이 대조해야 한다. 필드가 존재한다는 이유로 신뢰할 수 있는 IdP/EDR 정보가 되지 않는다.
특히 raw 스냅샷을 신규 이벤트/바이트 증분으로 바꾸지 않는다. 서명 검증·등록부/업무 승인 검증과
온라인 도착 시각/현재 권한 확인을 이 도구가 대신하지 않는다.

## 구조 점검

개발/보정/최종 후보 사이의 session·tenant 내 주체/기기·계열·선언 보안 순서 투영 중복을 센다.
마지막 투영은 ID/절대 시각/원문/서명 없는 승인 주장을 제외한 관측 순서이며,
같은 틀의 ID/시각 변형을 새 독립 자료로 착각하지 않기 위한 점검이다.
앞 단계의 마지막 관측보다 다음 단계 첫 관측이 뒤에 있는지도 확인한다.
이 조건을 모두 만족해도 모든 종류의 정보 누수나 독립성이 증명된 것은 아니다.

같은 순서에 반대 라벨·같은 이벤트 ID에 다른 내용·세션 내 주체/기기 변경·미상 정답·
혼합 라벨 계열을 보고한다. 해당 사례를 삭제하거나 정답을 자동 수정하지 않는다.
영역/규칙별 양성 계열·정상 계열 지지도 별도로 보여주며, 정해 둔 지원 수를 채웠다는 것만으로
통계적 충분성이나 실제 운영 비율을 보장하지 않는다.

unknown **정답**은 정상으로 합치지 않고 재판정 대상으로 남긴다. 이 단계는 성능 지표를 계산하지 않는다.
이후 라벨이 있는 평가에서 발생하는 모델의 unknown/오류/timeout을 분모에서 빼는 절차와 혼동하지 않는다.
그 처리 계약은 후보 고정 전에 정해야 한다.

## 실행 가능한6사례 형식 예시

[intake-example](../infra/f1-lab/intake-example/)은 실제 조직 자료가 아닌 직접 작성한 형식 예시다.
입력/라벨을 바꾸지 않고 새 출력 폴더를 사용한다.

```powershell
.venv\Scripts\python.exe -m scripts.prepare_f1_intake prepare --bundle infra/f1-lab/intake-example --expected-sha256 e4532017c9663dbf71bdc3e36cf47f257186dcd2d17a74eec128e6fc8f2efbdf --directory runtime/f1/my-intake-review
```

출력은 `intake-report.json`, `contract.json`, 빈 `reviews.jsonl`이다. 원문 관측/라벨 파일을 복사하지 않는다.
생성 명령의 `review_contract_sha256`을 별도로 보관한다.
입력 manifest 지문은 원본 묶음을, review contract 지문은 사례/근거 범위와 구조 보고서를 묶는다.

```powershell
.venv\Scripts\python.exe -m scripts.prepare_f1_intake assess --bundle infra/f1-lab/intake-example --expected-sha256 <review_contract_sha256> --directory runtime/f1/my-intake-review
```

빈 검토지의 실제 결과는 reviewed0/pending6·exit2였다.
형식 예시는 세 분할의 구조 점검을 통과했지만 최종 평가의 영역별 계열 지원도 충분하지 않다.
회사 출처·발급자 attestation·독립 검토·최종 평가 준비와 목표 달성은 모두 false다.

## 사람이 작성할 검토 기록

각 `reviews.jsonl` 행의 case ID를 유지하고 다음을 작성한다.

| 필드 | 작성 내용 |
|---|---|
| `reviewer_subject` | 실제 검토자 식별자. 생성자의 자기 검토를 피함 |
| `review_label` | normal / threat / unknown. 부족한 근거는 unknown과 이유로 남김 |
| `evidence_event_ids` | **해당 사례** 관측에서 확인한 근거. 다른 사례 ID를 가져오지 않음 |
| `rationale` | 최소10자의 구체적인 이유·부족한 관측·원본 대조 내용 |
| `reviewed_at` | 실제 검토 시각과 timezone. 미래/naive 시각을 쓰지 않음 |

검토 기록이 모두 채워지면 팀 합의 준비 상태를 보여준다. 이름을 입력한 것만으로
그 사람이 실제로 검토했거나 구현자와 독립적인지 증명되지 않는다.
그래서 `independent_review_verified`, `final_evaluation_ready`, `goal_qualified`는 계속 false다.
기존 라벨과의 불일치/새 라벨 제안은 별도로 집계하며 원본을 고치지 않는다.
라벨 변경·출처 확인·분할 수정·최종 동결은 사람이 근거를 확인한 다음 새 버전으로 결정한다.

## 실제 반례 실행

기존 고정96세션/330이벤트를 raw 형식으로 옮기고 변형 번호0/1/2를 단순히 세 분할에 배정한
**의도적인 부적합 분할 제어군**도 실행했다. 결과는 사례96건을 모두 보존한 채
분할 중복·시간 역전·반대 라벨의 동일 순서1그룹을 검출했고 검토96건은 pending이었다.
서명 업무 맥락이 없는 raw 관측과 변형 분할만으로 독립 최종 평가를 만들 수 없다는 예시다.
이 자료를 새 독립 데이터나 목표 달성 근거로 사용하지 않는다.

실제 원자료는 `runtime/f1/extra-intake-demo-v10-20261112`,
최종 형식 예시 검토는 `runtime/f1/extra-intake-example-v10-20261112-02`에 있다.
정확한 실행/시험/소스 지문은 [v10 공개 결과](infrastructure-results/extra-intake-v10-20261112.json)를 따른다.
