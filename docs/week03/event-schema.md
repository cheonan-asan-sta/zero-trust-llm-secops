# 3주차 보안 이벤트 스키마

## 1. 설계 원칙

`SecurityEvent`는 이벤트 생성기, 규칙 분석기, LLM 분석기가 공통으로 사용하는 입력 계약이다. 공격 여부를 하나의 문자열에 미리 적지 않고, 신원·기기·네트워크·자원·인증·행위를 나눠 관찰 사실로 전달한다.

핵심 불변조건은 다음과 같다.

1. 정의하지 않은 추가 필드는 거부한다.
2. 시각은 시간대를 포함해야 한다.
3. 횟수·시간·전송량은 음수가 될 수 없다.
4. 상태값과 행위는 정해진 허용값만 사용한다.
5. `ground_truth`는 평가 전용이며 `analysis_payload()`에서 제외한다.
6. `event_text`는 명령이 아닌 비신뢰 데이터로 취급한다.

## 2. 구조

```text
SecurityEvent
├─ event_id
├─ timestamp
├─ user
│  ├─ user_id
│  ├─ role
│  ├─ department
│  └─ active
├─ device
│  ├─ device_id
│  ├─ managed
│  └─ security_posture
├─ network
│  ├─ ip
│  ├─ location
│  ├─ access_method
│  └─ location_anomaly
├─ resource
│  ├─ resource_id
│  ├─ resource_type
│  ├─ sensitivity
│  └─ required_role
├─ action
├─ auth_context
│  ├─ mfa
│  ├─ failed_attempts
│  └─ session_age_minutes
├─ behavior
│  ├─ new_device
│  ├─ unusual_time
│  ├─ request_rate
│  ├─ download_volume_mb
│  ├─ distinct_resources_10m
│  ├─ policy_exception_approved
│  └─ event_text
└─ ground_truth  # 평가 전용
```

## 3. 필드 설계 근거

| 구분 | 필드 | 판단에 필요한 이유 |
|---|---|---|
| 신원 | `user.role`, `user.active` | 요구 권한과 사용자 역할의 일치, 계정 활성 상태를 확인한다. |
| 기기 | `managed`, `security_posture` | 기기가 관리 대상인지와 취약·침해 징후를 확인한다. |
| 네트워크 | `access_method`, `location_anomaly` | 원격·VPN 접속과 평소와 다른 위치를 구분한다. |
| 자원 | `sensitivity`, `required_role` | 같은 사용자라도 자원 민감도와 필요 권한에 따라 다른 판단을 낸다. |
| 인증 | `mfa`, `failed_attempts`, `session_age_minutes` | 추가 인증 성공 여부와 반복 실패, 오래된 세션을 평가한다. |
| 행위 | `request_rate`, `download_volume_mb`, `distinct_resources_10m` | 평소보다 빠른 요청, 대용량 전송, 짧은 시간의 다수 자원 접근을 표현한다. |
| 예외 | `policy_exception_approved` | 백업·데이터 이관 같은 정상 예외를 위협으로 단정하는 오탐을 줄인다. |

## 4. 관찰 사실과 평가 라벨 분리

| 계층 | 예시 | 입력 여부 |
|---|---|---|
| 관찰 사실 | `managed=false`, `mfa=failed`, `action=DOWNLOAD` | 분석기 입력에 포함 |
| 파생 특징 | `location_anomaly=true`, `request_rate=high` | 계산 방식과 생성 근거를 기록한 후 포함 |
| 평가 라벨 | `expected_risk`, `expected_action` | 분석기 입력에서 제외 |

`ground_truth`가 모델 입력에 들어가면 위협을 판단한 것이 아니라 정답을 복사한 것이므로 실험 결과를 사용할 수 없다.

## 5. 분석 입력 예시

다음 예시는 ZT-S04의 관찰값만 담은다. 평가 정답은 포함하지 않는다.

```json
{
  "event_id": "evt-zt-s04",
  "timestamp": "2026-09-09T10:00:00+09:00",
  "user": {
    "user_id": "user-017",
    "role": "analyst",
    "department": "research",
    "active": true
  },
  "device": {
    "device_id": "device-managed-01",
    "managed": true,
    "security_posture": "at_risk"
  },
  "network": {
    "ip": "198.51.100.10",
    "location": "region-a",
    "access_method": "remote",
    "location_anomaly": true
  },
  "resource": {
    "resource_id": "internal-service-07",
    "resource_type": "document",
    "sensitivity": "high",
    "required_role": "analyst"
  },
  "action": "REMOTE_ACCESS",
  "auth_context": {
    "mfa": "success",
    "failed_attempts": 0,
    "session_age_minutes": 12
  },
  "behavior": {
    "new_device": true,
    "unusual_time": false,
    "request_rate": "high",
    "download_volume_mb": 2,
    "distinct_resources_10m": 12,
    "policy_exception_approved": false,
    "event_text": null
  }
}
```

## 6. 현재 제약과 4주차 검토 항목

- `ip`는 현재 길이만 제한하므로 IPv4·IPv6 문법 검증은 추가 검토가 필요하다.
- `role`과 `resource_type`은 자유 문자열이므로 조직 정책에 따른 열거형 확장 여부를 검토한다.
- 시나리오 카탈로그의 관찰 신호는 현재 설명용 문자열이다. 자동 평가 규칙으로 사용하려면 별도의 구조화가 필요하다.
