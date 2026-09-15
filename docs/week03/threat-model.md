# 3주차 위협 모델

## 1. 목적과 경계

이 문서는 제로 트러스트 접근 요청을 평가할 때 필요한 5종 위협 시나리오를 고정한다. ATT&CK 매핑은 시나리오를 일관된 용어로 분류하기 위한 참고이며, 특정 공격이 실제로 발생했음을 입증하는 탐지 규칙이 아니다.

제로 트러스트는 네트워크 위치나 장비 소유 여부만으로 묵시적 신뢰를 부여하지 않고, 현재의 사용자·기기·자원을 같이 평가하는 관점으로 설계했다.

## 2. 시나리오 요약

| ID | 위협 시나리오 | ATT&CK 전술·기법 | 예상 위험도 | 예상 대응 |
|---|---|---|---|---|
| ZT-S01 | 탈취 계정의 비정상 접근 | Credential Access · [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | CRITICAL | HOLD_FOR_REVIEW |
| ZT-S02 | 관리되지 않은 기기의 원격 접근 | Initial Access · [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/) | MEDIUM | REQUIRE_MFA |
| ZT-S03 | 권한 범위 초과 | Privilege Escalation · [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | HIGH | REDUCE_PRIVILEGE |
| ZT-S04 | 내부 횡단 이동 의심 | Lateral Movement · [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/) | HIGH | HOLD_FOR_REVIEW |
| ZT-S05 | 정책 위반 데이터 접근 | Exfiltration · [T1020 Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) | HIGH | HOLD_FOR_REVIEW |

## 3. 상세 시나리오

### ZT-S01 탈취 계정의 비정상 접근

- 관찰 신호: MFA 실패, 반복된 로그인 실패, 미관리 신규 기기, 비정상 위치, 고민감 자원 접근
- 정상 예외: 출장이나 VPN 출구 변경으로 위치가 달라진 경우
- 판단 근거: 위치 이상 하나가 아니라 인증 실패·신규 기기·민감 자원 접근이 동시에 나타난다.
- 안전 처리: 즉시 계정을 차단했다고 간주하지 않고 사람 검토 대기로 전환한다.

### ZT-S02 관리되지 않은 기기의 원격 접근

- 관찰 신호: 기기 미등록, 보안 상태 미확인, 신규 기기, 원격 접속
- 정상 예외: 아직 등록 전인 신규 지급 장비, 사전 승인된 BYOD
- 판단 근거: 미관리 기기만으로 공격으로 단정하지 않지만, 현재 기기 상태를 입증할 수 없으므로 추가 인증이 필요하다.
- 안전 처리: REQUIRE_MFA를 제안하고 기기 등록 여부를 다시 확인한다.

### ZT-S03 권한 범위 초과

- 관찰 신호: 사용자 역할과 요구 역할의 불일치, ADMIN 행위, 고민감 관리자 자원, 반복 실패
- 정상 예외: 사전 승인된 긴급 권한, 직무 변경 후 IAM 동기화 지연
- 판단 근거: 요청 자원의 요구 역할과 현재 사용자 역할이 다르므로 최소 권한 원칙을 위반한다.
- 안전 처리: REDUCE_PRIVILEGE를 제안하되 실제 권한은 변경하지 않는다.

### ZT-S04 내부 횡단 이동 의심

- 관찰 신호: REMOTE_ACCESS, 10분 내 다수 자원 접근, 높은 요청 빈도, 비정상 위치, 취약한 기기 상태
- 정상 예외: 승인된 배포 자동화, 장애 대응을 위한 운영자의 원격 접근
- 판단 근거: 원격 프로토콜이 실제 운영에서도 사용될 수 있으므로 자원 수·위치·기기 상태와 함께 본다.
- 안전 처리: 정상 운영 예외을 확인할 때까지 HOLD_FOR_REVIEW로 보류한다.

### ZT-S05 정책 위반 데이터 접근

- 관찰 신호: 고민감 자원, DOWNLOAD, 대용량 전송, 비정상 시간대, 미승인 예외
- 정상 예외: 승인된 백업, 사전 검토를 거친 데이터 이관
- 판단 근거: 대용량이라는 이유만으로 위협으로 분류하지 않고, 자원 민감도·시간대·예외 승인을 함께 본다.
- 안전 처리: 실제 전송을 차단했다고 표현하지 않고 HOLD_FOR_REVIEW를 반환한다.

## 4. 위험도와 정답 라벨

- `expected_risk`와 `expected_action`은 현재 실험을 위한 프로젝트 기준이다.
- 해당 라벨은 LLM 입력에 포함하지 않는다.
- ATT&CK 기법과 위험도 라벨 사이에 1:1 자동 변환 규칙은 두지 않는다.
- 정상 예외가 존재하는 사건은 위험 신호가 있어도 사람 검토 또는 추가 인증으로 전환한다.

## 5. 참고자료

- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [MITRE ATT&CK Enterprise Techniques](https://attack.mitre.org/techniques/enterprise/)

참고 기준일: 2026-09-16
