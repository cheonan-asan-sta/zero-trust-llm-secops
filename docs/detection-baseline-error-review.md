# 탐지 기준선 오류 분해: 규칙 변경 없음

2026-11-12 · 새 평가가 아니라 11/11 기존 개발/holdout 결과의 읽기 전용 집계다.
원자료 SHA-256·지표·오류 계열·예시는 [공개 JSON](infrastructure-results/week4-baseline-errors-20261112.json)에 연결했다.
Sigma 이벤트 탐지의 합성 가족 변형 평가이며 LLM 정확도·세션 회수 성능·기업 blind 평가가 아니다.

개발360은 TP170/FP50/FN10/TN130, holdout360은 TP90/FP50/FN90/TN130이다.
holdout 정밀도64.29%·재현율50%·F1 56.25%·오탐률27.78%로 목표에 미달한다.
규칙·임계값·라벨을 바꾸지 않았고 목표 달성을 보장하지 않는다.

| holdout 영역 | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| credential | 10 | 10 | 20 | 20 |
| device | 10 | 0 | 20 | 30 |
| exfiltration | 10 | 0 | 20 | 30 |
| lateral | 20 | 20 | 10 | 10 |
| privilege | 20 | 0 | 10 | 30 |
| remote | 20 | 20 | 10 | 10 |

## holdout 오류 계열 전체

| 결과 | 영역 | 계열 | 건수 |
|---|---|---|---:|
| FN | credential | credential-distributed-slow | 10 |
| FN | credential | credential-stolen-success | 10 |
| FN | device | device-managed-compromise | 10 |
| FN | device | device-unmanaged-at-risk | 10 |
| FN | exfiltration | exfiltration-high-sensitivity-export | 10 |
| FN | exfiltration | exfiltration-low-and-slow | 10 |
| FN | lateral | lateral-api-traversal | 10 |
| FN | privilege | privilege-unauthorized-download | 10 |
| FN | remote | remote-misclassified-activity | 10 |
| FP | credential | credential-authorized-drill | 10 |
| FP | lateral | lateral-fleet-deployment | 10 |
| FP | lateral | lateral-incident-response | 10 |
| FP | remote | remote-approved-night-support | 10 |
| FP | remote | remote-approved-vpn-maintenance | 10 |

## 다음 검토와 개선 경계

1. 김택희가 원자료의 case_id·기대 규칙·실제 규칙·관측값을 대조해 라벨 타당성과 관측 공백을 독립 검토한다.
2. 오탐/미탐의 실제 원인은 관측값과 해당 규칙 조건을 읽어 확인한다. 계열 이름만으로 근본 원인을 확정하지 않는다.
3. 소수의 계열에서 파생된 변형 건수와 독립 세션/기업 트래픽 표본 수를 구분한다.
4. 팀이 개선을 시작하기로 결정하면 개발 자료에서 가설·변경·실패 기준을 먼저 고정하고 별도 새 평가 자료로 재검증한다.
   이미 관찰한 holdout을 보면서 임계값만 조정한 결과를 독립 일반화 성능이라고 제출하지 않는다.
5. 이번 집계는 기존 결과를 설명하는 자료이며 사람의 라벨 승인·성능 목표 통과·후속 개선 완료는 아니다.
