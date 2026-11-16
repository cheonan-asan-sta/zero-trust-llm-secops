# 목표 수치까지의 현재 개선 상태

2026-11-16 · 목표 active · 무료 로컬 · 목표 전 push·새 CI·병합 보류

최신 [v114 VPN 제어 관측](extra-vpn-control-review.md): VPN FP 48→42·TP 84/FN 0 유지, F1 77.78%→80.00%. 별도 Harrison/Shaw/Wheeler VPN도 FP 각 2건 감소. 원래 1,681,815행 유지·전체 새 FP/기존 TP 손실 0·Linux 776건 통과다. 이미 관측한 개발/보정 자료의 비교이며 새 독립 평가나 전체 목표 달성은 아니다.

아래는 현재 R/S/F 종류별 수치다. 원래 6개 보안 영역의 독립 인수를 로그 종류로 대체하지 않는다.

| 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 인증 | 32 | 0 | 0 | 100.0000% | 100.0000% | 100.0000% | 0.0000% | 0.0000% |
| 공유 감사 | 0 | 3 | 6 | 0.0000% | 0.0000% | 0.0000% | 0.1276% | 100.0000% |
| 웹 감사 | 47 | 0 | 0 | 100.0000% | 100.0000% | 100.0000% | 0.0000% | 0.0000% |
| VPN | 84 | 42 | 0 | 66.6667% | 100.0000% | 80.0000% | 0.2286% | 0.0000% |

인증·웹 감사는 관측 목표를 유지했다. 공유 감사와 VPN은 미달이다. VPN은 오탐률이 0.23% 미만이어도 위협 표본이 적어 정밀도 66.67%·F1 80%이며 완료로 처리하지 않는다. 공유 감사 TP 0/FN 6도 변화 없다.

현재 양성 수 기준 공유 감사 FN 6→0·FP 3→0, VPN FP 42→4 이하가 필요하다. 별도 Wheeler 학습 VPN FN 9, Harrison 별도 VPN FP 36과 원래 6개 보안 영역의 새 독립 인수도 남는다. 과거 신원·실행·권한 근거가 없는 부분은 확인 불가로 유지한다. 전체 완료 시간은 남은 근거 확보와 실제 회귀 검증에 달려 있다.

직전 [v113 실제 정상 audit 학습](extra-native-audit-normal-review.md)은 웹 감사 FP 15→0·F1 100%, [v112 방화벽 관측](extra-web-firewall-review.md)은 Wilson 웹 감사 FN 3→0, [v111 AppArmor 문맥](extra-apparmor-causal-review.md)은 공유 FP 24→3으로 개선했다. [v109 VPN 문맥](extra-vpn-protocol-refinement.md)의 FP 208→48과 [v110 학습 공격 근거](extra-vpn-attack-evidence.md)의 Wheeler FN 28→9도 보존했다.

[최신 구현·검증·남은 문제](extra-vpn-control-review.md) · [시험·재현 가이드](vpn-control-test-guide.md) · [결과 JSON](infrastructure-results/extra-vpn-control-v114-20261116.json)
