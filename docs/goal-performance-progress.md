# 목표 수치까지의 현재 개선 상태

2026-11-16 · 목표 active · 무료 로컬 · 목표 전 push/새CI/병합 보류

최신 [v112 웹 감사 동시 관측](extra-web-firewall-review.md): 별도 **학습 Wilson** 웹 감사 FN3→0·TP19→22·FP10 유지·F1 74.51%→81.48%. 원래1,681,815행은 v111 판정 유지·전체 새FP/기존TP손실0·Linux693건. 새 독립 평가/전체95% 목표 달성은 아니다.

아래는 현재 R/S/F 종류별 수치다. 원래6개 보안 영역의 독립 인수를 로그 종류로 대체하지 않는다.

| 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 인증 | 32 | 0 | 0 | 100.0000% | 100.0000% | 100.0000% | 0.0000% | 0.0000% |
| 공유 감사 | 0 | 3 | 6 | 0.0000% | 0.0000% | 0.0000% | 0.1276% | 100.0000% |
| 웹 감사 | 47 | 15 | 0 | 75.8065% | 100.0000% | 86.2385% | 0.2022% | 0.0000% |
| VPN | 84 | 48 | 0 | 63.6364% | 100.0000% | 77.7778% | 0.2612% | 0.0000% |

직전 [v111 공유 감사 오탐](extra-apparmor-causal-review.md)은 FP24→3, 별도 Wilson/Wardbeck 각8→1로 줄였고 FN6/F1 0%는 그대로다. [v109 VPN 오탐](extra-vpn-protocol-refinement.md)은 FP208→48·F1 77.78%, [v110 학습 Wheeler 미탐](extra-vpn-attack-evidence.md)은 FN28→9·F1 66.67%로 개선했다. 이번에도 유지했다. 별도 Wilson/Wardbeck 인증도 기존 결과를 유지한다.

목표 간격: 공유 감사 FN6→0·FP3→0, 웹 감사 FP15→2 이하, VPN FP48→4 이하가 필요하다. 별도 Wilson 웹 감사 FP10·Wheeler 학습 VPN FN9와 원래6개 보안 영역의 독립 인수가 남는다. 이후 수집된 근거나 설정을 과거 사건에 소급하거나 원본·라벨·분모·목표를 고치지 않는다.

[최신 구현·검증·한계](extra-web-firewall-review.md) · [웹 감사 시험 근거·실행 방법](web-firewall-test-guide.md) · [AppArmor 재현](apparmor-causal-test-guide.md) · [VPN 재현](vpn-protocol-test-guide.md)
