# 목표 수치까지의 현재 개선 상태

**v122 실제 검증·정리 완료(2026-11-17):** [원본 PCAP 321만 기록·초기 로그 66/66 진단 연결·Docker 정리](extra-vpn-packet-data-review.md). 헤더 특징은 정상65/위협1에서 같아 후보 미채택·탐지 지표 v117 유지. 오래된 프로젝트 이미지10·관련 캐시38(2.715GB) 삭제, 현 시험/최신 역할 image·volume14·타 프로젝트 컨테이너 보존·재사용 확인. 전체 목표 active.

**v121 개발·수집 진행(2026-11-17):** [예측기 미승인 초기 frame 진단·캡처 품질](extra-vpn-frame-diagnostic.md). Linux 964건. VPN native 4,159행에서 initial 중복 0, 통계에서 kernel drop 최대 22,396 발견. 시각/완전성 가정으로 예측기에 넣지 않음·지표 v117 유지. 현재 검증 뒤 프로젝트 Docker 정리 요청 대기(삭제 0)·목표 active.

**v120 개발·수집 진행:** [PCAP CRC/SHA·원문 일치 검증과 공유 journal 공백](extra-packet-member-verification.md). Linux 929건 통과·실제 원본 수집/적합/성능 재평가는 미완료. 공유 FN 4의 사건 전 60초 journal 0행, 뒤늦은 echo는 판정에 소급하지 않음. 확정 탐지 지표 v117 유지·목표 active.

**v119 개발·수집 진행:** [고정 원본 수집기·초기 프레임 추출](extra-packet-source-acquisition.md). Linux 908건 통과. 실제 원본 다운로드는 별도 실행 중이며 checksum/실제 로그 연결/적합/성능 재평가는 미완료. 탐지 수치는 v117 유지·목표 active·유료 호출/CI/병합 보류.

**v118 추가 조사·성능 유지:** [연결 이력 3후보 제외·공개 패킷 형식 확인](extra-vpn-lifecycle-and-packet-review.md). 학습 자료의 오탐/미탐 감소 모두 0이라 채택하지 않았다. PCAP 일부는 확인했으나 전체 checksum/사건 당시 연결 미검증으로 학습·채점에 미사용. 확정 성능과 마지막 Linux 855건은 v117·전체 목표 active.

2026-11-16 · 목표 active · 무료 로컬 · 목표 전 push·새 CI·병합·유료 호출 보류

최신 [v117 AppArmor 현재 상태 알림](extra-apparmor-status-review.md): 공유 감사 **FP 3→0·TP 2/FN 4 유지·F1 36.36%→50%**. 별도 Wilson/Wardbeck FP도 각각 1→0이며 FN 2씩은 남는다. 원래 1,681,815행 유지·전체 새 FP/기존 TP 손실 0·Linux 855건 통과다. 인증·웹 감사 관측 100%와 VPN F1 80%는 유지했다. 현재 기록의 미확인 호출자를 인증 완료로 바꾸지 않았고, 경보를 낮춰도 검토를 유지한다.

아래는 현재 R/S/F 종류별 수치다. 원래 6개 보안 영역의 독립 인수를 로그 종류로 대체하지 않는다.

| 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 인증 | 32 | 0 | 0 | 100.0000% | 100.0000% | 100.0000% | 0.0000% | 0.0000% |
| 공유 감사 | 2 | 0 | 4 | 100.0000% | 33.3333% | 50.0000% | 0.0000% | 66.6667% |
| 웹 감사 | 47 | 0 | 0 | 100.0000% | 100.0000% | 100.0000% | 0.0000% | 0.0000% |
| VPN | 84 | 42 | 0 | 66.6667% | 100.0000% | 80.0000% | 0.2286% | 0.0000% |

공유 감사는 TP 2/FP 0/FN 4로 여전히 미달이다. 현재 양성 6행에서는 재현율 95%를 위해 FN 0이 필요하다. VPN은 TP 84를 유지할 때 FP 42→4 이하가 필요하다. 별도 Wheeler 학습 VPN FN 9·Harrison VPN FP 36과 원래 6영역 새 독립 인수도 남는다. 과거 자료에 없는 신원·실행·기기/권한은 미확인으로 유지한다.

최근 F1 개선은 규칙·경량 분류기·근거 연결의 탐지 결과다. **LLM 자체의 새 품질 향상을 측정한 것이 아니며 실제 LLM 호출 0**이다. [v116 후보 제외·LLM 지표 구분](extra-residual-candidate-review.md)에서 과거 합성 8건 시험의 한계와 별도 LLM 평가 항목을 확인할 수 있다. v116 주소/DNS 후보의 새 오탐 29행과 지지 부족 서비스 간격 후보는 채택하지 않았다.

직전 [v115 journal 실행 관측](extra-journal-service-review.md)은 Santos의 같은 사건 시작/종료 2행을 회수했다. [v114 VPN 제어](extra-vpn-control-review.md)는 VPN FP 48→42·F1 80%, [v113 실제 정상 audit 학습](extra-native-audit-normal-review.md)은 웹 감사 FP 15→0·F1 100%로 개선했다. v112 Wilson 웹 감사 FN 3→0, v111 공유 FP 24→3, v110 Wheeler 학습 VPN FN 28→9도 보존했다.

v115에서 한 번 발생한 시간 의존 fixture 오류는 이번에 재현되지 않았지만 원인은 미확정이다. 원래 6영역의 새 독립 인수·장기 soak도 미완료다. 전체 완료 시각은 추가 근거 확보와 실제 검증 결과에 달려 있어 확정하지 않는다.

[최신 구현·검증·남은 문제](extra-apparmor-status-review.md) · [시험·재현](apparmor-status-test-guide.md) · [결과 JSON](infrastructure-results/extra-apparmor-status-v117-20261116.json)
