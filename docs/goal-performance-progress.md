# 목표 수치까지의 현재 개선 상태

2026-11-17 · 최신 v123 · 무료 로컬 · 목표 active · 목표 전 push/새 CI/병합/유료 호출 보류

[Native decoder 관측과 첫 서비스 실행 흐름](extra-shared-native-dns-review.md)으로 공유 감사 **TP2→4·FN4→2·FP0 유지·F1 50%→80%**를 확인했다. 원래 1,681,815행을 유지한 9개 묶음 비교에서 추가 FP·기존 TP 손실·추론 오류0이며 Linux1,109건·Ruff+RUF100을 통과했다. 같은 R 학습 사건의 시작/종료 두 행을 회수한 결과다. 새 독립 공격 두 건이나 실제 앱의 과거 수신/운영 배포를 의미하지 않는다.

아래는 현재 R/S/F 로그 종류별 수치다. 원래 6개 보안 영역의 별도 독립 인수를 이 표로 대체하지 않는다.

| 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 인증 |32|0|0|100%|100%|100%|0%|0%|
| 공유 감사 |4|0|2|100%|66.6667%|80%|0%|33.3333%|
| 웹 감사 |47|0|0|100%|100%|100%|0%|0%|
| VPN |84|42|0|66.6667%|100%|80%|0.2286%|0%|

공유 감사는 Fox FN2가 남아 재현율/F1/FNR 미달이다. 정상4행도 경보로 바꾸는 넓은 DNS 후보는 제외하고, raw unit 이름을 학습하지 않는 첫 source 실행 흐름과 검증한 같은 호스트 native 관측만 결합했다. 사람·기기/권한·정확한 명령 인과는 계속 미확인이다.

VPN은 FP42→4 이하가 필요하며 TP84/FN0을 보존해야 한다. [v122 실제 초기 패킷 검증](extra-vpn-packet-data-review.md)의 같은 헤더 셀은 정상65/위협1로 혼재해 정상 예외로 채택하지 않았다. 별도 Wheeler training FN9·Harrison VPN FP36, Wilson/Wardbeck 공유 FN2씩도 남는다. 별도 자료는 원래 분모에 더하지 않았다.

원래 credential/device/privilege/lateral/exfiltration/remote 여섯 영역의 새 독립 인수도 미완료다. 현재 소비한 8개 canonical testbed와 알려진 source 지문을 [노출 대장](../infra/f1-lab/observed-source-exposure-v123.json)에 기록했고, 예전 Harrison/Wilson 예약도 이미 소비된 것으로 처리했다. 다섯 분리 축·source/label 심사·정상/위협 지지·최종 후보 동결은 별도로 검증해야 한다. 목표·라벨·모집단을 바꾸지 않았고 local gate/goal_qualified는 false다.

이번 수치는 규칙/경량 모델 baseline과 native 근거 연결의 오프라인 비교다. LLM 자체의 새 품질 향상이나 provider 호출은 없었다. [v116 지표 구분](extra-residual-candidate-review.md)을 유지한다. 장기 soak는 유예하며 과거 시간 의존 fixture 오류의 근본 원인도 미확정이다.

직전 [v117](extra-apparmor-status-review.md)은 공유 FP3→0·F1 50%, [v115](extra-journal-service-review.md)는 Santos TP2 회수, [v114](extra-vpn-control-review.md)는 VPN FP48→42, [v113](extra-native-audit-normal-review.md)은 웹 감사 FP15→0이다. [v122 Docker 정리](extra-vpn-packet-data-review.md)로 오래된 image10·관련 cache38(2.715GB)을 제거하고 현재 image/volume14를 보존했다. 이번 시험도 같은 cached image를 재사용했다.

[최신 구현·증거·남은 문제](extra-shared-native-dns-review.md) · [시험/재현](native-dns-test-guide.md) · [현재 전체 JSON](infrastructure-results/extra-native-dns-v123-20261117.json)
