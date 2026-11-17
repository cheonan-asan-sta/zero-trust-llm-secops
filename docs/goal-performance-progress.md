> 2026-11-17 오후 후속: 개발360건 TP163/FP6/FN17/TN174·F1 93.41%·목표 미달 유지. 전체 수치 후보는 악화, 다운로드60건 후보는 개선0으로 모두 런타임 미채택. 선택적 LLM 근거 조회는 실제 실행/MFA 사례의 탐지 유지·inline으로 agent 요청24→12. 불완전 근거의 ALLOW 권고를 서버에서 HOLD로 제한하고 원래 권고 보존; 분류/F1 변경0. 취소 도중 JSONL 감사 경합·검토 중 호출 계정 변경·감사 후 철회 시 전달 거부도 재현/수정. 로그 지시문6종의 실제12회는 판정 유지. 유료1,071회/$4.87398975추정·미확인0·고정47fc624 Linux7,696/skip2·Windows660/skip27 통과·CI/push/병합/AWS 없음. [모든 결과·한계](llm-operation-evidence-20261117.md) 아래는 이전 시점 기록이다.

> 2026-11-17 검증 근거 연결: 서버 정책·서명·현재 세션/회수·승인 소비를 읽는 /analysis/verified-session 구현. 새 로컬12개×2반복에서 FN4→0, 최종 F1 44.44→92.31/100%(검증 오류1 포함). 과거 TP 유지·FN2 잔여, FP0/1 변동. 실제 API266회·확인 사용량 추정$1.152008+미확인1건 예약$0.028229·Win/Linux 각각442건 통과. 실제 기업SSO/독립95%/배포 완료 아님·기본 모드 유지·로컬만 저장. [검증 방법·모든 결과·한계](llm-verified-session-evidence-20261117.md) 아래는 이전 시점 기록이다.

> 2026-11-17 최신 main96a1570 후속: 채택v1 24건 반복2회 FP1→0·FN2 유지·기존 TP 손실/새 FP0, F1 86.96→90.91%. 별도12건 FP0/FN0 유지. v2는 별도12건 TP손실1로 제외. 추가156 API/$0.606518 추정·Windows94/skip8·Linux102 통과. 원격2건·독립95% 목표는 미해결, 기본 모드 유지·이번 변경은 로컬만 보존. [최신 결과와 미해결 근거](llm-auth-remote-review-20261117.md) 아래는 이전 시점의 기록이다.

> 2026-11-17 후속: 사용자 실제 aitest 병합 요청으로 이번 통합의 이전 보류 조건을 해제했다. 목표 미달과 평가 범위는 그대로이며 아래는 이전 작업 당시 기록이다. [최신 통합 승인·검증](aitest-team-llm-merge-20261117.md)

> 2026-11-17 LLM 오탐 후속: 24건 반복2회 모두 FP6→1·FN2 유지·기존 TP 손실/새 FP0, F1 71.43→86.96%. 별도12건 FP2→0·FN0. 추가240 API/$0.801756 추정·기능85건 통과. 개발 평가이며 native/독립95% 목표와 별도·기본 전환/CI/push/병합 보류. [최신 결과·실패 실험](llm-fp-recall-review-20261117.md) 아래는 이전 시점 기록이다.

> 2026-11-17 LLM 실제 개선: 사용자 유료 호출 승인으로 168회 비교·사용량 추정 $0.365284·기능60건 통과. 정책+근거 schema·전체 교차 검토 옵션 구현. 12건 F1 71.43→85.71%지만 24건 FP5→6으로 기본 전환 미승인. 합성 개발 평가이며 native/독립95% 목표는 미완료·CI/push/병합 보류. [전체 실험과 적용 범위](llm-grounded-improvement-20261117.md)

> 2026-11-17 v128: 목표 미달과 재개 조건을 요구사항별 감사했다. 공유 감사/VPN F1 80%·원래6영역 최종 지지0. DEDALE 고정 README만으로 syslog의 정답 대응/과거 AIT 신원/독립6영역을 증명하지 못한다. 같은 필수 근거 공백이 최근3턴 반복돼 추가 근거 전 자동 개선 반복 보류·CI/push/병합 금지 유지. [감사와 재개 조건](extra-target-evidence-gap-v128.md)

> 2026-11-17 v127: 기존 training4곳의 VPN native39파일·journal15,747/text5,868기록을 조사했으나 접속 메시지 복사본0으로 미채택. 모델/정답/예측/새 시험0·공유 감사/VPN F1 80% 유지·목표 전 CI/push/병합 보류. [출처·시각 근거](extra-vpn-native-clock-review.md)

> 2026-11-17 v126: DEDALE syslog125MB·게시 MD5·첫128행의 중첩 압축/형식 검증과 관련 Windows/Linux120건을 완료했다. 새46건·정답/학습/예측0·새 독립 인수0이며 F1 공유 감사/VPN80% 유지. Docker 소유 컨테이너 제거·목표 전 CI/push/병합 보류. [수집 근거](extra-dedale-native-intake.md)

# 목표 수치까지의 현재 개선 상태

2026-11-17 · 최신 검증 v125 · 채택 성능 v124 유지 · 무료 로컬 · 목표 active · 목표 전 push/새 CI/병합/유료 호출 보류

[Native decoder 관측과 첫 서비스 실행 흐름](extra-shared-native-dns-review.md)으로 공유 감사 **TP2→4·FN4→2·FP0 유지·F1 50%→80%**를 확인했다. 원래 1,681,815행을 유지한 9개 묶음 비교에서 추가 FP·기존 TP 손실·추론 오류0이며 관련 Linux1,244건·Ruff+RUF100을 통과했다. 같은 R 학습 사건의 시작/종료 두 행을 회수한 결과다. 새 독립 공격 두 건이나 실제 앱의 과거 수신/운영 배포를 의미하지 않는다.

v124에서 완전한 EVE 요청·응답 근거를 R/F에 추가했지만 모든 판정이 같았다. Fox의 가까운 인코딩 질의는9.046초 전이어서 기존5초 조건을 늘리거나 늦은 counter로 과거 관측을 갱신하지 않았다.

v125 issuer 후보의 pooled24행은 단계별4행뿐이어서 미채택했다. 단계별 최소5와 projection 분리를 보강한 뒤9개 전체 판정이v124와 같음을 확인했다. 초안의 H/W FP감소 각5행은 최신 성능에 포함하지 않는다.

아래는 현재 R/S/F 로그 종류별 수치다. 원래 6개 보안 영역의 별도 독립 인수를 이 표로 대체하지 않는다.

| 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 인증 |32|0|0|100%|100%|100%|0%|0%|
| 공유 감사 |4|0|2|100%|66.6667%|80%|0%|33.3333%|
| 웹 감사 |47|0|0|100%|100%|100%|0%|0%|
| VPN |84|42|0|66.6667%|100%|80%|0.2286%|0%|

공유 감사는 Fox FN2가 남아 재현율/F1/FNR 미달이다. 정상4행도 경보로 바꾸는 넓은 DNS 후보는 제외하고, raw unit 이름을 학습하지 않는 첫 source 실행 흐름과 검증한 같은 호스트 native 관측만 결합했다. 사람·기기/권한·정확한 명령 인과는 계속 미확인이다.

VPN은 FP42→4 이하가 필요하며 TP84/FN0을 보존해야 한다. [v122 실제 초기 패킷 검증](extra-vpn-packet-data-review.md)의 같은 헤더 셀은 정상65/위협1로 혼재해 정상 예외로 채택하지 않았다. 별도 Wheeler training FN9·Harrison VPN FP36, Wilson/Wardbeck 공유 FN2씩도 남는다. 별도 자료는 원래 분모에 더하지 않았다.

원래 credential/device/privilege/lateral/exfiltration/remote 여섯 영역의 새 독립 인수도 미완료다. 현재 소비한 8개 canonical testbed와 알려진 source 지문을 [노출 대장](../infra/f1-lab/observed-source-exposure-v125.json)에 기록했고, 예전 Harrison/Wilson 예약도 이미 소비된 것으로 처리했다. 다섯 분리 축·source/label 심사·정상/위협 지지·최종 후보 동결은 별도로 검증해야 한다. 목표·라벨·모집단을 바꾸지 않았고 local gate/goal_qualified는 false다.

이번 수치는 규칙/경량 모델 baseline과 native 근거 연결의 오프라인 비교다. LLM 자체의 새 품질 향상이나 provider 호출은 없었다. [v116 지표 구분](extra-residual-candidate-review.md)을 유지한다. 장기 soak는 유예하며 과거 시간 의존 fixture 오류의 근본 원인도 미확정이다.

직전 [v117](extra-apparmor-status-review.md)은 공유 FP3→0·F1 50%, [v115](extra-journal-service-review.md)는 Santos TP2 회수, [v114](extra-vpn-control-review.md)는 VPN FP48→42, [v113](extra-native-audit-normal-review.md)은 웹 감사 FP15→0이다. [v122 Docker 정리](extra-vpn-packet-data-review.md)로 오래된 image10·관련 cache38(2.715GB)을 제거하고 현재 image/volume14를 보존했다. 이번 시험도 같은 cached image를 재사용했다.

[최신 구현·증거·남은 문제](extra-vpn-issuer-relation-review.md) · [시험/재현](native-dns-test-guide.md) · [현재 전체 JSON](infrastructure-results/extra-vpn-issuer-v125-20261117.json)
