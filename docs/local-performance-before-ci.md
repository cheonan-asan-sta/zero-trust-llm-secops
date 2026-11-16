> 2026-11-17 v126: DEDALE syslog125MB·게시 MD5·첫128행의 중첩 압축/형식 검증과 관련 Windows/Linux120건을 완료했다. 새46건·정답/학습/예측0·새 독립 인수0이며 F1 공유 감사/VPN80% 유지. Docker 소유 컨테이너 제거·목표 전 CI/push/병합 보류. [수집 근거](extra-dedale-native-intake.md)

> 2026-11-17 v125: 단계별 최소지지5를 분리하고 관련 Linux1,244건 검증. issuer 초안의 pooled24=각단계4여서 미채택, H/W 각5행 감소를 최종 수치로 쓰지 않는다. 공유 감사·VPN F1은80% 유지, 목표 미달·CI/push/병합 보류. [최신 근거](extra-vpn-issuer-relation-review.md)

> 2026-11-17 v124: native DNS 요청·응답 근거와 Linux1,190건 검증. 추가 TP/FP/TP손실0, 공유 감사·VPN F1은80%로 동일하다. 전체 목표 미달, push/새 CI/병합/유료/AWS 보류. [최신 검토](extra-shared-dns-transaction-review.md)

# 성능 개선·로컬 평가를 CI보다 먼저 수행

**v123 로컬 개선(2026-11-17):** [native 관측·첫 source 서비스 흐름](extra-shared-native-dns-review.md). 공유 TP2→4·FN4→2·FP0 유지·F1 50→80%, 추가FP/기존TP손실0·원래1,681,815행·Linux1109건. R의 같은 학습 사건 2행이며 native-capture 오프라인 profile·사람/명령/실제 앱 수신은 미확인. VPN F1 80% 유지·원래6영역 독립 인수 미완료·소비된Harrison/Wilson 예약 재사용 금지·전체목표 active.

**v122 실제 검증·정리 완료(2026-11-17):** [원본 PCAP 321만 기록·초기 로그 66/66 진단 연결·Docker 정리](extra-vpn-packet-data-review.md). 헤더 특징은 정상65/위협1에서 같아 후보 미채택·탐지 지표 v117 유지. 오래된 프로젝트 이미지10·관련 캐시38(2.715GB) 삭제, 현 시험/최신 역할 image·volume14·타 프로젝트 컨테이너 보존·재사용 확인. 전체 목표 active.

**v121 개발·수집 진행(2026-11-17):** [예측기 미승인 초기 frame 진단·캡처 품질](extra-vpn-frame-diagnostic.md). Linux 964건. VPN native 4,159행에서 initial 중복 0, 통계에서 kernel drop 최대 22,396 발견. 시각/완전성 가정으로 예측기에 넣지 않음·지표 v117 유지. 현재 검증 뒤 프로젝트 Docker 정리 요청 대기(삭제 0)·목표 active.

**v120 개발·수집 진행:** [PCAP CRC/SHA·원문 일치 검증과 공유 journal 공백](extra-packet-member-verification.md). Linux 929건 통과·실제 원본 수집/적합/성능 재평가는 미완료. 공유 FN 4의 사건 전 60초 journal 0행, 뒤늦은 echo는 판정에 소급하지 않음. 확정 탐지 지표 v117 유지·목표 active.

**v119 개발·수집 진행:** [고정 원본 수집기·초기 프레임 추출](extra-packet-source-acquisition.md). Linux 908건 통과. 실제 원본 다운로드는 별도 실행 중이며 checksum/실제 로그 연결/적합/성능 재평가는 미완료. 탐지 수치는 v117 유지·목표 active·유료 호출/CI/병합 보류.

**v118 추가 조사·성능 유지:** [연결 이력 3후보 제외·공개 패킷 형식 확인](extra-vpn-lifecycle-and-packet-review.md). 학습 자료의 오탐/미탐 감소 모두 0이라 채택하지 않았다. PCAP 일부는 확인했으나 전체 checksum/사건 당시 연결 미검증으로 학습·채점에 미사용. 확정 성능과 마지막 Linux 855건은 v117·전체 목표 active.

**최신 v117:** [현재 AppArmor 상태 알림의 공유 감사 오탐 개선](extra-apparmor-status-review.md). 공유 FP 3→0·TP 2/FN 4 유지·F1 50%, 별도 Wilson/Wardbeck FP 각 1→0·FN 2씩 유지. 원래 1,681,815행·새 FP/기존 TP 손실 0·Linux 855건. 미확인 호출자와 검토 필요 유지·LLM 새 품질 평가 없음·전체 목표 active·push/새 CI/병합/유료 호출 보류. 아래 기록은 해당 버전 당시 결과다.

**v116 검토·미채택:** [주소/DNS 오탐 실패·작업 간격 지지 부족·LLM 지표 구분](extra-residual-candidate-review.md). 새 탐지 후보는 적용하지 않았고 확정 성능은 v115다. 실제 LLM 품질을 새로 개선/측정한 것으로 보고하지 않는다. 목표 active·유료 호출/CI/병합 보류.

**최신 v115:** [앞선 journal 실행 관측](extra-journal-service-review.md). 공유 감사 TP 0→2·FN 6→4·FP 3 유지·F1 36.36%. 같은 학습 사건의 audit 2행, 사람/현재 invocation/유출 성공 검증은 아님. 원래 1,681,815행·새 FP/기존 TP 손실 0·Linux 820건. 인증·웹 감사 100%·VPN F1 80% 유지·전체 목표 active·push/새 CI/병합 보류.

**직전 v114:** [VPN 제어 메시지 관측](extra-vpn-control-review.md). VPN FP 48→42·TP 84/FN 0 유지·F1 80%, 별도 Harrison/Shaw/Wheeler FP 각 2건 감소. 원래 1,681,815행 유지·새 FP/기존 TP 손실 0·Linux 776건. 인증·웹 감사 관측 100% 유지. 공유 감사·VPN·원래 6영역 독립 목표는 미완료·목표 active·push/새 CI/병합 보류.

**직전 v113:** [실제 정상 SSH·sudo 감사 학습](extra-native-audit-normal-review.md). 웹 감사 FP 15→0·TP 47/FN 0 유지·F1 100%, 별도 Wilson/Wardbeck FP 각 10→0. 원래 1,681,815행·새 FP/기존 TP 손실 0·Linux 732건. 추가 실제 정상 169행은 학습 전용으로 분모에 미합산. 공유 감사·VPN·원래 6영역 독립 목표는 미완료이며 목표 active·push/새 CI/병합 보류.

**직전 v112:** [웹 방화벽 요청·netfilter 동시 관측](extra-web-firewall-review.md). 별도 학습 Wilson 웹 감사 FN3→0·TP19→22·FP10 유지·F1 81.48%. 원래1,681,815행 유지·전체 새FP/TP손실0·Linux693건. 사람/부모 프로세스 인과 증명 아님·전체 목표 active·push/새CI/병합 보류.

**직전 v111:** [공유 감사 실행 관측 기반 오탐 개선](extra-apparmor-causal-review.md). FP24→3·별도 Wilson/Wardbeck 각8→1, 전체 새FP/TP손실0·Linux644건. 공유 감사 FN6/F1 0%는 그대로다. VPN/인증/웹 감사 기존 성능 유지·전체 목표 active·push/새CI/병합 보류.

**직전 v110:** [VPN 공격 근거의 인과적 유지](extra-vpn-attack-evidence.md). 별도 학습 Wheeler FN28→9·TP28→47·FP38 유지. 기존1,681,815행 판정 유지·전체 새FP/TP손실0·Linux606건. 학습 결과이며 독립 목표는 미달/미완료. 목표 active·push/새CI/병합 보류.

**직전 v109:** [VPN 추가 연결 문맥](extra-vpn-protocol-refinement.md). 기존1,681,815행에서 VPN FP208→48·F1 44.68%→77.78%, 기존TP84/FN0 유지·새FP/TP손실0. Linux579건. 이미지 내 프로젝트 자료 차단 후9개 묶음 예측 지문 동일 확인. 인증 개선 유지, 공유/웹 감사·VPN·독립 목표는 아직 미달. 목표 active·push/새CI/병합 보류.

**직전 v108:** [웹 저장 경로의 root 계정 조회 문맥](extra-webpath-identity-read.md). Linux489건·기존1,681,815행 판정 유지. 별도8,908행 Wilson 인증FN1→0·새FP/TP손실0. 관측5개자료 인증 P/R/F1 각각100%이며 새 독립 평가가 아니다. 웹 감사 F1 86.24%·공유 감사·VPN 및 원래6영역 독립 목표는 미달/미인수다. 목표 active·push/새CI/병합 보류.

**직전 v107:** [개발 학습 확장·전이 미탐 회수](extra-audit-training-extension.md). Linux475건·기존1,681,815행 판정 유지. 별도8,908행에서 웹 감사 미탐2·인증 미탐1 회수, 새FP/TP손실0. 추가8,325행은 학습용으로 시험 분모에 합산하지 않았다. R/S/F 인증100%·웹 감사 F1 86.24% 유지지만 Wilson 인증FN1·공유/웹 감사·VPN·원래6영역 독립 목표는 남아 있다. 목표 active·push/새CI/병합 보류.

**직전 v106 웹 감사 개선:** [프로세스 역할·로그인 흐름](extra-audit-intent-context.md). 기존1,681,815행에서 FP6건 감소·새FP/기존TP손실0. 웹 감사 FP21→15·F1 81.74%→86.24%, 인증100% 유지. Linux372건 통과. 모델은R/S/Wilson 학습·Fox/Wardbeck 비학습 보정이며 새 독립 인수가 아니다. 전체 목표 active·push/새CI/병합 보류.

**직전 v105 실제 인증 미탐 개선:** [명령/PAM 원문 문맥](extra-sensitive-auth-context.md). 기존1,681,815행에서 미탐3건 회수·새FP/TP손실0. 관측 인증32양성/1,082정상에서 P/R/F1 각각100%, FPR/FNR0%, R/S/F 각 자료도 충족. Linux348건 통과. 공유/웹 감사·VPN 및 원래6영역 독립 목표는 미달/미인수이며 목표 active·push/새CI/병합 보류.

**직전 v104 근거 적용 판정:** [공유 감사·인증·VPN 판정 개선](extra-evidence-risk-refinement.md). Linux526건·실제 systemd18조건 통과. 로컬 정책 제어6시나리오에서 불필요 경보2→0·명시적 폐기 미탐3→0. 점수는 fixture이며 독립 공격 탐지 F1에 합산하지 않는다. v103 대비 기존1,681,815행 판정 동일·새FP/TP손실0·목표 미달. push·새CI·병합 보류.

**직전 v103 로컬 수집·연결:** [실행 주체·PAM 호출 신원·VPN 기기 결속](extra-live-evidence-ingress.md). Linux 집중485건·실제 systemd/PAM/OIDC11조건 통과. v102 대비 기존1,681,815행 판정 동일·새FP/기존TP손실0. 과거 로그의 미상 근거를 소급 생성하지 않아 탐지 목표는 계속 미달이다. 기관 SSO/MDM·실제 VPN hook·새 독립 평가는 별도이며 push·새CI·병합은 보류한다.

**직전 v102 로컬 개선:** [같은 소스 audit 사건 순서 보강](extra-ordered-audit-review.md). 기존1,681,815행에서 웹 감사 FN1→0·F1 80.70%→81.74%, 새FP/기존TP손실0. Linux 묶음339건 통과. 공유 감사·인증·VPN은 유지됐으며 목표 미달·새 독립 평가 아님. 추가 push·CI·병합 없이 로컬 후보로 보존한다.


2026-11-16 사용자 요청으로 추가 게시 순서를 바꿨다. **실제 탐지 성능 개선 → 로컬 평가의 목표 충족 확인 → CI → aitest 병합** 순서를 따른다. PR88은 기존 head의17개 CI가 이미 성공했지만 draft·미병합으로 보존한다. 이 변경 브랜치는 로컬 전용이며 성능 미달 상태에서 새 push/CI/병합을 시작하지 않는다. monitored의 로컬 원인 조사는 계속할 수 있다.

## 로컬 확인 도구

`scripts.check_local_metric_gate`는 SHA로 고정한 evaluator 집계에서 종류별 P/R/F1≥95%, FPR/FNR≤5%를 검사한다. 반올림한 표시값 대신 유리수로 비교하며, 모든 모집단의 필수 지표가 충족되어야0으로 종료한다. 미달은1, 잘못된 집계/지문은2다. 큰 집단의 평균으로 작은 미달 집단을 가리지 않는다. 정답/행을 바꾸거나 미상·추론 실패를 분모에서 빼는 입력을 통과시키지 않는다. 정상/위협의 필요한 분모가0이면 해당 지표는 미측정이며 실패한다.

```text
python -m scripts.check_local_metric_gate --report <counts.json> --sha256 <별도 SHA256> --track observed_log_kinds
```

관측 로그8종류와 원래 credential/device/privilege/lateral/exfiltration/remote6영역은 별도 track이다. 이 계산기는 집계의 출처·라벨 정확성·후보 코드 결속·출처/세션/패턴 분리·독립 검토를 증명하지 않는다. 모든 숫자가 충족돼도 `goal_qualified=false`를 유지하며 CI/병합 명령을 실행하지 않는다. 해당 인수 근거를 별도로 확인해야 한다.

## 실제로 적용한 결과

v85의 이미 관측한 R/S/F 집계 원본 지문 `23f96b5ba2fc3112852b37a52e4a69f33e7bdaa8fce2ca4a2dcc63541d6b0627`를 확인해 새 로컬 게이트에 입력했다. **게이트 실패: 공유 감사·웹 감사·인증·VPN.** CPU·DNS·웹 access/error의 점 지표가 높다고 전체 목표 달성으로 처리하지 않는다. 정상 웹 error는4행뿐이며 새 독립 성능도 아니다.

| 종류 | 현재 TP/FP/FN | 기존 정탐을 유지할 때 목표를 충족하는 예시 | 필요한 변화 |
|---|---:|---:|---|
| 공유 감사 | 0/24/6 | 6/0/0 | 미탐6 회수·오탐24 제거 |
| 웹 감사 | 46/21/1 | 46/2/1 | 오탐 최소19 제거 |
| 인증 | 29/0/3 | 31/0/1 | 오탐0 유지·미탐 최소2 회수 |
| VPN | 84/208/0 | 84/4/0 | 정탐84 유지·오탐 최소204 제거 |

위 예시는 달성 결과가 아니다. 현재 고정 점수의 임계값 변경만으로 해당 목표를 충족하는 경계는 없다는 기존 진단을 유지한다. 공유 감사의 주체·명령 근거, 인증의 결속된 호출 신원, VPN의 검증된 기기/권한 근거가 없는 과거 행을 임의로 채워 넣지 않는다.

기존 분석에서 정상 공유 정책 교체에는 명시적인 변경 생략 근거가 없고, 인증의 남은3행은 PID/계정 결속이 부족한 root PAM 세션 열기다. VPN의 관측 벡터 충돌·근거 부족도 [기존 진단](extra-vpn-precision-audit.md)에 남아 있다. 새로운 관측을 모아 후보를 개선하되, 같은 자료의 재평가·합성 제어 시험을 최종 독립 성능으로 바꾸지 않는다.

로컬 게이트/기존 점수 경계 관련52개 검사를 통과했다. 이 수는 탐지 성능이 아니다. 모델·임계값·기존 예측·라벨은 변경하지 않았으며 개선 실적을 새로 주장하지 않는다. AWS/유료 API0·장기 연속 시험 유예를 유지했다. [실행 순서 계약](../infra/f1-lab/local-before-ci-protocol.json).

[실제 로컬 게이트 결과·집계 지문](infrastructure-results/extra-local-before-ci-v101-20261116.json).
