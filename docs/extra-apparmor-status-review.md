# AppArmor 상태 알림의 공유 감사 오탐 개선 — v117

2026-11-16 · 채희주 담당 · 무료 로컬 · 전체 목표 active · 목표 전 push·새 CI·병합 보류

원래 1,681,815행을 유지한 전후 비교에서 R/S/F 공유 감사 **FP 3→0, TP 2/FN 4 유지, F1 36.36%→50%**를 확인했다. 정밀도 40%→100%, 재현율 33.33% 유지, 오탐률 0.1276%→0%, 미탐률 66.67% 유지다. 미탐 목표는 여전히 미달이다. 별도 Wilson/Wardbeck 공유 감사 FP도 각각 1→0이지만 두 자료의 공유 감사 FN 2씩은 남는다. 원래 분모에 합산하지 않는다.

## 무엇을 바꿨나

남은 공유 감사 오탐은 AppArmor의 AVC STATUS/profile_replace 기록이었다. 기존 v111 관측기는 앞서 확인한 같은 프로세스의 parser 명령 또는 현재까지 완성된 사건이 있어야 하므로, 미래 SYSCALL/PROCTITLE을 빌리지 않는 첫 STATUS 행은 후보가 되지 않았다.

[새 관측기](../scripts/f1_lab/apparmor_status_notice.py)는 **현재 행에 실제 있는 상태·작업·UID 보고 여부**만 별도로 분류한다. STATUS/profile_replace, unconfined, parser comm, 유효 PID·절대 경로 문법을 확인하고 오류·거부 mask·요청 mask·미지원 info·민감 파일/위험 payload를 제외한다. 경로의 shell 메타문자도 제외한다. source SHA·바이트 SHA·물리 순서·시각/serial·크기 경계가 맞지 않으면 경보를 낮추지 않는다. ENRICHED의 원래 audit 구간만 의미 해석하며 전체 원문 바이트 지문은 유지한다. 나중의 중복 행이 앞선 결과를 바꾸지 않는다.

학습 특징은 event 종류, 현재 행 한정이라는 범위, 변경/미변경 보고, UID 역할과 **caller_unverified**다. 구체적인 profile 이름·PID·UID 숫자·호스트/IP·절대 날짜를 학습하지 않는다. UID 누락은 uid_missing이며 root로 채우지 않는다. 숫자 UID가 보고돼도 실제 사람 신원을 검증했다는 뜻은 아니다. 현재 학습 자료의 두 셀은 모두 UID 누락이다.

이미 선언된 **R/S/Wilson/Shaw/Wheeler training**으로만 새 head를 적합했다. 변경 보고는 정상 20/위협 0행, 같은 profile 보고는 정상 12/위협 0행이었다. 최소 정상 지지 5·같은 셀의 공격 1행이라도 존재하면 하향 금지를 유지한다. 32행은 서로 독립적인 사람/운영 환경 32개를 의미하지 않는다. Fox/Wardbeck/Harrison은 이번에도 적합에 쓰지 않았지만 이전에 관측한 보정 자료이므로 새 독립 평가라고 부르지 않는다.

새 head는 기존 일반 경보(unchanged/missing_context)를 낮출 수 있으나 **review=True·자동 집행 금지**를 유지한다. 이미 정상인 행, 오류, 독립 위험 사유, journal 위험 경보는 유지한다. 점수 0은 관측된 셀의 검토 분류 표식이며 공격 확률 0이라는 뜻이 아니다. 기본 탐지 경로는 바꾸지 않았고 명시적 apparmor-status 실험 프로필에서만 동작한다. 기존 CA·DB·인증/앱 정책·자동 조치 권한도 변경하지 않았다.

**profile_replace는 실제 정책 변경일 수 있다. STATUS나 parser 이름만으로 승인된 변경·정상 사용자·무해함을 증명하지 않는다.** 학습에서 없던 악성 교체가 같은 셀을 사용할 위험은 남는다. 이번 결과는 관측된 자료의 개발 비교이며 운영 배포나 원래 6영역 독립 인수의 근거로 대체하지 않는다.

## 전후 결과

| R/S/F 종류 | TP | FP 전→후 | FN | 정밀도 전→후 | 재현율 | F1 전→후 |
|---|---:|---:|---:|---:|---:|---:|
| 공유 감사 | 2 | 3→0 | 4 | 40%→100% | 33.3333% | 36.3636%→50% |
| 웹 감사 | 47 | 0→0 | 0 | 100%→100% | 100% | 100%→100% |
| 인증 | 32 | 0→0 | 0 | 100%→100% | 100% | 100%→100% |
| VPN | 84 | 42→42 | 0 | 66.6667%→66.6667% | 100% | 80%→80% |

R/S/F에서 오탐 1행씩을 제거했다. 별도 Wilson/Wardbeck도 각각 1행 감소했다. 전체 9묶음에서 새 FP·기존 TP 손실·추론 오류는 0이었다. 원래 ID·물리 행·정답·목표를 유지했고 별도 자료를 원래 분모에 더하지 않았다. 기존 journal로 회수한 같은 Santos 사건 2행을 유지했으며 새 공격 사건을 찾은 것은 아니다.

## 검증 근거와 남은 문제

Windows 새 경계 조건 35건, Linux 전체 관련 묶음 **855건**·Ruff+RUF100 통과다. 새 시험은 호출자 미확인 유지·미래 자료 비사용·명시적 거부/위험/오류 보존·정상 지지 4/5 경계·공격 veto·소스/시각/serial/중복/원문 변조·위험 경로·ENRICHED·명시적 활성화와 staging 정답 제외를 확인한다. 초기 경계 시험이 shell 메타문자를 가진 경로를 놓치는 점을 발견해 경로 검사를 보완했고 최종 고정 코드로 다시 학습·검증했다. 기능 fixture 통과율을 F1에 더하지 않는다.

예측기는 network none·UID10001·read-only root·capability 제거·CPU 2/2GiB로 실행했다. 이미지의 기존 프로젝트 자료는 차단하고 현재 코드·필요한 원문/metadata·동결된 v115 예측·새 head만 제공했다. **학습 계수는 제공했고 평가 정답/집계는 제공하지 않았다.** 이전 모델은 다시 적합하지 않았다. 예측 봉인·컨테이너 제거 뒤 기존 정답으로 채점했으며 원문/입력/코드/archive 불변과 기능 시험/예측 코드 일치를 확인했다.

과거 v115의 service_registry_window 시간 의존 실패는 이번 855건에서 재현되지 않았지만 원인을 해결한 것으로 보고하지 않는다. 장기 8시간 soak도 보류 상태다.

최근 F1 향상은 규칙·경량 분류기·근거 연결의 탐지 결과이며 **LLM 자체의 새 품질 향상이 아니다. 이번 실제 LLM 호출은 0**이다. LLM의 위험도/대응 추천 정확도·근거 설명·출력 형식·안전성·지연/비용은 별도 평가가 필요하다. [과거 시험의 범위와 LLM 지표 구분](extra-residual-candidate-review.md)을 함께 읽는다.

남은 핵심은 공유 감사 FN 4, VPN FP 42·별도 Wheeler training FN 9와 Harrison VPN FP 36, 원래 credential/device/privilege/lateral/exfiltration/remote 6영역의 새 독립 인수다. 과거에 없는 사람 신원·실행 명령·기기/권한을 만들어 채우거나 정상/위협 라벨을 바꾸지 않는다. 전체 목표는 미달이며 push·새 CI·병합·AWS·유료 호출은 실행하지 않았다.

[혼동행렬·지문 JSON](infrastructure-results/extra-apparmor-status-v117-20261116.json) · [실제 JUnit](infrastructure-results/extra-apparmor-status-v117-20261116.xml) · [시험·재현](apparmor-status-test-guide.md) · [현재 진행표](goal-performance-progress.md)
