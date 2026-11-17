> 2026-11-17 검증 근거 연결: 서버 정책·서명·현재 세션/회수·승인 소비를 읽는 /analysis/verified-session 구현. 새 로컬12개×2반복에서 FN4→0, 최종 F1 44.44→92.31/100%(검증 오류1 포함). 과거 TP 유지·FN2 잔여, FP0/1 변동. 실제 API266회·확인 사용량 추정$1.152008+미확인1건 예약$0.028229·Win/Linux 각각442건 통과. 실제 기업SSO/독립95%/배포 완료 아님·기본 모드 유지·로컬만 저장. [검증 방법·모든 결과·한계](llm-verified-session-evidence-20261117.md) 아래는 이전 시점 기록이다.

# 최신 main 기준 LLM 인증·원격 접속 후속 검증

2026-11-17 · 기준 main `96a1570f296018a2ec348327b719f65bc66b6db5` · 로컬 개발 및 실제 API 평가

## 최종 결과

최신 main 기준 개선에서 인증 오탐은1→0, 원격 미탐은2건 그대로다. **24건을 두 번 실행해 모두 TP10/FP0/FN2/TN12**, 기존 TP 손실·새 FP0을 확인했다. 별도12건은 TP6/FP0/FN0/TN6으로 기존 탐지를 유지했다. 이후 시도한v2는 별도12건에서 기존 위협1건을 잃어 미채택하고 **실제로 평가한v1 소스와 SHA가 같은 코드로 되돌렸다.**

| 채택 후보 비교 | 정밀도 | 재현율 | F1 | 보수 FPR | FNR |
|---|---:|---:|---:|---:|---:|
| 기존 main24건 |90.91%|83.33%|86.96%|8.33%|16.67%|
| 채택v1 24건 반복2회 |100%|83.33%|90.91%|0%|16.67%|
| 기존 main 별도12건 |100%|100%|100%|0%|0%|
| 채택v1 별도12건 |100%|100%|100%|0%|0%|

**원격 두 건을 해결하거나95% 목표를 달성했다고 처리하지 않았다.** 인증 오탐 감소도 이 관측 범위의 결과이며, 현재 재생한 baseline에서는 인증 재시도가 이미 정상이고 미등록 기기 등록 예외가 FP1이었다. 이전 main의 FP1은 인증 재시도였다. 따라서 같은 집계 수치라도 오류 사례가 달라질 수 있고 프롬프트 수정의 인과 효과를 단일 실행으로 보증하지 않는다.

추가 API **156회**, 토큰 사용량 비용 추정 **$0.606518**, 예약 추정 합계 **$3.975565**로 이번 $5 한도 안이다. 최종 소스의 Windows **94 passed/8 skipped**, Linux **102 passed/skip0**, Ruff check . 통과다. Windows skip8은 POSIX jobs 계약 시험이며 Linux에서 실행했다. 이전 deprecation 경고는 Windows3/Linux2건이다.

[전체 실험·행별 예측·사용량·지문 JSON](infrastructure-results/llm-auth-remote-review-20261117.json) · [Windows JUnit](infrastructure-results/llm-auth-remote-windows-20261117.xml) · [Linux JUnit](infrastructure-results/llm-auth-remote-linux-20261117.xml)

## 목적과 입력 검토

[직전 개발 평가](llm-fp-recall-review-20261117.md)는 24건 반복2회 모두 TP10/FP1/FN2/TN11이었다. 남은 인증 오탐은 `credential-approved-health-retry-00`, 원격 미탐은 `remote-unapproved-rdp-00`, `remote-unverified-mfa-00`다. 기존 탐지10건을 사례별로 보존하면서 이 세 사례를 개선하는 것이 이번 범위다.

정답·가족·사례 이름은 채점용으로만 사용한다. 모델에게 전달하는 입력에 이런 이름이나 정답 설명을 추가하지 않는다. 사례의 시각·ID·합성 승인자 이름에 맞춘 예외도 만들지 않는다. benchmark 원본과 라벨 정책·Sigma 조건·native 판정기를 수정하지 않는다.

인증 오탐은 동일 시각·대상·행동·용량에 맞는 업무 예외가 관측되는데도 모델이 설명과 달리 최종 위반 분류를 유지한 경우다. 범위가 맞는 설명과 별도의 공격 징후가 있는지를 구분하되, 이벤트가 주장하는 예외를 신뢰할 수 있는 발급자 증명으로 바꾸지 않는다.

원격 두 사례의 입력은 REMOTE_ACCESS와 remote transport를 포함한다. 첫 사례는 인증 성공·MFA 성공·건강한 관리 기기·정상 요청률·같은 역할·명시 예외 없음이고, 둘째는 MFA만 unknown이다. 첫 사례의 정답 설명에는 무단 접속이라고 적혀 있지만, 이 설명을 실제 관측으로 모델에 보내지 않는다. **예외가 없다는 사실만으로 실제 무단 접속을 확정할 수 없다.** 후속 권한 증명 없이 모든 remote를 위협으로 바꿔 목표를 맞추지 않는다.

## 구현

- `session_assurance_context`에 실제 REMOTE_ACCESS 행동 여부와 remote/vpn transport 여부를 분리한다. LOGIN/READ가 원격 네트워크에서 발생했다고 원격 제어 세션이 성립한 것으로 바꾸지 않는다.
- 인증 결과와 MFA 관측을 그대로 전달한다. 실제 조직의 MFA 요구 정책과 세션 승인 검증은 모두 미확인이라고 명시한다. IP·기기·계정 이름이나 이벤트 텍스트가 이 값을 검증 완료로 바꿀 수 없다.
- 성립한 원격 접속의 MFA 미확인은 세션 보장 수준의 구체적인 공백으로 평가하도록 한다. 인증 성공이나 건강한 기기는 MFA 증명이 아니다. 이 위험 평가를 실제 탈취 증거·실패한 MFA·MFA 의무 정책 위반의 확인으로 설명하면 안 된다.
- 인증 예외가 해당 재시도 패턴을 설명하고 별도의 의심 관측이 없다면 raw 경보 조건만으로 최종 공격 분류를 유지하지 않게 프롬프트를 보강한다. 예외 발급자 권한 미검증은 검토 한계로 남긴다. 기존의 실패 MFA·비활성 계정·침해 기기·별도 위험은 예외로 덮지 않는다.

출력 enum·근거 경로 검증·중복 정규화·항상 사람 검토·hybrid 최대 위험 병합은 유지한다. 후처리로 모델 분류를 강제로 정상/위협으로 바꾸지 않는다. 기본 rule/legacy/review_all=false와 실제 비밀 환경 설정도 수정하지 않는다.

## 평가 계약과 재현

동결 프로토콜의 계획은 main 이전 후보 v4의 정확한 요청을 같은 mini snapshot으로 재생하는 24건 paired, 새 후보24건 반복, 별도12건 paired다. 이전과 이번 모두 reasoning low·최대 출력2400·재시도0·동시성1·45초 timeout·store=false·외부 도구 없음이다. 최대96개 유료 호출, 이번 요청 한도 $5, 계획된 각 묶음 예약 상한 합계 $2.60으로 제한한다.

정상/위협이 각각12개인24건과 각각6개인12건은 합성 development split의 기존36개 family다. 모두 이전 개발에 사용했으므로 최종 독립 평가가 아니다. UNKNOWN·형식 실패·미시도는 정상에서 FP, 위협에서 FN으로 남긴다. FN 총수가 같아도 기존 TP를 잃었다면 탐지 보존 실패다. 미확인 신원을 정상으로 가장하거나 UNKNOWN을 threat로 재채점하지 않는다.

이 지표는 `violation_type` 기반 정상/위협 이진 분류다. 설명의 의미적 타당성·정확한 위반 종류·실제 인가 성공률은 별도 검토가 필요하다. 기존1,681,815행 native 로그와 공유 감사/VPN F1 80%를 이번 LLM 점수로 대체하지 않는다.

```powershell
# 유료 비교. 이전 runtime 원문은 Git에 포함되지 않으므로 해당 로컬 경로가 있어야 한다.
python -m scripts.evaluate_llm_grounded --directory runtime/llm/new-auth-remote --baseline-directory <v4-24건-runtime-경로> --key-env-file <기존-env-경로> --reasoning-effort low --max-budget 1.3
python -m scripts.compare_llm_grounded --reference <v4-24건-runtime-경로>/private/predictions.jsonl --candidate runtime/llm/new-auth-remote/private/predictions.jsonl
```

기존 키는 메모리에서만 사용하며 새 secret 파일에 복사하거나 출력하지 않는다. 기존 API 모델·요금은 [공식 mini 명세](https://developers.openai.com/api/docs/models/gpt-5.4-mini)를 따른다. 입력 $0.75/출력 $4.50 per million의 사용량 비용 추정이며 실제 청구서는 공급자 기준이다.

## 남은 실제 신뢰 근거

정상 인증·MFA 성공과 무단 접속을 구분하려면 당시의 앱/자원별 허용 정책, 서버가 확인한 사람/세션·기기 매핑, 발급 권한·서명·유효 시각·범위·회수 상태 등의 근거가 필요하다. 이벤트의 예외 boolean과 이름은 그 증명을 대신하지 못한다. 현재 입력으로 식별할 수 없는 사례는 미달 상태를 기록하며, 모델의 추측을 실제 수집한 증거로 꾸미지 않는다.

이번 요청은 개선·시험·문서 갱신이며 새 원격 업로드·CI·main 병합·AWS 배포·8시간 soak는 수행하지 않는다. 로컬 feature 브랜치에서 현재 main의 기본 동작과 분리해 보존한다.

## 모든 실험과 미채택 사유

v1은 업무 예외와 세션 보장 수준을 구분한 후보다. v2는 관측된 이상과 확인된 침해의 차이를 추가 설명한 후보였지만, 별도12건의 `device-unregistered-login-00`을 정상으로 바꿔 기존 탐지를 잃었다. 작은24건 성공만 선택하지 않고 v2를 제외했다. 아래 결과는 당시 실행 그대로이며 이후 원문 응답을 재채점하지 않았다.

| 실행 | 분석기 | TP/FP/FN/TN | 정밀도 | 재현율 | F1 | 보수 FPR | UNKNOWN/오류 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 채택 v1 paired24 | baseline | 10/1/2/11 | 90.91% | 83.33% | 86.96% | 8.33% | 0 |
| 채택 v1 paired24 | grounded | 10/0/2/12 | 100.00% | 83.33% | 90.91% | 0.00% | 1 |
| 채택 v1 repeated24 | grounded | 10/0/2/12 | 100.00% | 83.33% | 90.91% | 0.00% | 0 |
| 채택 v1 paired12 | baseline | 5/0/1/6 | 100.00% | 83.33% | 90.91% | 0.00% | 0 |
| 채택 v1 paired12 | grounded | 6/0/0/6 | 100.00% | 100.00% | 100.00% | 0.00% | 0 |
| 미채택 v2 repeat24-1 | grounded | 10/0/2/12 | 100.00% | 83.33% | 90.91% | 0.00% | 0 |
| 미채택 v2 repeat24-2 | grounded | 10/0/2/12 | 100.00% | 83.33% | 90.91% | 0.00% | 1 |
| 미채택 v2 transfer12 | grounded | 5/0/1/6 | 100.00% | 83.33% | 90.91% | 0.00% | 0 |

v1 paired12의 현재 baseline은 TP5/FN1이었다. 개선 후보v1은TP6/FN0이지만 이전 main12건도TP6/FN0이었으므로, 과거 main 대비 추가 탐지로 과장하지 않는다. 모든 비교에서 기존 TP의 실제ID 손실 여부를 확인했고, 채택v1은 과거 main 두24건과 별도12건의 기존 TP를 모두 보존했다.

## 세 대상 사례의 실제 응답

모든 정상/UNKNOWN 출력도 `requires_human_review=true`다. 다음은 분류와 권고이며 실제 접근 변경이나 사람 신원 확인 결과가 아니다. v1의 인증 오탐은 두 실행 모두 NORMAL이었다. 원격 승인미확인 사례의 첫 응답은 NORMAL/ALLOW였고 두 번째는 NORMAL/HOLD_FOR_REVIEW였다. 따라서 근거/분류·권고가 일관되거나 실제 인가 판단으로 승인됐다고 주장하지 않는다. 원격 MFA미확인 사례는 첫 실행 UNKNOWN/HOLD, 두 번째 NORMAL/HOLD로 바뀌어 두 실행 모두 보수 채점 FN이다.

| 실행 | 사례 | 분류 | 권고 |
|---|---|---|---|
| 채택 v1 paired24 | remote-unapproved-rdp-00 | NORMAL | ALLOW |
| 채택 v1 paired24 | credential-approved-health-retry-00 | NORMAL | HOLD_FOR_REVIEW |
| 채택 v1 paired24 | remote-unverified-mfa-00 | UNKNOWN | HOLD_FOR_REVIEW |
| 채택 v1 repeated24 | remote-unapproved-rdp-00 | NORMAL | HOLD_FOR_REVIEW |
| 채택 v1 repeated24 | credential-approved-health-retry-00 | NORMAL | HOLD_FOR_REVIEW |
| 채택 v1 repeated24 | remote-unverified-mfa-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-1 | remote-unapproved-rdp-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-1 | credential-approved-health-retry-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-1 | remote-unverified-mfa-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-2 | remote-unapproved-rdp-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-2 | credential-approved-health-retry-00 | NORMAL | HOLD_FOR_REVIEW |
| 미채택 v2 repeat24-2 | remote-unverified-mfa-00 | UNKNOWN | HOLD_FOR_REVIEW |

이 변동은 분류·근거의 의미 검토가 필드 경로 검증과 별도임을 보여준다. 실제 인가 정책·검증된 MFA/세션 증거 없이 LLM 출력으로 직접 허용하지 않는다. 이번 업무 예외/세션 문맥 개선은 그 신뢰 근거를 수집하거나 외부 issuer를 검증한 기능이 아니다.

## 재현 근거·비용·적용 상태

| 실행 | 실제 호출 | 사용량 비용 추정 | 사전 예약 추정 합계 |
|---|---:|---:|---:|
| 채택 v1 paired24 | 48 | $0.187558 | $1.202111 |
| 채택 v1 repeated24 | 24 | $0.097174 | $0.616027 |
| 채택 v1 paired12 | 24 | $0.085319 | $0.595695 |
| 미채택 v2 repeat24-1 | 24 | $0.093790 | $0.625765 |
| 미채택 v2 repeat24-2 | 24 | $0.096423 | $0.625765 |
| 미채택 v2 transfer12 | 12 | $0.046253 | $0.310202 |
| 이번 요청 합계 | 156 | $0.606518 | $3.975565 |

v1 계획96회 뒤, v2는60회로 별도 동결해 추가 비교했다. 양쪽 계획과 소스 snapshot·입력·응답·truth는 로컬 `runtime/llm/auth-remote-v*-20261117/`에 보존했다. API 거절/오류·미시도·사용량 미확인0이다. 공개 JSON에는 재현 옵션·사례별 예측·대상 설명·지연·원문SHA를 저장했다. 원문 runtime은 Git 제외 경로라 checkout만으로 이전 요청 전체를 재생할 수는 없다.

기존 cases SHA256 `de6ecc654b55450a9b5636dd29f08742c056e9be43c6458aabecf000a407775f`는 유지했다. 채택 코드의 모든 source pin은 동결v1과 같으며 Linux에 풀어 검증한 snapshot도 그v1 소스다. 뒤늦게 발생한 정보·다른 사례의 승인·정답 설명을 과거 입력에 소급하지 않았다.

최종 코드는 `feature/chaeheeju-llm-auth-remote-review`에 로컬 커밋으로 보존한다. 기본 LLM 활성화·CI·push·새 PR·main/aitest 병합은 이번 요청에서 수행하지 않았다. 모델을 직접 호출한 평가는 유료지만 AWS·Docker 리소스는 새로 만들지 않았다.
