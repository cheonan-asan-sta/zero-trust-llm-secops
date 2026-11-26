# 공개 MFA·기기 등록 자료의 연결 가능성과 회귀 평가

`extra` · CPU 로컬 검증 · 공개 자료 열람과 기존 봉인 비교.

## 외부 자료에서 확인한 근거

같은 로그인에 연결된 인증원의 MFA 결과, 테넌트·계정·기기 식별자가 일치하는 선행 등록 상태, 로그인별 정상·ATO 정답을 함께 요구했다. 공개 원본에서 사용자명·IP·User-Agent·기기 지문 유사성이나 서로 다른 실험 간 시각만으로 연결하지 않았다. MFA 등록 성공, MFA 푸시 전송, 인증 단계 성공, 로그인 완료를 각각 구분했다. 토큰에 포함된 MFA 주장을 해당 로그인에서 새로 성공한 인증으로 세지 않았다. [Entra MFA 로그 해석](https://learn.microsoft.com/entra/identity/authentication/howto-mfa-reporting)

| 검토한 자료 | 원본에서 확인한 범위 | 실제 평가에 빠진 근거 |
| --- | --- | --- |
| Splunk Entra 기기 등록 | `Register device` 성공 10행. 10행 모두 발행자 기록의 실행 계정·기기 식별자 확인 | 같은 로그인·MFA 결과와 로그인별 ATO/정상 정답 |
| Splunk Entra 로그인·MFA 등록 | 로그인 행 48건 중 완료된 로그인 40건. 여섯 행에서 앱 알림 MFA 단계 성공을 확인했지만 완료 로그인 행과 겹치지 않음. 40개 완료 행은 토큰의 MFA 주장만 확인 | 로그인 행의 공급자 기기 ID 0/48. 검증된 선행 기기 이력과 결합 0건 |
| Splunk Okta MFA·기기 등록 | MFA 이벤트 10건 중 성공 3건, 실패 7건. 별도 수집의 기기 등록 성공 2건 | MFA 행의 등록 기기 ID 0/10. 세션 시작 기록 0건. 개별 로그인 ATO/정상 정답 없음 |
| DatabaseSample 합성 MFA 자료 | 시도 380건과 MFA 설정 변경 58건. 발행자 표식은 소유자 306건, 공격자 74건이며 공격자 승인 사례는 7건 | 시도·설정 변경에 기기 결속 키가 없고 시도에서 발급 세션 ID를 확인할 수 없음 |
| IAM-UEBA | 공개 스키마의 인증·세션 이벤트와 User-Agent에서 추출한 기기 필드 | 등록 상태와 사고 정답이 함께 제공되는 평가 단위 부재 |

Splunk 원본 5개는 `attack_data` 커밋 `5879f5423e6c08df2b22b63f7b36e84866f9c51c`에서 내려받고 Git LFS 지문과 실제 바이트를 대조했다. 공격 모의 사례 설명을 로그 전체의 행별 ATO 정답으로 사용하지 않았다. DatabaseSample 파일은 발행자의 SHA-256을 확인했고 IAM-UEBA는 발행자 설명과 스키마를 확인했다. 위 자료에서는 조건을 모두 갖춘 평가 행을 확보하지 못했다. [Splunk Entra 등록](https://research.splunk.com/attack_data/9d833380-b164-4b1d-8d4f-49a6cf62df5f/) · [Splunk Entra 로그인](https://research.splunk.com/attack_data/5f673895-0a89-4c21-bd0a-54d28fb4b948/) · [Splunk Entra MFA 방법](https://research.splunk.com/attack_data/1080fb28-9a11-40c8-907d-70daf17415e4/) · [Splunk Okta 등록](https://research.splunk.com/attack_data/e8b09d11-6659-4bf9-85a5-4f804ddeeac0/) · [Splunk Okta MFA](https://research.splunk.com/attack_data/6ab28c66-327b-4c39-8b30-b727b04763ec/) · [외부 합성 MFA 자료](https://databasesample.com/datasets/mfa-push-fatigue-and-bypass-attempt-logs) · [IAM-UEBA](https://zenodo.org/records/22871318)

## 별도 RBA 계정군의 결측 회귀

기존에 개별 판정을 검토하지 않은 RBA 계정 해시 구간 20~24를 지정했다. 기존 모델 평가 구간 0~19 및 70~99와 최초 probe 계정을 제외했다. 이전에 고정한 계정 분할 목록으로 계정 215,362개와 로그인 866,564건을 확인했다. 기존 OS 기반 후보를 같은 SHA로 적용하고 새 MFA·기기 근거를 미확정으로 유지했다. 예측을 봉인한 뒤 ATO 정답 8건을 결합했다. [공개 RBA](https://zenodo.org/records/6782156)

| 같은 RBA 로그인 866,564건 | 기존 우선 검토 | 추가 근거 결측 시 우선 검토 |
| --- | ---: | ---: |
| TP / FP / FN | 4 / 2,581 / 4 | 4 / 2,581 / 4 |
| 재현율 | 50.00% | 50.00% |
| F1 | 0.3085% | 0.3085% |
| 오탐률 | 0.2978% | 0.2978% |

변경된 판정·새 오탐·기존 탐지 손실은 각각 0건이었다. 앞서 해제한 반복 실패 경보 377건도 다시 발생하지 않았다. 이전 0~19 구간에서는 재현율 27.50%, F1 0.2148%, 오탐률 0.2899%였다. 해당 구간의 기존 예측을 수정된 채점기로 다시 채점해 결과 파일의 SHA-256이 같음을 확인했다. 두 구간의 값 차이는 표본이 달라 발생한 것이며, 직접 비교는 같은 20~24 구간의 표를 사용한다. [이전 0~19 구간 결과](extra-rba-ato-separation-20261123.md)

MFA·기기 등록을 실제로 적용했을 때의 외부 재현율·F1·오탐률은 미측정이다. 로컬에서 실제 OTP·mTLS를 이용했던 이전 통제 시험은 별도 결과로 유지한다. [로컬 MFA·기기 근거 시험](extra-rba-ato-device-review-20261123.md)

## 재현

Splunk 공개 파일의 정확한 경로는 발행자 설명에 있다. 고정 커밋의 Git LFS 파일 본문을 내려받아 `entra-device.jsonl`, `entra-login.jsonl`, `entra-mfa-method.jsonl`, `okta-device.jsonl`, `okta-mfa.jsonl`에 저장한다. 외부 합성 JSON은 `external-mfa-fatigue.json`으로 저장한다. 평가기가 여섯 자산의 SHA-256을 검사한다. RBA 확인에는 이전과 같은 ZIP·probe 기록·고정 우선순위 후보를 사용한다.

```powershell
python -m scripts.audit_public_mfa_device_sources <public-input-directory> <new-audit.json>
go run scripts/experiments/rba_login_projection/main.go --missing-evidence <rba.zip> <probe.json> <new-projection>
python -m scripts.evaluate_rba_ato_separation capture <new-projection> <new-evaluation> <frozen-candidate.json> <candidate-sha256> --missing-evidence
python -m scripts.evaluate_rba_ato_separation score <new-projection> <new-evaluation> <seal-sha256> --missing-evidence
```

관련 회귀 47개와 Ruff를 통과했다. 유료 API·클라우드 배포·병합은 0회다. 원본·개별 예측은 로컬 `runtime` 아래에 두었다. [집계와 봉인 지문](infrastructure-results/public-mfa-device-evaluation-20261123.json)
