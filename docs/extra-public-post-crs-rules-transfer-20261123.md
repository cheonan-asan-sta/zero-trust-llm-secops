# 웹 요청의 OWASP CRS 규칙 근거와 공개 자료 전이 검증

2026-11-23 · `extra` · 무료 로컬 분석 · 성공한 HTTP POST 요청 범위.

## 후보 구현

Coraza 3.8.1과 OWASP CRS 4.25.0의 로컬 검사에서 일치한 `attack-` 태그 규칙 ID를 수집하도록 했다. 결과에는 행 번호, 경보, 중복을 제거한 규칙 ID만 저장한다. 이 모드 전후로 SR-BH 성공 POST **19,553건의 CRS 경보가 모두 같았다**. 기존 CRS 경보는 새 후보에서도 보존한다.

새 후보는 요청 대상·본문의 길이와 문자 구조, 응답 상태, CRS 규칙 ID를 사용한다. 개발 구간에서 나타난 규칙 ID 21개만 모델 입력에 포함했다. 발행자의 정답, 원문 토큰, 클라이언트 IP, 도구와 캠페인 이름은 새 모델 입력에 넣지 않았다. 로컬 실행기는 HTTP 요청을 보내거나 앱 권한을 변경하지 않는다. [이전 성공 POST 평가](extra-public-successful-post-transfer-20261123.md) · [Coraza와 CRS 연동](https://www.coraza.io/docs/tutorials/coreruleset/)

## SR-BH 시점 분리 진단

7월 17일 학습 5,088건, 18일 보정 13,007건, 19일 시점 진단 525건을 사용했다. 동일 요청 대상과 본문이 뒤 구간에 있으면 앞 구간에서 제거했다. 기준값은 보정 구간으로만 선택했다. 보정 구간에서 모든 조건을 충족하는 기준값이 없었고, 진단용 0.58에서 오탐률 30.45%, 새 오탐 2건, 기존 탐지 손실 196건이었다.

| 7월 19일 525건 | 정밀도 | 재현율 | F1 | 오탐률 | FP / FN | 기존 탐지 손실 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 기존 웹 모델 또는 기본 CRS | 74.44% | 82.18% | 78.12% | 94.21% | 114 / 72 | 0 |
| 기본 CRS 또는 규칙·요청 구조 후보 | 98.72% | 95.30% | 96.98% | 4.13% | 5 / 19 | 19 |

오탐은 109건 감소했고 새 오탐은 0건이었다. 기존에 놓친 72건을 회복하면서 기존에 잡던 19건을 놓쳤다. 진단 표본의 네 수치에는 도달했지만 기존 탐지 보존 조건이 미달이다. 같은 출처에서의 시점 분리 결과이며, 운영에 적용하지 않았다. SR-BH 발행자의 라벨 검토에 ModSecurity 결과가 포함되어 있어 CRS 기반 입력과 정답의 근거가 일부 관련될 수 있다. [SR-BH 자료](https://doi.org/10.7910/DVN/OGOIXX)

## 별도 공개 crAPI·VAmPI 실험 기록

발행자가 고정 배포한 `v1.0.0` 아카이브의 SHA-256 `9126e43da413bee16cb543a8d0b9187819d312303f83c83e57d8bda3b1ecfd86`를 확인했다. HTTP 기록 21,136건에서 메서드와 관측된 응답 코드로 POST 2xx 5,216건을 선택했다. 학습과 보정에는 SR-BH만 사용했다. 동일한 모델 계획과 판정을 재현한 뒤 외부 데이터의 예측을 봉인했다. 채점은 별도 명령에서 라벨을 읽는다. 525개 재현 진단에서 병렬 트리 점수의 최대 차이는 약 `1.11e-16`이었다. 모델 계획과 기준값, 행 순서, 최종 판정은 모두 같았다.

공개 시험의 정상·위협 라벨은 저자가 기록한 클라이언트와 캠페인 시간에 근거한다. 위협 캠페인에 포함됐다는 사실만으로 개별 요청의 악성 여부나 성공을 확인할 수 없다. 같은 요청에 대한 인증원 결정이나 정책 엔진 승인 기록도 포함되지 않는다. 운영 트래픽을 대표하는 지표나 실제 침해 성공률로 해석하지 않는다. [공개 자료와 라벨 방식](https://github.com/aziz-abibulaiev/web-attack-detector#datasets) · [발행자 수집 설명](https://github.com/aziz-abibulaiev/web-attack-detector/blob/main/src/corpus/README.md)

| 외부 POST 2xx 5,216건 | 정밀도 | 재현율 | F1 | 오탐률 | TP / FP / FN / TN |
| --- | ---: | ---: | ---: | ---: | ---: |
| 기존 웹 모델 | 51.24% | 79.98% | 62.46% | 95.46% | 2,321 / 2,209 / 581 / 105 |
| 기본 CRS | 100.00% | 5.41% | 10.26% | 0.00% | 157 / 0 / 2,745 / 2,314 |
| 기존 웹 모델 또는 기본 CRS | 51.25% | 80.01% | 62.48% | 95.46% | 2,322 / 2,209 / 580 / 105 |
| 기본 CRS 또는 규칙·요청 구조 후보 | 55.83% | 100.00% | 71.65% | 99.22% | 2,902 / 2,296 / 0 / 18 |

기존 웹 모델 또는 CRS와 비교해 위협 라벨 580건을 새로 탐지했고 기존 탐지 손실은 0건이다. 정상 18건의 경보가 해제됐지만 새 오탐 105건이 생겨 전체 오탐은 87건 늘었다. 후보의 오탐률은 crAPI 100.00%, VAmPI 99.07%였다. 기준값을 다시 조정하거나 앱·캠페인을 제외하지 않았다. 정밀도·F1·오탐률 목표와 새 오탐 0건 조건이 미달로 운영 적용을 보류한다. 이 외부 표본에서 오탐률 5%를 만족하려면 정상 2,314건 중 오탐을 115건 이하로 줄여야 한다.

미탐 회복의 480/580건은 로그인 반복 시도와 재사용 자격 증명 시도 캠페인에 속했다. 단일 요청의 구조만으로 재현율을 높이면 두 앱에서 정상 워크플로까지 광범위하게 경보로 잡혔다. 후속 실험은 요청별 검증된 인증 결과, 계정 단위의 선행 시도 이력, 승인·정책 근거를 우선한다. 이 자료에는 그 근거의 일부가 없어서 결측 상태를 유지한다.

## 재현

기존 [SR-BH 성공 POST 예측과 CRS 봉인](extra-public-successful-post-transfer-20261123.md#재현)을 준비한다. Python 3.12, scikit-learn 1.7.2, PyArrow 24.0.0에서 실행했다. `<crs-bin>`은 `scripts/experiments/crs_shadow`에서 `go build -trimpath`로 만든 바이너리 경로다. 이전 CRS 봉인에 저장된 경보와 새 규칙 관측의 경보를 대조한다.

```powershell
python -m scripts.evaluate_public_post_crs <sr-bh.csv> <post-output> <rules-output> --exe <crs-bin> --rule-ids
python -m scripts.evaluate_public_post_crs_rules <sr-bh.csv> <post-output> <crs-output> <rules-output> <diagnostic-output>
python -m scripts.evaluate_public_api_post_transfer capture <publisher.tar.gz> <external-output> <sr-bh.csv> <post-output> <crs-output> <rules-output> <crs-bin> <diagnostic-output> <diagnostic-seal-sha256>
python -m scripts.evaluate_public_api_post_transfer score <publisher.tar.gz> <external-output> <external-seal-sha256>
```

각 출력은 새 디렉터리를 사용한다. 원본 요청과 개별 예측은 `runtime/independent-web-target-20261123/`에 로컬로 보관했다. 평가기와 웹 회귀 160개, Ruff, 로컬 Go 빌드를 통과했다. 유료 API·AWS 호출·병합은 0회다. [집계 결과와 봉인 지문](infrastructure-results/public-post-crs-rules-transfer-20261123.json)

[후속 인증 결과·계정 이력 실험](extra-account-login-history-20261123.md)은 Keycloak에서 연결을 검증하고, 별도 공개 RBA에서 오탐 변화를 측정했다. 이 웹 자료의 검증된 이력 결측 시 기존 판정이 유지되는 것도 확인했다.
