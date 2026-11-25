# 웹 POST의 요청 대상과 본문 검사 비교

2026년 11월 26일 · `extra` · 로컬 CPU 재검증

## 구현

[FPAD 요청 대상 평가](extra-public-fpad-crs-20261125.md)에서 미탐 6,256건 중 4,442건에 본문이 있었다. FPAD 공개 파일에는 Content-Type이 없어 형식을 추정하지 않았다. 별도로 Content-Type을 기록한 기존 POST 자료에서 Coraza 3.8.1·CRS 4.25.0의 같은 규칙을 요청 대상만 검사했을 때와 본문까지 검사했을 때 비교했다.

로컬 실행기에 `--target-and-body`를 추가했다. 관측된 Content-Type이 JSON 또는 URL 인코딩 폼이고 지원하는 문자 인코딩일 때만 최대 1 MiB 본문을 요청 검사기에 전달한다. 본문 대상이 아니거나 기록이 불분명하면 요청 대상 검사 결과를 유지한다. 운영 차단은 수행하지 않는다. 저장 결과에는 행 번호, 판정, 일치 규칙 ID, 본문 전달 여부만 남기고 본문과 헤더 원문은 남기지 않는다. [검사기](../scripts/experiments/crs_shadow/main.go) · [비교 실행기](../scripts/evaluate_public_post_body_scope.py)

두 판정의 메서드와 요청 대상, 프로토콜, CRS 규칙을 같게 유지했다. 새 입력은 관측된 본문과 형식이며 길이는 저장된 본문의 바이트 수에서 계산했다. 응답 2xx는 비교할 POST 집단을 고르는 데만 사용했다. Cookie·IP·Referer·학습용 정답은 판정에 전달하지 않았다. 본문을 전달하지 않은 행에 판정 차이가 생기면 채점이 실패한다. 두 예측을 먼저 봉인하고 발행자 라벨은 채점에서만 읽었다.

## SR-BH에서의 효과

| 같은 POST 2xx 19,553건 | TP / FP / FN / TN | 정밀도 | 재현율 | F1 | 오탐률 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 요청 대상만 | 387 / 0 / 17,328 / 1,838 | 100.00% | 2.18% | 4.28% | 0.00% |
| 요청 대상과 기록된 본문 | 7,699 / 6 / 10,016 / 1,832 | 99.92% | 43.46% | 60.57% | 0.33% |

17,321행에서 본문을 검사기에 전달했다. 위협 7,312건을 추가로 탐지했고 기존 탐지 손실과 추론 오류는 0건이었다. 새 오탐 6건에는 모두 CRS 규칙 계열 `932`만 일치했다. 같은 조건에 새로 잡은 위협도 1,965건 있어 그 계열을 일괄 제외하면 재현율을 다시 낮춘다. 정밀도와 오탐률 목표에는 들었고 재현율·F1 및 새 오탐 0건 조건은 미충족이다. SR-BH는 기존에 본 자료이고 발행자 정답 구성에 WAF 관측이 포함돼 있다. [SR-BH 발행자 자료](https://doi.org/10.7910/DVN/OGOIXX) · [기존 SR-BH와 웹 API 자료 평가](extra-public-post-crs-rules-transfer-20261123.md)

## crAPI·VAmPI 회귀

| 같은 POST 2xx 5,216건 | TP / FP / FN / TN | 정밀도 | 재현율 | F1 | 오탐률 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 요청 대상만 | 0 / 0 / 2,902 / 2,314 | 계산 불가 | 0.00% | 0.00% | 0.00% |
| 요청 대상과 기록된 본문 | 128 / 0 / 2,774 / 2,314 | 100.00% | 4.41% | 8.45% | 0.00% |

관측된 JSON 본문 5,216건을 전달했다. 새 오탐·기존 탐지 손실·추론 오류는 모두 0건이었다. 라벨은 발행자의 캠페인과 수집 시간에 따른 것으로 개별 요청의 실제 피해나 위반 여부를 확정할 수 없다. 이전에 평가한 동일 소스를 사용했으므로 새 독립 성능으로 합산하지 않는다. [공개 자료와 라벨 기준](https://github.com/aziz-abibulaiev/web-attack-detector#datasets) · [집계와 봉인](infrastructure-results/public-testbed-post-body-scope-20261126.json)

## 기존 전체 검사와 대조

기존의 전체 요청 CRS는 SR-BH에서 위협 11,754건, crAPI·VAmPI에서 위협 157건을 탐지했다. 기존 웹 모델과 전체 요청 CRS를 합친 경보에 이번 본문 검사를 더해도 두 자료 모두 판정이 바뀌지 않았다. 추가 탐지 7,312건과 128건은 요청 대상만 제공한 조건과의 차이다. 기존 전체 경로의 미탐과 오탐을 줄인 결과는 이번에 확인되지 않았다. 본문 후보는 입력 범위를 제한한 로컬 진단으로 유지한다. [기존 경보와 행별 대조 집계](infrastructure-results/public-post-body-vs-existing-alerts-20261126.json)

## 추가 공개 PKDD 자료의 본문 확인

새 PKDD 평가 10,024건에서 본문이 있는 요청은 1,891건이다. 공개 파일의 본문이 평문 문자열로 보관돼 있고 원래 압축 바이트를 확인할 수 없었으므로, 기록된 인코딩이 `identity`인 480건에만 기존 본문 모드를 적용했다. Content-Type과 Content-Encoding은 원래 헤더 기록에서 확인했다. [새 PKDD 평가와 자료 출처](extra-public-web-shape-transfer-20261126.md#기준값-보정과-새-혼합-자료-검증)

고정 CRS 요청 대상 단독 대비 위협 62건과 오탐 12건이 추가됐으며 기존 위협 탐지 손실과 추론 오류는 0건이었다. 재현율 49.33%에서 51.36%, F1 62.85%에서 64.45%, 오탐률 3.32%에서 3.49%로 바뀌었다. 정밀도는 86.61%에서 86.49%로 내려갔다. 공개 기록의 관측 한계를 유지했고 운영 경보에 적용하지 않았다. [PKDD 본문 비교 집계](infrastructure-results/public-pkdd-typed-body-20261126.json)

일치한 내용 규칙 ID의 심각도에 기본 CRS 가중치 5/4/3/2를 적용해 최소 5점 조건도 대조했다. FPAD·FPAD-OOD, 정상 웹 두 표본 및 PKDD의 저장 판정에서는 오탐과 위협 탐지가 모두 그대로였다. 이 계산은 저장된 내용 규칙만 대상으로 했으며 CRS의 전체 inbound 차단 판정과 범위가 다르다. [CRS 공식 점수 기준](https://coreruleset.org/docs/concepts/anomaly_scoring/) · [가중치 대조 집계](infrastructure-results/public-crs-severity-audit-20261126.json)

## 재현

`scripts/experiments/crs_shadow`에서 `go test ./...` 및 `go build -trimpath -o <검사기>`를 실행하고 저장소 루트에서 새 결과 경로를 사용한다. SR-BH에는 기존 성공 POST 봉인을 지정한다. crAPI·VAmPI 아카이브에서는 `--sr-bh-reference`를 생략한다. crAPI·VAmPI 원본 Parquet을 읽을 때 PyArrow 24.0.0을 사용했다.

```powershell
python -m scripts.evaluate_public_post_body_scope capture <원본> <새-출력> <검사기> --sr-bh-reference <SR-BH-POST-봉인-폴더>
Get-FileHash <새-출력>/seal.json -Algorithm SHA256
python -m scripts.evaluate_public_post_body_scope score <원본> <새-출력> <seal-SHA256>
```

관련 로컬 회귀 153개, Go 시험과 Ruff를 통과했다. 기존 FPAD 16,197건의 요청 대상 단독 판정, 기존 SR-BH 19,553건의 전체 요청 검사 판정, SR-BH 본문 비교의 재실행 두 판정이 각각 이전 예측 파일과 바이트 단위로 같았다. 원시 입력은 로컬에 두었다. AWS와 유료 API를 호출하지 않았고 운영 판정 또는 정책에는 적용하지 않았다. [SR-BH 집계와 봉인](infrastructure-results/public-sr-bh-post-body-scope-20261126.json)
