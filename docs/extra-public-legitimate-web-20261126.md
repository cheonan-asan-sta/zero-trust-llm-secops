# 별도 정상 웹 요청의 오탐 검증

2026년 11월 26일 · `extra` · 로컬 CPU 검사

open-appsec 공개 벤치마크에서 실제 웹사이트를 탐색해 수집한 정상 요청 모음을 사용했다. 후보 검사기와 평가 규칙은 자료를 읽기 전에 고정했다. 발행자가 정상으로 표시한 요청 12,887건을 12개 수집 파일에서 확보했다. ZIP의 전체 692개 JSON 중 압축 크기 4 MiB 이하, 원문 크기 24 MiB 이하인 파일을 파일명 SHA-256으로 정렬하고 앞 12개를 정했다. 다운로드한 부분의 공개 ZIP ETag와 각 파일 지문을 확인했다. 전체 정상 모음에 대한 전수 평가가 아니다. [발행자 자료 구성과 라이선스](https://github.com/openappsec/waf-comparison-project#legitimate-data-set)

판정에는 메서드와 원본 요청 대상, 형식이 확인되는 경우의 본문만 사용했다. 원래 없는 HTTP 버전이나 응답·사용자 권한을 가정하지 않았다. 헤더에서 본문 형식과 인코딩만 분리했고 Cookie나 Host는 포함하지 않았다. 한 요청에 형식이 여러 개 기록돼 모호하면 본문 검사에서 제외했다. 요청 서버로 트래픽을 보내지 않고 저장 데이터만 검사했다.

| 같은 정상 요청 12,887건 | 경보 | 보수 오탐률 | 추론 오류 |
| --- | ---: | ---: | ---: |
| CRS 요청 대상만 | 74 | 0.57% | 0 |
| CRS 요청 대상과 기록된 본문 | 496 | 3.85% | 0 |

본문을 전달한 요청은 2,844건이고, 새 오탐은 422건이었다. 이 표본에서는 두 구성 모두 오탐률 5% 이하였지만, 후자의 새 오탐 0건 조건은 미달이다. 정상만 있는 자료여서 정밀도·재현율·F1은 산정하지 않았다. 기존 [SR-BH·crAPI·VAmPI 비교](extra-public-post-body-scope-20261126.md)와 별도로 기록한다.

새 오탐 중 JSON은 380건, URL 인코딩 폼은 42건이었다. 두 형식 모두 오탐이 나타났다. [형식과 규칙 계열별 집계](infrastructure-results/public-openappsec-body-fp-families-20261126.json)

## 추가 수집 사이트 표본

동일 크기 범위에서 앞선 12개 파일과 수집 사이트가 같은 파일을 제외한 뒤, 고정한 순서로 다른 사이트 파일 12개를 추가 선택했다. 사이트별 수집 파일에는 공용 주소나 외부 리소스 요청도 포함될 수 있다. 본문 판정 기준은 이 표본을 열기 전에 고정했다. 전체 정상 15,250건에서 요청 대상만 확인하면 오탐은 **359건(2.35%)**, 본문을 함께 보면 **764건(5.0098%)**이었다. 본문을 전달한 2,499건에서 새 오탐 405건이 생겼고 추론 오류는 없었다. 새 오탐이 없다는 조건과 오탐률 5% 기준을 모두 놓쳤다. [추가 파일 선택과 지문](infrastructure-results/public-openappsec-holdout-sample-20261126.json) · [판정 집계](infrastructure-results/public-openappsec-holdout-crs-20261126.json)

파일별로 보면 오탐률 5%를 넘은 수집 파일은 요청 대상 검사에서 1/12개, 본문 포함 검사에서 4/12개였다. 본문 모드의 최고 오탐률은 13.65%였다. 형태 보정 모델을 CRS와 결합한 경우 전체 오탐률은 3.03%였지만 학습 중복을 제외한 같은 12개 파일 중 2개에서 5%를 넘었다. [파일별 오탐률 집계](infrastructure-results/public-openappsec-site-fpr-20261126.json) · [형태 모델 보정 결과](extra-public-web-shape-transfer-20261126.md#기준값-보정과-새-혼합-자료-검증)

## 세 번째 사이트 분리 표본

앞서 쓴 사이트 24개의 수집 파일을 제외하고, 파일명 SHA-256 순서에 따라 서로 다른 사이트의 파일 32개를 더 확보했다. 각 파일의 압축 해제 크기는 최대 24 MiB이며 ZIP CRC와 SHA-256을 확인했다. 총 49,399건 중 기존 형태 모델의 학습·보정과 요청 대상 및 본문이 그대로 겹친 827건을 모든 비교에서 함께 제외했다. 보정 기준값 0.84와 Windows CRS 바이너리를 기존 평가와 같게 유지했다.

| 같은 정상 요청 48,572건 | 경보 | 전체 오탐률 | 5% 초과 수집 파일 | 파일 최고 오탐률 |
| --- | ---: | ---: | ---: | ---: |
| CRS 요청 대상 | 715 | 1.47% | 2 / 32 | 6.05% |
| CRS 대상 및 본문 | 1,767 | 3.64% | 5 / 32 | 50.48% |
| CRS 대상과 형태 모델 결합 | 1,339 | 2.76% | 5 / 32 | 25.71% |

각 구성에서 미판정은 0건이었다. 본문 후보의 새 오탐 1,052건 중 732건이 한 수집 파일에 집중됐다. 그 파일에서 해당 오탐을 메서드·대상·본문 조합으로 중복 제거하면 308가지였으며, 같은 조합의 최다 반복은 16건이었다. 단일 요청을 반복한 현상만으로 설명되지 않는다. 파일별 차이가 크고 이 표본에는 위협 정답이 없어서 세 구성을 운영 경보에 반영하지 않았다. [세 번째 표본의 파일별 지표·지문](infrastructure-results/public-openappsec-expanded-site-fpr-20261126.json)

## 재현

원본 ZIP의 ETag는 `"7f7b53e6e8d780e4d390c8070bffce88-71"`이고 아카이브 크기는 1,203,983,791바이트다. 원시 요청과 선택·다운로드 영수증은 로컬 `runtime/independent-web-access-20261125/openappsec-legitimate/`에 보관했다. 아래 실행은 이미 확보한 파일만 읽는다. 출력에는 집계와 판정 지문을 남기고 AWS·유료 API·실제 정책 변경은 없었다. [집계 결과](infrastructure-results/public-openappsec-legitimate-crs-20261126.json) · [선택과 지문](infrastructure-results/public-openappsec-legitimate-sample-20261126.json)

```powershell
python -m scripts.evaluate_public_legitimate_web_crs <샘플-폴더> <새-출력> <고정-CRS-실행파일>
python -m scripts.evaluate_public_legitimate_web_crs <추가-샘플-폴더> <새-출력> <고정-CRS-실행파일> --holdout
python -m scripts.evaluate_public_legitimate_web_crs <32개-샘플-폴더> <CRS-출력> <고정-CRS-실행파일> --expanded
python -m scripts.evaluate_public_web_site_distribution <32개-샘플-폴더> <FPAD-학습-JSONL> <최초-정상-샘플-폴더> <CRS-출력> <새-집계-폴더>
```
