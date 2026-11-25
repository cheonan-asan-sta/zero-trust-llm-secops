# 별도 정상 웹 요청의 오탐 검증

2026년 11월 26일 · `extra` · 로컬 CPU 검사

open-appsec 공개 벤치마크에서 실제 웹사이트를 탐색해 수집한 정상 요청 모음을 사용했다. 후보 검사기와 평가 규칙은 자료를 읽기 전에 고정했다. 발행자가 정상으로 표시한 요청 12,887건을 12개 수집 파일에서 확보했다. ZIP의 전체 692개 JSON 중 압축 크기 4 MiB 이하, 원문 크기 24 MiB 이하인 파일을 파일명 SHA-256으로 정렬하고 앞 12개를 정했다. 다운로드한 부분의 공개 ZIP ETag와 각 파일 지문을 확인했다. 전체 정상 모음에 대한 전수 평가가 아니다. [발행자 자료 구성과 라이선스](https://github.com/openappsec/waf-comparison-project#legitimate-data-set)

판정에는 메서드와 원본 요청 대상, 형식이 확인되는 경우의 본문만 사용했다. 원래 없는 HTTP 버전이나 응답·사용자 권한을 가정하지 않았다. 헤더에서 본문 형식과 인코딩만 분리했고 Cookie나 Host는 포함하지 않았다. 한 요청에 형식이 여러 개 기록돼 모호하면 본문 검사에서 제외했다. 요청 서버로 트래픽을 보내지 않고 저장 데이터만 검사했다.

| 같은 정상 요청 12,887건 | 경보 | 보수 오탐률 | 추론 오류 |
| --- | ---: | ---: | ---: |
| CRS 요청 대상만 | 74 | 0.57% | 0 |
| CRS 요청 대상과 기록된 본문 | 496 | 3.85% | 0 |

본문을 전달한 요청은 2,844건이고, 새 오탐은 422건이었다. 이 표본에서는 두 구성 모두 오탐률 5% 이하였지만, 후자의 새 오탐 0건 조건은 미달이다. 정상만 있는 자료여서 정밀도·재현율·F1은 산정하지 않았다. 기존 [SR-BH·crAPI·VAmPI 비교](extra-public-post-body-scope-20261126.md)와 별도로 기록한다.

## 재현

원본 ZIP의 ETag는 `"7f7b53e6e8d780e4d390c8070bffce88-71"`이고 아카이브 크기는 1,203,983,791바이트다. 원시 요청과 선택·다운로드 영수증은 로컬 `runtime/independent-web-access-20261125/openappsec-legitimate/`에 보관했다. 아래 실행은 이미 확보한 파일만 읽는다. 출력에는 집계와 판정 지문을 남기고 AWS·유료 API·실제 정책 변경은 없었다. [집계 결과](infrastructure-results/public-openappsec-legitimate-crs-20261126.json) · [선택과 지문](infrastructure-results/public-openappsec-legitimate-sample-20261126.json)

```powershell
python -m scripts.evaluate_public_legitimate_web_crs <샘플-폴더> <새-출력> <고정-CRS-실행파일>
```
