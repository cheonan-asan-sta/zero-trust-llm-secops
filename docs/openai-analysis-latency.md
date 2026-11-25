# OpenAI 분석 응답과 승인된 민감 자료 다운로드

간결 프로필은 모델에 보낼 이벤트와 예시의 JSON 공백을 줄이고, 감사 식별자는 로컬에 둔다. 모델의 단일 최종 응답을 기존 JSON 모델로 직접 검증한다. 완료 여부, 거절, 예상하지 않은 도구 출력과 복수 메시지도 검증한다. ASGI의 SDK 준비는 외부 요청 없이 진행된다.

유효 범위의 예외를 포함한 고·치명 민감도 자료의 500MB 이상 다운로드는 최소 `MEDIUM`이다. 이 조건에서 중간 위험의 `ALLOW` 권고는 추가 MFA 권고로 바뀐다. 더 높은 위험도와 더 강한 대응, 사람 검토는 유지한다. 정책 결정에는 적용 조건을 나타내는 감사 근거를 남긴다. 이 판단은 모의 대응 권고다.

## 실제 API 비교 기록

아래 값은 2026년 11월 25일 개발 브랜치에서 같은 합성 8종을 두 번 실행한 기존 SQLite 환경의 결과다. 각 회차는 첫 분석 요청부터 측정했다. P95는 가장 가까운 순위 방식이다.

| 시험 | 위험 등급 | 대응 일치 | JSON | 평균 | P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 간결 프로필의 이전 구성 | 14/16 | 13/16 | 16/16 | 2.451초 | 3.501초 |
| 입력·검증 경로 개선 | 14/16 | 14/16 | 16/16 | 1.870초 | 2.506초 |
| 서버의 다운로드 정책 적용 | 16/16 | 16/16 | 16/16 | 2.409초 | 3.352초 |

이전 구성의 이벤트 ID에는 시나리오 이름이 포함돼 있었다. 후속 시험에서는 평가 입력의 ID를 무작위로 발급하고, 간결 프로필에서는 모델에 보내기 전에 이를 생략했다.

승인된 700MB 백업은 이전에 `LOW / ALLOW`였고 정책 적용 후 두 회차 모두 `MEDIUM / REQUIRE_MFA`였다. 마지막 시험의 정확도는 실제 API 응답에 서버 정책을 적용한 결과다. 마지막 시험의 P95는 3초를 초과했다. 두 건은 OpenAI 응답 헤더 대기만 3초를 넘겼으며, 한 건은 SQLite 감사 쓰기에 414ms가 걸렸다.

- [간결 설정 비교](infrastructure-results/openai-latency-20261125.json)
- [응답 지연 재검증](infrastructure-results/openai-tail-latency-20261125.json)
- [다운로드 정책 검증](infrastructure-results/openai-scoped-download-20261125.json)

## 최신 main의 JSONL 재검증

2026년 11월 25일, 원격 `main`의 병합 커밋 `0b98968`에서 표준 요금의 GPT‑5.4 mini로 같은 합성 8종을 한 번 실행했다. 준비 완료 후 첫 분석 요청부터 포함했다. 앱 준비 시간 1.522초는 분석 응답 시간과 별도로 측정했다. 정책을 적용한 최종 위험 등급과 대응을 기준으로 채점했다.

| 시험 | 위험 등급 | 대응 일치 | JSON | 평균 | P95 | 3초 초과 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 이전 개발 브랜치, SQLite | 16/16 | 16/16 | 16/16 | 2.409초 | 3.352초 | 3/16 |
| 최신 `main`, JSONL | 8/8 | 8/8 | 8/8 | 1.722초 | 2.901초 | 0/8 |

가장 느린 요청은 첫 정상 사무 접근이었다. 전체 2.901초 중 OpenAI 응답 헤더 대기는 2.741초였고, JSONL 감사 저장은 1.962ms였다. 전체 8건의 감사 저장은 평균 1.886ms, 최대 2.363ms였다. 모든 감사 행에서 해시 체인 무결성을 확인했다.

이번 회차의 P95는 3초 기준을 99ms 차이로 충족했다. 8건의 최근접 순위 P95는 최댓값이다. 이전 시험과 저장소·실행 시점이 달라 지연 차이를 저장소 변경 효과로 해석할 수 없다. 기준을 충족해 운영 코드 변경은 보류했다.

실제 API 8회, 재시도 0회, AWS 호출 0회였다. 반환 토큰을 공개 요금에 대입한 비용은 약 US$0.010이었다. [OpenAI 공개 단가표](https://developers.openai.com/api/docs/pricing.md)

[최신 main의 건별 결과와 단계별 계측](infrastructure-results/openai-main-jsonl-20261125.json)

## 실행 설정

```dotenv
ANALYZER_MODE=openai
OPENAI_MODEL=gpt-5.4-mini-2026-03-17
OPENAI_SERVICE_TIER=default
OPENAI_PROMPT_MODE=legacy
OPENAI_COMPACT_LEGACY_OUTPUT=true
OPENAI_REASONING_EFFORT=none
OPENAI_TEMPERATURE=0
```

main의 [검증 실행기](../scripts/verify_submission_openai.py)는 임시 JSONL 감사 저장소에서 회차당 합성 이벤트 8종을 분석한다. 기존 SQLite 기록과는 저장소가 다르다. 실제 호출 시험은 아래 명령으로 실행한다. 키는 별도 로컬 dotenv 파일에서 읽으며 유료 API를 최대 8회 호출한다.

```powershell
python -m scripts.verify_submission_openai --model gpt-5.4-mini-2026-03-17 --service-tier default --temperature 0 --compact-legacy-output --key-file .env.local openai-report.json
```
