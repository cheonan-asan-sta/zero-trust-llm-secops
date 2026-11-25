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
