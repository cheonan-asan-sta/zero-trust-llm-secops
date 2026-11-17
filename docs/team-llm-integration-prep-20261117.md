> 2026-11-17 후속: 사용자 실제 aitest 병합 요청으로 이번 통합의 이전 보류 조건을 해제했다. 목표 미달과 평가 범위는 그대로이며 아래는 이전 작업 당시 기록이다. [최신 통합 승인·검증](aitest-team-llm-merge-20261117.md)

# LLM·팀 대시보드 통합 준비 및 인수인계

2026-11-17 KST · 로컬 준비 전용 · 원래 성능 목표 미완료 · 원격 업로드/PR/새 CI/기준 브랜치 병합 보류

## 준비 결과와 범위

준비 브랜치는 `feature/chaeheeju-team-llm-integration-prep`, checkout은
`C:/Users/chaeh/Desktop/파란학기/tmp/team-llm-integration-prep-20261117`이다.
통합 후보 커밋은 `5b5708b232ea5185b7c697d78b19bd769d38c554`이며 부모는 최신 내 작업
`51bb4836bccc2bd436846b758477b3107809f46e`와 확인한 `origin/main`
`d2370c2a493cfa584ad005420abe172cef913c7b`다. 이 merge commit은 **준비 브랜치 안에서만** 만들었다.
실제 로컬 `main`/`aitest`나 원격 포인터에 병합한 결과가 아니다.

원본 `tmp/local-target-gate-20261116`의 HEAD는 그대로 보존했고 이 작업에서 그 worktree에 파일을 쓰지 않았다.
다른 기존 worktree에서 checkout/reset/clean/stash를 수행하지 않았다.
주 저장소에 있던 미추적 `docs.zip`, `docs/week03.zip`도 보존했다.

**동시 작업 관측:** 원본은 시작 때 clean이었으나 최종 확인 때 `app/grounded_prompting.py`,
`infra/llm-grounded.example.env`, `scripts/evaluate_llm_grounded.py`,
`tests/test_grounded_prompting.py`, `tests/test_llm_grounded_evaluation.py`의 수정과
`docs/llm-fp-recall-review-20261117.md`, `scripts/compare_llm_grounded.py`,
`tests/test_llm_grounded_comparison.py`의 미추적 추가를 관측했다. 원본 HEAD는 여전히 `51bb483`이다.
이 새 미커밋 작업은 읽어 병합하거나 commit/stash/reset하지 않았다. **본 후보와 검증은 요청에 지정한
`51bb483`을 기준으로 하며 이 후속 WIP는 포함하지 않는다.** 후속 LLM 변경이 커밋되면 별도로 포함 관계와
회귀를 대조해야 한다. 상태 관측 시각과 파일 목록은 JSON에 기록했다.

## 최신 원격·저자·포함 관계

작업 시작 시 `git fetch origin --prune`을 다시 성공시켰다. 검증 중 `git ls-remote`로도
main/aitest/팀원 branch가 같은 SHA임을 재확인했다. 아래 SHA는 고정 비교값이다.

| 참조 | 확인한 전체 SHA | 실제 변경 소유 근거 |
|---|---|---|
| origin/main | `d2370c2a493cfa584ad005420abe172cef913c7b` | PR #82 merge; L3V3L-Z3R0 |
| origin/aitest | `b3abad3871be881e5978dc4f677d7714880c4f82` | PR #87 merge; chaehj02 |
| origin/feature/kim-dashboard-refinement | `57c77c2ba8af144ab9beffe47dbb2bc7ac1094a3` | L3V3L-Z3R0의 대시보드 기능/구조 문서 |
| feature/chaeheeju-local-target-gate | `51bb4836bccc2bd436846b758477b3107809f46e` | chaehj02의 grounded LLM 및 앞선 native/인프라 개선 |
| 기존 로컬 main (변경 금지) | `b1d61563e8fecd47d8386f0183f2224647ad60ed` | 원격 main과 별도인 기존 포인터 |
| 기존 로컬 aitest (변경 금지) | `cea8303ad40350e07d088767d570fb340e89156e` | 원격 aitest와 별도인 기존 포인터 |

브랜치 이름만으로 담당자를 추측하지 않았다. `git log --format`과 `shortlog`로 저자/실제 diff를 대조했다.
이번 main 고유 이력 4개는 `L3V3L-Z3R0 <67004336+L3V3L-Z3R0@users.noreply.github.com>`이고,
비 merge 변경은 `2f65faff99e2652213c7a024c23ea9478c7d3e1d`(인증 작업과 복원 jobs)와
`57c77c2ba8af144ab9beffe47dbb2bc7ac1094a3`(세션 관측 입력 문서)다.
`eaa8178`은 공통 기반과 tree가 같고, `d2370c2`는 PR #82 merge다.
내 쪽 main 비포함 이력 123개는 chaehj02의 로컬 저자 메일 114개와 GitHub merge 저자 메일 9개다.
공통 기반 이전에는 두 저자의 변경이 섞여 있으므로 전체 파일을 단일 저자 소유라고 주장하지 않는다.

좌/우는 `git rev-list --left-right --count LEFT...RIGHT`의 고유 커밋 수다.

| LEFT / RIGHT | 좌/우 고유 | 포함 관계 |
|---|---:|---|
| main / aitest | 4 / 47 | 서로 조상 아님 |
| main / 팀원 branch | 1 / 0 | 팀원 HEAD가 main의 조상: **전부 이미 포함** |
| main / 내 HEAD | 4 / 123 | 서로 조상 아님 |
| aitest / 팀원 branch | 47 / 3 | 서로 조상 아님 |
| aitest / 내 HEAD | 0 / 76 | aitest가 내 HEAD의 조상: **전부 이미 포함** |
| 팀원 branch / 내 HEAD | 3 / 123 | 서로 조상 아님 |

main/aitest/팀원/내 작업이 갈라지는 공통 기반은 `be25a5c93cc8d60ddde1ea94e185cbba121be23b`다.
aitest와 내 HEAD의 공통 기반은 aitest HEAD 자체다.
`git cherry -v 51bb483 origin/main`에서 위 팀원 비 merge 두 커밋은 둘 다 `+`다.
즉 내 쪽에 patch-equivalent 적용으로 중복된 변경도 없었다.
따라서 **origin/main 하나만** 후보에 반영했고 aitest 및 팀원 branch를 추가 merge/cherry-pick하지 않았다.
후보는 이 네 참조의 확인된 HEAD를 모두 조상으로 포함한다.

## 파일 충돌·의미적 호환 해결

공통 기반 이후 main 변경은 26파일, 내 쪽과 겹치는 파일은 세 개다.
`git merge-tree --write-tree 51bb483 origin/main`은 exit 0, tree
`d6315544fd2faf84948f9cd7275238194560518b`로 텍스트 충돌 0이었다.
실제 준비 브랜치의 `merge --no-ff --no-commit origin/main`에서도 unmerged entry가 없었다.
충돌 마커를 수동 삭제한 일은 없으며 아래 의미적 호환을 검토/수정했다.

| 파일/경계 | 최종 처리 |
|---|---|
| `.env.example` | 두 쪽 설정을 함께 보존. `ANALYZER_MODE=rule`, `OPENAI_PROMPT_MODE=legacy`, `HYBRID_REVIEW_ALL=false`; jobs 설정은 주석 예제·live 기본 예산 0. POSIX 호스트 요구 추가 |
| `app/config.py` | 내 `openai_prompt_mode`/`hybrid_review_all`과 팀원 jobs directory/tenant/paired/budget 필드를 모두 유지. 운영 인증 validator 유지 |
| `scripts/test_execution_mtls_runtime.py` | 내 `execute_for_runtime` 호출(관측자 quiesce/재개 계약)과 팀원 고정 진단 3종·미래 기준선/승인 시간을 함께 유지. 서버 backdate/유효기간 검사 완화 없음 |
| `app/main.py` 및 API | 팀원 jobs router와 catalog를 실제 앱에 연결. 기존 analysis/context/zero-trust/response 라우터·의존성 유지. 브라우저 catalog는 메타데이터이며 인가 근거가 아님 |
| `scripts/execution_mtls_runtime.py` | 팀원의 관측자/진단 프로세스 cgroup 메모리 384m/384m 조정 유지. 새로운 native 탐지 지표로 계산하지 않음 |
| `app/services/dashboard_jobs.py` | **발견한 실제 호환 결함 수정:** 무조건 `import fcntl` 때문에 Windows에서 jobs 비활성 상태라도 전체 앱 import가 실패했다. 선택 import 및 POSIX/O_NOFOLLOW 지원 검사 도입. 미지원 호스트에서는 디렉터리 생성 전 거부; 약한 잠금/ACL 대체 구현 없음 |
| `app/dashboard_jobs_api.py` | 미지원 호스트의 capabilities를 enabled=false/모든 action unavailable로 응답. 접수 409·조회 503으로 fail closed. 일반 API import/분석/조회는 계속 가능 |
| 대시보드 UI/가이드/시험 | jobs 불가 안내를 호스트 환경과 관리자 설정 확인으로 수정. POSIX 실행 시험의 플랫폼 범위 명시. 미지원 호스트·기본값·8종 실제 명령 생성 회귀 추가 |

## 실제 실행기와 권한 경계

작업 요청은 서버가 인증한 ADMIN만 가능하고 local/test 환경·api_key/oidc 인증 방법·설정한 tenant가 모두
일치해야 한다. POST는 `X-Dashboard-Action: 1`과 Origin 일치 검사, UUID·사유·confirmed=true·금액의
엄격한 schema를 통과해야 한다. 브라우저가 shell/명령/경로/환경 변수를 지정할 필드는 없다.
작업 id 재사용은 동일 tenant·actor·본문에만 허용하며 실행 중 다른 작업은 충돌 처리한다.
기록은 서버의 비공개 디렉터리·소유권 marker·SQLite·파일 잠금에 저장하고 중단 상태는 자동 재실행하지 않는다.

| action | 실제 호출 | 이번 검증 |
|---|---|---|
| runtime-status/up/down/recover | `python -m scripts.execution_mtls_runtime <mode> --directory <server-owned runtime/c02/dashboard-HASH>` | 고정 명령·경로 및 기존 runtime 단위 회귀. 실제 Docker 실행 0 |
| runtime-verify | `python -m scripts.test_execution_mtls_runtime --directory <별도 verify-UUID>` | 명령 연결·진단/정리 회귀. 실제 Docker 검증 0 |
| m6-mock | `python -m scripts.evaluate_m6 --output <job/report.json>` | 실제 무료 subprocess, 재시작·중복 실행 방지 및 브라우저에서 확인 |
| m6-plan | `python -m scripts.evaluate_m6 --m7-paired <서버 설정> --output-dir <job/evaluation>` | 생성 명령 확인; `--live` 없음 |
| m6-live | 같은 paired 명령 + `--live --live-max-usd <금액> --max-requests 600 --wall-seconds 3600` | 생성/상한 거절 시험만. 실제 API 호출 0; 기본 서버 예산 0 |

모든 작업은 argv 배열과 `shell=False` 기본으로 시작하며 `--purge`를 dashboard에 노출하지 않는다.
실행기 내부의 runtime 하위 경로·소유권·mTLS·승인 검증은 유지한다.
jobs의 호스트 관리자 권한은 LLM이 부여하는 권한이 아니다. LLM은 도구를 받지 않으며 설명·분류·권고만 반환한다.
근거 schema 검증/사람 검토·hybrid max-risk 병합·LLM 실패 시 rule+사람 검토를 유지했다.
실제 세션/기기/권한 신호·서명/범위/신선도·2인 승인·재사용/회수 검증은 기존 결정적 서비스가 수행한다.
LLM의 `recommended_action`이나 confidence만으로 접근 허용 또는 실제 차단을 승인하지 않는다.

## native·LLM 성능 보존 범위

원본 `51bb483`의 app/scripts Python 및 app/data/infra 679경로 중 674경로의 Git blob이 그대로다.
변경된 기존 5개는 config/dashboard API/main/실행 환경 정의/합성 실행 검증기이며 표에 설명했다.
`app/analyzers`, grounded prompt, native 판정기·학습 모델·원문/정답 fixture·평가 계약/라벨/모집단은
원본 그대로다. 새 서비스/router/UI를 추가한 것이므로 **새 native 전 행 실측을 수행했다고 주장하지 않는다.**
비교 manifest 및 전체 참조 관계는 [기계 판독 JSON](infrastructure-results/team-llm-integration-prep-20261117.json)에 있다.

기존 1,681,815행 native 결과 중 공유 감사/VPN F1 80%와 원래 6영역의 독립 95% 인수 미완료 상태를 유지한다.
기능 시험 수나 합성 UI 시험을 성능 평가 TP/분모에 더하지 않았다. 임계값·라벨·score를 조정하지 않았다.
LLM 선행 실측은 168요청·추정 $0.365284·관련 기능60건 통과였으나 합성 개발 평가다.
12건 F1 71.43→85.71%와 동시에 24건 FP5→6이므로 기본 모드 전환/오탐 비증가/전체95% 달성으로 승인하지 않는다.
[LLM 원본 실험 기록](llm-grounded-improvement-20261117.md),
[목표 미달 및 재개 조건](extra-target-evidence-gap-v128.md)을 계속 적용한다.

## 비용 없는 로컬 검증

아래 결과는 완료된 실제 로컬 실행이다. Docker/AWS/유료 LLM/8시간 soak/새 CI 실행은 0이다.

| 검증 | 실제 결과 | 공개 근거 |
|---|---|---|
| Linux Python 3.12.3 전체 pytest | **7,399 passed / 2 skipped / 실패·오류 0**, 985.70초 | [JUnit](infrastructure-results/team-llm-integration-linux-20261117.xml) |
| Windows Python 3.12.9 집중 pytest | **130 passed / 20 skipped / 실패·오류 0**, 11.69초 | [JUnit](infrastructure-results/team-llm-integration-windows-20261117.xml) |
| 관제 브라우저 | **46/46 조건 통과** | [JSON](infrastructure-results/team-llm-dashboard-browser-20261117.json) |
| 인증 작업 브라우저 | **135/135 조건 통과**; 실제 로컬 API·2인 승인·403·M6 mock·중복 방지 | [JSON](infrastructure-results/team-llm-dashboard-operations-browser-20261117.json) |
| Ruff 0.17.3 `check .` | **통과** | 로컬 `runtime/integration/ruff.log` |
| 실행기 3종 `--help` 및 Linux `pip check` | **통과** | 로컬 `runtime/integration/runner-help-and-pip-check.log` |

Linux skip 2건은 고정된 patched Linux image의 보안·출처/venv 부트스트랩 조건이 없는 호스트에서
의도적으로 제외된 시험이다. Windows skip 20건은 POSIX 호스트 작업/파일 잠금/소유권 시험이다.
Linux 전체 시험은 그 POSIX jobs 시험도 실행했다. 총 시험 수를 독립 성능 표본으로 합산하지 않는다.
Linux 경고 5건은 Starlette/Mangum deprecation, 의도적으로 잘못된 시각을 넣은 Pydantic 직렬화,
JUnit record_property 호환 경고다. Windows 경고 3건은 Starlette/Mangum deprecation이다.
결과 JSON에 정확한 시험 파일·명령·skip 사유·보고서 SHA256을 보존했다.

세 실제 실행기의 `--help` 실행으로 CLI 인자도 확인했고 Linux `pip check`를 통과했다.

검증용 Linux venv는 기존 hash-pinned `infra/runtime/requirements/test.lock`과 `browser.lock`으로 설치했다.
Windows의 Linux 전용 lock 설치는 colorama 누락 및 uvloop wheel 부재로 중단됐고 잠금 파일을 바꾸지 않았다.
Windows 시험은 기존 주 저장소 venv(Python 3.12.9 / pytest 8.4.2 / FastAPI 0.141.1 /
OpenAI 2.54.0 / cryptography 50.0.1)의 인터프리터·의존성을 재사용했다. 그 venv의 패키지를 설치/업데이트하지 않았다.
원격 패키지/Chromium 다운로드 외에 외부 모델/클라우드 서비스는 호출하지 않았다. 프로젝트 key 파일은 읽거나 출력하지 않았다.

처음 Windows 마운트에서 실행한 Linux 전체 시험은 파일 읽기 지연 때문에 SIGINT로 중단했다.
그 실행의 pytest teardown KeyboardInterrupt/KeyError는 통과 결과로 세지 않는다.
완료된 후보 `5b5708b`의 `git archive`를 Linux 디스크의
`/home/chaehj02/team-llm-prep-source-5b5708b`에 풀어 전체 시험을 새로 실행했다.
source tar SHA256은 JSON에 보존했다. 소스 snapshot에는 Git metadata와 원본 worktree의 runtime/secret을 넣지 않았다.
브라우저 두 실행은 실제 준비 checkout에서 합성 로컬 서버로 수행했고, 원본 Docker 환경과 데이터를 사용하지 않았다.

## 남은 승인 조건과 추천 순서

1. **현재는 보류:** 이 로컬 준비만 완료하고 upload/PR/새 CI/실제 main·aitest 병합은 하지 않는다.
   원래 성능 기준(종류별 P/R/F1≥95%, FPR/FNR≤5%, 새FP/기존TP손실0)과 6영역 독립 인수,
   출처·정답·시간·session/subject/device/family/pattern 분리 근거가 미충족이다.
   이번 합성 LLM/UI/단위 시험은 이 gate를 해제하지 않는다.
2. 자료/검증 근거가 확보되고 후보를 동결한 후 비용 없는 native 원래 전 행 회귀와 새 독립 인수를 진행한다.
   기본 LLM opt-in 변경은 별도 성능·설명 근거·오류/비용 검토를 통과해야 한다.
   유료 LLM/AWS/장기 soak는 이번 준비에 포함되지 않으며 필요한 경우 해당 범위를 다시 승인받는다.
3. gate 충족 후에도 최신 원격을 fetch하고 이 문서의 SHA와 대조한다. 원격이 바뀌면 본 후보의
   로컬 성공을 새 SHA에 그대로 적용하지 말고 포함 관계/충돌/권한 경계와 해당 회귀를 다시 확인한다.
4. 실제 runtime 경로는 이번에 Docker로 실행하지 않았다. 팀원이 과거에 통과시킨 mTLS 결과를
   이 새 후보의 실측으로 옮겨 쓰지 않는다. 실제 통합 승인 전 같은 동결 후보로 격리 mTLS의
   재시작/정리/복원/2인 승인/회수 및 무관 접근 경계를 다시 확인해야 한다. AWS와 8시간 soak를
   이번 로컬 시험으로 완료 처리하지 않는다.
5. 추천 순서는 **main의 이미 병합된 팀원 변경을 포함한 이 통합 후보를 aitest에서 검토/검증한 뒤,
   검증된 aitest를 main에 한 번 반영**하는 것이다. 팀원 branch를 따로 다시 merge/cherry-pick하지 않는다.
   aitest의 확인된 HEAD는 이미 후보의 조상이다. 내 원본 branch 단독을 먼저 main에 보내거나
   두 기능을 별도 중복 merge하는 흐름은 권하지 않는다.
6. 허가된 실제 통합 단계에서만 준비 branch를 upload하고 PR/CI를 시작한다. 이 문서와 로컬 시험은
   실제 CI 성공·독립 성능 승인·운영 배포/복원 승인을 대신하지 않는다.

인수자는 이 문서, JSON/JUnit/브라우저 보고서, 후보 commit의 두 부모를 함께 확인하면 된다.
기존 key 파일과 Git 제외 LLM 원문 응답은 인수인계 공개 산출물에 포함하지 않았다.
