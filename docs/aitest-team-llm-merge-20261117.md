# aitest 팀원 작업·최신 LLM 통합 승인과 검증

2026-11-17 KST · PR 제출 시점 기록 · 통합 대상 aitest · main/운영 배포 아님

사용자가 “팀원이 더 개발할 것 같진 않아서 그냥 여기서 aitest에 병합했으면 좋겠어”라고 요청했다. 기존 성능 목표 전 병합 보류는 이번 aitest 코드 통합에 한해 해제됐다. 공유 감사/VPN native F1 80%와 독립95% 인수 미완료 상태를 성능 달성으로 바꾸지 않는다.

## 포함한 작업

- 팀원 대시보드 작업은 `origin/main d2370c2`에 이미 포함돼 있어 중복으로 cherry-pick하지 않았다. 준비 후보의 Windows fcntl 호환과 미지원 호스트 jobs fail-closed 수정을 유지했다.
- [기존 팀 통합 준비](team-llm-integration-prep-20261117.md)의 `e9544e2`에 최신 LLM `ef09475`를 병합했다. 코드 통합 commit은 `f8034032baf40213e9c9a2edfff0e081b77e7230`다. 이후 보고서 commit은 코드 변경이 없다.
- `origin/aitest b3abad3`, `origin/main d2370c2`, 팀원 `57c77c2`, 최신 LLM `ef09475`, 기존 PR#88의 `cc01ef4`가 모두 이 후보의 조상임을 확인했다. PR#88 변경도 빠뜨리지 않았다.
- 충돌은 `AI_HANDOFF.md`의 동시 추가 공지1곳이었다. 팀원 준비 결과·최신 LLM 결과를 둘 다 보존하고 최신 사용자 승인을 위에 기록했다. 코드 충돌0.

기본 `ANALYZER_MODE=rule`, `OPENAI_PROMPT_MODE=legacy`, `HYBRID_REVIEW_ALL=false`는 그대로다. 선택 grounded profile은 mini 고정 버전·reasoning low·출력2400이다. LLM은 근거 설명·분류·권고를 담당하며 사람 검토, hybrid max-risk 병합, 기존의 서명/범위/신선도·실제 인가/회수 경계를 바꾸지 않는다.

[LLM 최신 실측](llm-fp-recall-review-20261117.md)은 24건 반복2회 모두 FP6→1·FN2 유지·F1 71.43→86.96%, 별도12건 FP2→0·FN0이다. 합성 개발 결과이며 native 모집단·정답·임계값은 변경하지 않았다. 이 병합 준비에서 유료 LLM/API·AWS 호출은 추가하지 않았다.

## 새 통합 후보에서 실행한 로컬 검증

| 환경 | 결과 | 근거 |
|---|---|---|
| Windows 기존 venv | 237 passed / 20 skipped / 실패·오류0 | [JUnit](infrastructure-results/aitest-team-llm-windows-20261117.xml) |
| Linux 기존 locked venv | 257 passed / 0 skipped / 실패·오류0 | [JUnit](infrastructure-results/aitest-team-llm-linux-20261117.xml) |
| Ruff check . | 통과 | 로컬 실행 |

같은17개 시험 파일로 대시보드 인증/jobs·API·LLM 입력과 오류/회귀 비교·보안/제로트러스트 API·정책·실행 근거 유지·monitored 회귀를 묶어 실행했다. Windows의 skip20건은 POSIX 소유권/파일 잠금/jobs 시험이며 Linux에서는 모두 실행했다. Linux는 동결된 `git archive f803403`을 `/home/chaehj02/aitest-team-llm-f803403`에 풀어 검사했다. 원본 worktree와 실제 비밀 설정은 복사하지 않았다.

이전 후보 `5b5708b`의 Linux 전체7399건·브라우저46/135건은 [준비 문서](team-llm-integration-prep-20261117.md)의 과거 근거로 보존한다. 이를 최신 후보의 전체 실측으로 옮겨 쓰지 않는다. 최신 전체 pytest·Docker·Lambda·mTLS/HA/DB/선정·브라우저는 이 통합 PR의 **정확한 HEAD에서17개 CI 모두 성공 확인 후에만 병합**한다. 실제 실행 SHA·job별 결과와 병합 SHA는 GitHub PR 기록이 기준이다. 로컬에서는 Docker 통합을 중복 실행하지 않았고 8시간 soak도 실행하지 않았다.

[참조 SHA·로컬 검증 JSON](infrastructure-results/aitest-team-llm-merge-20261117.json)을 함께 제공한다. 기본 브랜치에 직접 push하거나 CI 실패를 건너뛰어 강제 병합하지 않는다. 코드 통합 승인은 성능 목표나 운영 배포 승인을 대신하지 않는다.
