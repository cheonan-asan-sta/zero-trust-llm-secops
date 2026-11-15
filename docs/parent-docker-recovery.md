# 부모 Docker 데몬 재시작 후 전환 복구

2026-11-04 · I4·I6/C04 · 기존 [컨테이너 유실 복구](actor-container-recovery.md)의 후속

11/5 후속 [CA·DB·leaf 서비스 복구](service-daemon-recovery.md)는 아래 worker/전환 복구와 별도 명령이다.
같은 서비스/저장소·최신 보안 checkpoint·기존 DB 역할/동기 복제를 확인하고 접속을 순서대로 연다.
아래 11/4 실험은 당시 actor/worker·합성 marker 범위의 역사적 결과로 유지한다.

부모 데몬이 재시작되면 전환 actor뿐 아니라 이미 만들어 둔 새 worker도 멈출 수 있다. 이번 변경은
**같은 Docker 데이터 저장소·이미지·볼륨이 살아 있는 경우** `recover-daemon`으로 같은 전환을 재개한다.
Docker Desktop이나 데몬 자체를 재시작하는 운영 명령은 추가하지 않는다. 복구는 명시적이며 증거가
충돌하거나 작업이 아직 살아 있으면 진행을 거부한다.

## 재시작 전에 보관하는 공개 식별 기록

정상 클러스터에서 `seal-daemon`은 프로젝트·이미지 ID·경로·socket 그룹의 공개 anchor와 Docker Engine ID를
`executor-daemon-seal-1` 파일에 저장한다. 정상 owner·cluster 쌍과 worker·일반 조회를 먼저 확인한다.
이 파일은 Docker 데이터 영역 밖의 신뢰된 운영자 저장소에 보관한다. 복구 시 다른 데몬으로 잘못 연결했거나
데이터 영역이 새로 초기화됐으면 볼륨을 읽거나 worker를 시작하기 전에 거부한다. 없어진 식별 기록을
장애 이후 현재 값으로 자동 재발급하지 않는다.

checksum과 Engine ID는 인증 수단이나 악의적 관리자·전체 디스크 snapshot rollback 방어가 아니다.
현재 Docker 접근 자격과 공개 식별 기록을 보호하는 운영자 신뢰는 계속 필요하다.

## 단계별 복구

| 상황 | 허용 동작 |
|---|---|
| 미완료 actor가 같은 ID로 정지 | 전체 actor 사양·양 전환 기록·현재 owner·원본 지문과 old/new worker의 정지를 확인한 뒤 같은 actor를 재개 |
| 미완료 actor도 유실 | 같은 검증 뒤 기존 checkpoint-bound 대체 경로 사용. 별도의 epoch/키 계획을 만들지 않음 |
| 새 worker 생성이 기록된 단계 | owner 쌍과 양 worker 고정 ID/사양·전환 표식을 전부 검증한 뒤 정지한 worker만 시작. 생성 단계를 건너뛴 published/retired 재개도 처리 |
| 이미 완료 | 양 완료 기록·cluster·현재 owner·양 worker ID/사양을 먼저 대조. 멈춘 worker만 시작하고 socket의 새 데몬 접근을 확인한 뒤 같은 완료 영수증 반환 |
| 완료 복구 중 시작 응답 유실 | 이미 실행 중인 검증된 worker는 유지하고 멈춘 peer만 시작. 원본 profile 복제·owner 재설치·키/epoch 재생성 없음 |
| live-restore로 actor/미완료 worker가 생존 | 자동 kill/lease 삭제/권한 강탈 없이 거부. 운영자의 독립적인 작업 조사·정지 확인이 먼저 필요 |
| worker가 `Running=true`이면서 paused | 완료 단계라도 양 worker 상태 확인에서 거부. 멈춘 peer도 먼저 시작하지 않으며 자동 unpause하지 않음 |
| 사본 불일치·다른 ID/이미지·모호한 상태 | 높은 epoch나 최신 시각으로 선택하지 않고 조사 대상으로 거부 |

완료 경로에서는 profile·보안 기록을 예전 snapshot으로 덮어쓰지 않는다. worker의 Unix socket bind는
정지 컨테이너를 다시 시작하면서 현재 socket에 연결한다. live-restore된 컨테이너의 오래된 연결을
자동으로 신뢰하지 않는다. 재시작된 worker도 기존 Store의 양 owner·완료 marker 검사를 계속 적용한다.
완료와 새 전환이 경합해도 고정 ID·owner/marker 재검증이 실패하면 성공을 반환하지 않는다.
이 명령의 대상은 전환 actor와 유지보수 worker다. 부모 데몬과 함께 멈춘 CA/DB/leaf 등 전체 서비스의
자동 재가동은 수행하지 않는다. 해당 서비스와 관리 전환 재개는 기존 절차에서 고정 ID·보안 checkpoint를
별도로 확인해야 하며, 서비스가 멈춘 것을 불확실한 업무 요청 재시도 허가로 해석하지 않는다.

## 운영 명령

아래는 살아 있는 새 시험 프로필의 예다. `<project>`·생존 site/세대·파일 경로를 실제 값으로 바꾼다.
정리된 과거 실험 디렉터리는 실행 중인 클러스터가 아니다. 비공개 Docker 접속 자격은 기존 환경/context로
설정하고 seal 파일에 넣지 않는다.

```powershell
# 정상 상태에서, 장애 전에 공개 식별 기록 보관
.venv\Scripts\python.exe -m scripts.executor_cluster seal-daemon --descriptor runtime/c02/<project>-console/cluster.json --daemon-seal runtime/c02/<project>-console/daemon-seal.json

# 같은 데이터 영역의 데몬이 돌아온 뒤 명시적 복구
.venv\Scripts\python.exe -m scripts.executor_cluster recover-daemon --anchor runtime/c02/<project>-console/anchor.json --daemon-seal runtime/c02/<project>-console/daemon-seal.json --site b --journal <project>-executor-b-g1-journal --owner <project>-executor-b-g1-owner --descriptor runtime/c02/<project>-console/cluster.json

# 별도 격리 데몬에서만 실제 재시작을 수행하는 재현 실험
.venv\Scripts\python.exe -m scripts.test_executor_daemon_restart --directory runtime/c02/c04/daemon-reproduce
.venv\Scripts\python.exe -m pytest tests/test_executor_daemon_recovery.py tests/test_executor_transition.py tests/test_executor_actor_loss.py -q
```

의도 기록이 없거나 일반적인 peer-only 단계 저장으로 사본이 달라졌으면 이 명령이 임의로 작업을
추정하지 않는다. 기존 고정 후보의 명확한 식별자 재개와 일반 사본 충돌은 구분하며, 모호한 경우는
조사 대상으로 남긴다. 새 모듈이 없는 구 이미지에 환경 변수만 붙이는 업그레이드는 지원하지 않는다.

## 실제 검증 범위

최종 프로젝트 `c02-66f1bc36252c`는 2026-11-04 14:10:11~14:18:42 UTC에 실행했다.
환경 준비를 포함한 전체 시간이며 운영 RTO 측정으로 해석하지 않는다. 공개 원자료는
[`c04-parent-daemon-windows-20261104.json`](infrastructure-results/c04-parent-daemon-windows-20261104.json)에 기록한다.

| 검사 | 실제 결과 |
|---|---|
| 실제 dockerd 재시작 | 12회. 모든 경우 supervisor PID/Engine ID 유지, dockerd PID 변경 |
| 살아 있는 actor의 중단 지점 | 의도 기록·봉쇄·부분 볼륨 생성·복제·한쪽 owner 기록·worker 생성·게시·완료 8개 지점 |
| 같은 전환 | 첫 작업에서 actor/전환 ID 유지, epoch 한 번만 증가, 생성 응답 미기록 worker의 같은 ID 채택 |
| 완료 복구 | actor가 없어도 고정 worker만 복원. 새 profile 표식과 같은 영수증 보존, 한 worker 시작 응답 유실 재시도 |
| 일시정지 | 실제 pause된 `Running=true` worker가 있으면 정지한 peer도 시작하지 않고 거부. 명시적 unpause 후 복구 |
| live-restore | 실제 actor와 양 worker의 생존 확인. actor 생존 거부·actor 정지 후 worker 생존 거부·명시적 정지 후 같은 전환 재개 |
| 최종 역할 | 두 전환 뒤 실행 epoch 3·A 활성·양 세대 2. 재시작 횟수만큼 새 epoch를 만들지 않음 |
| 합계·소스 | 최종 검사 16개 통과. 앱·스크립트 Python 94개 지문을 graph/executor 이미지 양쪽에서 대조 |

초기 이미지 ID 준비 실패 1회, live-restore 시험 준비의 잘못된 생존 가정을 확인한 전체/부분 진단 2회,
paused 보강 전 통과한 15검사/12재시작 1회는 각각 별도 원자료/정리 상태로 보존한다. 최종 합계에 더하지
않으며 생산 코드의 생존 작업 거부 기준을 낮추어 통과시키지 않았다. 최종 회귀·전체 소유 범위 정리와
Git raw/LF 지문 대조는 공개 원자료에 함께 기록한다.

신규 단위 검사 27개를 포함한 전체 회귀는 **Windows 1,381 통과·2 건너뜀·3 경고(199.28초)**,
**Linux Docker 1,383 통과·2 경고(123.64초)**와 Ruff 통과다. 건너뜀은 기존 Windows symlink 검사이며
경고는 기존 라이브러리 사용 중단 알림이다. 잘못된 seal/다른 데몬의 조기 거부, 생존 프로세스·paused
거부, 양 사본/owner/worker 선검증, 부분 시작 재시도와 기존 PID-1/유실 복구 회귀를 확인했다.

실행 코드 기준은 `b9c50ad`다. 최종 단위 이미지의 입력 136개 중 포함된 135개 지문을 대조했으며,
미포함 `.gitattributes` 1개를 구분했다. 현재 파일과 커밋의 Git blob을 raw/LF 두 지문으로 대조했고
PR #20 기준 앱/탐지 정책 변경은 없다. 앞선 시도·최종 실험·단위 이미지의 6개 소유 범위에서 컨테이너·
볼륨·네트워크·이미지 태그 잔여 0을 별도로 확인했다. 기존 `pod-forensics-20261025-control-plane`의
같은 ID/실행 상태와 ZIP 두 개의 SHA256은 보존했다. private runtime/환경 파일은 커밋하지 않는다.

### 동료 수집기 PR #21 결합 검증

위 데몬 실험 뒤 `aitest`에 병합된 PR #21 `e240c59`를 `e46ec18`로 보존 결합했다. 새 수집기 입력 회전·
유지보수 변경을 포함한 최신 전체 회귀는 **Windows 1,465 통과·2 건너뜀·3 경고(350.36초)**,
**Linux Docker 1,467 통과·2 경고(223.16초)**와 Ruff 통과다. 최신 입력 140개 중 단위 이미지의
139개 지문을 대조했고(미포함 `.gitattributes` 1개), 작업 파일/Git blob의 raw/LF 지문도 일치했다.

데몬 핵심 코드 8개는 실제 실험 때와 동일하다. 동료가 바꾼 캠페인 입력은 `collector_spool.py`와
수집기/mTLS 스크립트 3개이며, 당시 94개 중 나머지 90개는 그대로다. 옛 실제 데몬 이미지/지문을 최신 앱으로
바꿔 기록하지 않는다. 최신 결합 회귀와 새 입력은 공개 자료의 `integration_validation`에 따로 보존했다.
앱 변경은 PR #21의 기여이며 최신 기준 `e240c59` 대비 이번 작업의 앱 변경은 없다. 새 수집기를 실제 데몬
재시작 캠페인으로 다시 실행했다는 주장도 하지 않는다. 추가 단위 이미지를 포함한 총 7개 소유 범위의
컨테이너·볼륨·네트워크·이미지 태그 잔여 0과 기존 Docker/ZIP 보존을 다시 확인했다.

시험기는 사용자 Docker Desktop을 재시작하지 않는다. 별도의 privileged DinD 안에서 PID 1 supervisor와
`/var/lib/docker` 볼륨을 유지한 채 자식 dockerd에 SIGTERM을 보내고 새 프로세스로 시작한다. 동일 supervisor,
달라진 dockerd PID, 유지된 Engine ID와 고정 actor/worker를 대조한다. 시험용 관리 API는 호스트
`127.0.0.1`의 임시 포트에만 노출하고 정리한다. 인증 없는 이 시험 endpoint를 운영 구성으로 제시하지 않는다.

이번 실제 데몬 실험의 완료 후 보존 검사는 합성 공개 profile marker다. 새 CA 발급·토큰 소비·폐기 실험으로
바꾸어 부르지 않으며, [직전 실제 CA 캠페인](actor-container-recovery.md)의 43개/132거부 결과는 역사적으로
보존한다. PR #19의 별도 상시 mTLS 프로필에 C04 자동 갱신을 통합하는 후속 범위도 유지한다.

같은 물리 PC·신뢰된 부모 데몬과 데이터 영역·생존 journal/이미지가 필요하다. 데몬 재시작은 물리 호스트/
디스크 유실·전원 장애 내구성·quorum/자동 선출·전체 cold restore·운영 SLA/RTO/RPO 보장을 뜻하지 않는다.
SIGKILL/전원 차단의 모든 시점이나 일반 업무 POST 재전송·임의 busy 해제도 이번 보장에 포함하지 않는다.
socket은 관리자 권한이며 온라인 CA/leaf에 socket/vault를 추가하지 않는다. AWS·유료 LLM·실계정·OS 신뢰
설정이나 기존 탐지/평가 기준을 변경하지 않는다. 도구 보조 실행과 팀원 독립 검토 완료는 구분한다.
