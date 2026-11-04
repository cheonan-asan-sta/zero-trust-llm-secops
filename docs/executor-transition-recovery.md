# 관리 호스트 전환 실행기의 중단과 명시적 재개

2026-11-04 · I4·I6/C04 · 로컬 Docker 시험 프로필 전용

[관리 호스트·전환 기록 이중화](executor-host-high-availability.md)는 실행 호스트를 바꿨지만, 전환을 수행하던
운영자 프로세스가 종료되면 lock과 부분 owner 설치 상태를 수동 조사해야 했다. 이번 후속은 **같은 고정
컨테이너의 PID 1을 다시 시작해 같은 전환을 이어가는 기능**을 추가한다. 이전 PR #15는 `aitest`
`ee8067b`에 병합했고 병합 후 검사도 통과했다. 이전 결과는 당시 코드와 범위로 유지한다.

## 달라진 제어 경계

- 전환은 외부 Windows 프로세스가 직접 이어 쓰는 대신, 신뢰된 일회성 operator 컨테이너가 수행한다.
  고정 이름의 단일 컨테이너와 생존 journal 볼륨의 Linux flock으로 재시작을 직렬화한다.
- operator의 컨테이너 ID·이미지·명령·환경·UID·socket/공개 볼륨·네트워크·자원 제한을 대조한다.
  실행 중이거나 실행 중 명령이 남아 있으면 정지/삭제해 빼앗지 않는다. 기록된 ID가 바뀌면 재개를 거부한다.
- 공개 `executor-transition.json`을 다음 행동 전에 기록하고 다른 journal에 먼저 fsync한 뒤 생존 사본에
  반영한다. 정상 관리 실행기는 양쪽 전환 기록이 같고 완료되기 전에는 새 owner가 일치해도 작업을 거부한다.
- 최초 의도 기록 전에 생성된 컨테이너만 남아도, 고정 사양과 변경되지 않은 원래 owner/descriptor를
  확인한 뒤 그 컨테이너를 시작한다. 미완료 actor 자체가 제거됐으면 임의의 새 actor로 대체하지 않는다.
- 재개할 때 이전 실행기 정지와 남은 작업을 다시 확인한다. operator가 띄운 임시 작업도 별도 표식과
  고정 이미지로 확인해 정리한다. 기존 표식 없는 DinD는 고정 이름·ID·이미지로 직접 검사한다.

operator도 부모 Docker socket을 가진 관리자다. UID 10001·network none·읽기 전용 rootfs가 socket의
관리자 권한을 줄이지는 않는다. socket·공개 journal만 상시 마운트하고 vault나 offline Root/백업 키를
추가하지 않는다. 온라인 CA·leaf의 기존 socket/vault 차단 경계는 유지한다.

## 영속 단계와 반복 실행

| 단계 | 재개 시 수행하는 일 |
|---|---|
| `intent` | 원래 topology·목표·다음 세대 이름·actor ID를 먼저 기록. 두 이전 실행기를 봉쇄하고 남은 작업 0 확인 |
| `fenced` | 봉쇄 뒤 공개 프로필/관리 전환/클러스터/조정기 캐시의 지문 확정. 전환 표식이 일치하는 새 볼륨만 생성/재사용 |
| `volumes` | 같은 원본 지문과 일치하는 부분 사본만 이어 복제. 다른 내용·예상 밖 파일·바뀐 원본은 덮어쓰지 않음 |
| `copied` | 양 owner를 같은 새 실행 epoch로 설치. 생존 owner는 원래/새 역할만, 새 볼륨은 빈 상태/새 역할만 허용 |
| `owners` | 생성 의도와 사양이 같은 새 실행기만 구성. 생성 후 ID 저장 전에 종료했으면 전환 표식·전체 사양으로 같은 객체 채택 |
| `workers` | 같은 두 실행기 ID의 클러스터 정보를 양 journal에 공개. 실행기는 여전히 pending 전환 때문에 정상 명령 거부 |
| `published` | 시험의 명시적 폐기 모드에서만 옛 실행 볼륨 제거. 일반 전환은 옛 볼륨 격리 보존 |
| `retired` | 동일 영수증과 완료 기록을 양쪽에 확정 |
| `complete` | 현재 owner·클러스터·고정 실행기 확인 후 동일 결과만 반환. 복제·owner 재설치·기존 실행기 봉쇄를 반복하지 않음 |

복제 대상은 공개 실행 메타데이터다. 관리 cell의 vault·토큰 소비/폐기·witness·백업을 이전 시점으로 복원하지
않는다. 특히 완료 후 새 업무 상태가 생기면 `complete` 재개는 이를 보존한다. 기존 관리 전환의 `opening`
이후 초기화 금지도 유지한다. 불확실한 CA 발급 POST를 일반 재전송하는 기능이 아니다.

SHA256은 우발적 손상 검출이며 악의적인 Docker 관리자를 막는 서명이 아니다. 두 사본은 quorum이 아니고
높은 epoch 자동 선택·자동 선출을 제공하지 않는다. 최초 peer-only 저장 이후의 재개는 같은 생존 사본과
같은 actor가 수행하며, 허용된 부분 사본과 고정 객체를 대조한다. 임의로 파일/lock을 지워 차단을 풀지 않는다.

## 로컬 재현과 사용

```powershell
.venv\Scripts\python.exe -m scripts.test_executor_transition spec-check --directory runtime/c02/c04/operator-contract
.venv\Scripts\python.exe -m scripts.test_executor_transition --directory runtime/c02/c04/operator-reproduce
.venv\Scripts\python.exe -m pytest tests/test_executor_transition.py tests/test_executor_hosts.py -q
```

새 시험 이미지를 구성하는 방식이며 구 이미지/실제 운영 클러스터의 인플레이스 이전을 뜻하지 않는다.
실행기는 해당 프로젝트 자원만 정리한다. 정리된 결과 디렉터리를 살아 있는 클러스터로 사용하지 않는다.
운영 명령 예시는 `<project>`를 실제 프로젝트 ID로 바꾸고 공개 anchor/결과 경로를 준비한 후 사용한다.

```powershell
# 정상 호스트 전환: 내부적으로 고정 operator를 실행하고 완료 뒤 확인해 제거
.venv\Scripts\python.exe -m scripts.executor_cluster takeover --descriptor runtime/c02/<project>-console/cluster.json --site b
# 전환 도중 중단: 원래 목표 site와 명시한 생존 볼륨, 공개 anchor로 동일 actor 재개
.venv\Scripts\python.exe -m scripts.executor_cluster resume-takeover --anchor runtime/c02/<project>-console/anchor.json --site b --journal <project>-executor-b-g1-journal --owner <project>-executor-b-g1-owner --descriptor runtime/c02/<project>-console/cluster.json
```

`resume-takeover`는 관리 cell 전환의 `resume`과 다르다. 먼저 실행 호스트 전환을 완료한 뒤 남아 있는
`management-transition.json`의 같은 전환을 기존 `resume`으로 이어간다. actor가 아직 실행 중이면
완료를 기다린다. actor ID/사양 변경·사본 충돌·불명확한 작업·유실한 미완료 actor는 봉쇄 상태에서 조사한다.

## 검증과 남은 범위

신규 단위 사례는 **66개**다. Windows 전체 **1,152 통과·2 건너뜀**, Linux Docker 전체 **1,154 통과**와
Ruff를 확인했다. Windows의 두 symlink 검사는 OS 권한을 늘리지 않고 Linux에서 실행했다. 기존 의존성
경고는 Windows 3개·Linux 2개이며 이번 작업에서 해당 의존성이나 탐지 기준은 바꾸지 않았다.

최종 사전 실험은 기존 실행기 검사 **8개**와 operator 검사 **14개**를 통과했다. 최초 의도 기록 전
컨테이너만 남긴 경우부터 새 콘솔로 재개하고, 아래 8개 지점에서 같은 actor의 실제 exit 73을 확인했다.

| 실제 종료 지점 | 확인하는 조건 |
|---|---|
| `after_intent` | 양 의도 기록 이후 중단. 일반 관리 명령과 두 번째 operator 생성 거부 |
| `after_fence` | 이전 실행기·작업 정지 이후 재개. 임의의 새 실행 epoch 생성 없음 |
| `volume_created` | 볼륨 생성 직후 종료. 같은 OPID·종류·세대·소유 표식의 객체만 재사용 |
| `after_copy` | 공개 metadata 복제 이후 같은 단계에서 재개 |
| `owner_a_written` | 양 owner 중 하나만 새 역할인 상태에서 재개. 전환 중 정상 작업을 열지 않음 |
| `worker_created` | 새 실행기 생성 뒤 ID 기록 전 종료. 전체 사양을 대조해 동일 컨테이너 ID 채택 |
| `after_publish` | 새 역할·실행기가 일치해도 완료 전에는 정상 명령 거부 |
| `after_complete` | 완료 뒤 새 공개 프로필 상태를 작성. 최종 응답 재개·actor 정리 후 재조회가 이를 보존 |

새 CA 환경 1회에서 **operator 30개·실행기 15개·관리 저장소 제거 2개**, 총 **47개** 통합 검사를 통과했다.
operator 실제 종료는 양방향 각 8회로 **16회**, 별도 관리 cell 전환 프로세스 종료는 **2회**다. 매 재개와
완료 후 조회를 별도 Windows 콘솔 프로세스로 수행해 본 실행에서 **20회**의 새 콘솔 호출을 확인했다.
준비부터 검증 종료까지 1,417.142초이며 의도적인 종료/재시작이 포함된 한 표본이다. 전환별 RTO/RPO나
동일 조건 성능 비교로 사용하지 않는다.

- 첫 전환은 준비된 동일 Root 키 후보와 관리 전환 ID를 보존했다. 이어 Root/issuer/JWK epoch 1을 완료하고
  이전 JWK 66개 × CA 2대의 신선한 요청 132건을 거부했다. 현재 인증서의 mTLS 갱신은 성공했다.
- 두 번째 전환은 `opening` 상태에서 수행했다. operator 완료 후 마지막 응답 재개 전에 새 JWT를 만들어
  실제 소비하고, 같은 actor의 완료 재개 후 그 토큰의 재사용 거부를 확인했다. 기존 관리 전환의 재개 전
  추가로 소비한 다른 새 토큰도 관리 전환 재개 후 재사용을 거부했다.
- 기준 소비 토큰 약 629.538초·폐기 인증서 약 930.538초가 남은 상태에서 재사용/갱신을 거부했고 새 nonce는
  성공했다. 생존 백업/별도 키를 최신 보안 checkpoint와 대조했다. CA DB 전체 cold restore 재실행은 아니다.
- 같은 actor/worker/전환 ID를 재사용했다. 최종 관리/실행 epoch 각각 3·활성 a·양 저장소 세대 2다.
  옛 실행 볼륨 4개·관리 cell 볼륨 18개를 삭제했고 고정 서비스 ID는 첫 전환 2개·두 번째 6개를 검사했다.

[공개 지문·검사·정리 원자료](infrastructure-results/c04-executor-transition-windows-20261104.json)에 입력
**111개**, 양 이미지 안의 **91개 파일씩**, 외부 설정/시험 입력 **20개**와 새 단위 파일 지문을 남겼다.
Windows 원본 지문과 Git LF 지문을 구분한다. 초기 정상 경로/이전 좁은 사전 실험은 최종 성공 합계에서
제외한다. 최종/예비/단위 **5개 프로젝트** 범위를 별도로 재조회해 컨테이너·볼륨·네트워크·이미지 태그
잔여 0을 확인했다. 기존 forensics 컨테이너의 ID/실행 상태와 사용자 ZIP 두 개의 지문은 보존됐다.
AWS·유료 LLM·실계정·OS 신뢰 저장소 변경은 없었다.

통합 시험 중 동료의 지속 관측 수집기 PR #16이 `aitest`에 병합됐다. 위 CA 캠페인의 기준은 `ee8067b`이며,
수집기 추가 `a908270`을 보존해 합친 뒤 전체 회귀를 다시 수행했다. **Windows 1,223 통과·2 건너뜀**,
**Linux Docker 1,225 통과**와 Ruff를 확인했다. 기존 캠페인 소스/새 단위 파일 112개는 병합 전후 원본과
Git 지문이 같았다. 추가 수집기 Python 파일 5개를 포함한 117개 입력도 지문으로 남겼고, 결합 단위 이미지의
116개 존재 파일과 대조했다. 이미지에 복사되지 않은 1개는 `.gitattributes`다.

수집기는 새 CLI/테스트에서 참조하는 독립 추가이며 기존 CA 실행 의존 파일은 바뀌지 않았다. 이 때문에 CA
캠페인은 위 기준/이미지의 결과로 유지하고 결합 전체 회귀·이미지 대조를 별도로 기록한다. 결합 단위 시험
범위를 추가한 **6개 프로젝트** 모두 잔여 자원/이미지 태그 0이다. 이번 변경이 동료 수집기의 구현이나
탐지 품질 개선을 수행했다고 주장하지 않는다.
테스트의 fault 파일은 일회성 종료 지점을 기록하는 공개 시험 자료이며 보안 권한 근거로 사용하지 않는다.
동일 PC/부모 Docker·생존 journal·고정 actor 컨테이너가 남는 조건이다. 물리 서버/전체 데몬·디스크 손실,
전원 장애 fsync 보장, actor 컨테이너까지 제거된 중단 복구, 악의적 관리자, 운영 SLA/RTO/RPO와 독립
팀원 검토는 별도다. 앱·탐지·정책·개선 전 평가 기준과 전체 주간/제출 일정은 바꾸지 않는다.
다른 authority/leaf 작업의 불확실한 중단은 기존 busy 차단을 유지하며 이 actor 재개가 임의로 해제하지 않는다.
