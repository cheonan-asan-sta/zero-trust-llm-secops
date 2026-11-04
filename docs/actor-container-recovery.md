# 전환 실행기 컨테이너 유실 복구

2026-11-04 · I4·I6/C04 · 새 로컬 시험 이미지/프로필 대상

기존 [전환 실행기 재개](executor-transition-recovery.md)는 같은 컨테이너가 정지한 경우만 이어갔다.
이번 후속은 **기록된 실행기 컨테이너가 완전히 삭제된 경우**, 남은 공개 전환 기록과 현재 상태를 확인한
후 같은 전환을 대체 실행기에서 이어간다. 명령은 `recover-takeover`다. 기존 `resume-takeover`는
유실한 미완료 실행기를 조용히 새 객체로 바꾸지 않는다.

## 복구를 허용하는 근거

| 확인 항목 | 요구 조건 |
|---|---|
| 공개 anchor | 프로젝트·graph/executor 이미지 ID·논리 경로·socket 그룹이 원래 요청과 일치 |
| 남은 전환 기록 | checksum/스키마·원래 topology·목표·계획된 다음 세대·진행 단계가 유효 |
| 기존 실행기 부재 | 현재 기록된 ID와 모든 이전 실행기 ID가 부모 Docker 전체에서 부재. 이름 변경/정지 상태도 부재가 아님 |
| 상대 사본 | 지정된 생존 사본과 같은 기록. 큰 epoch나 최신 시각만으로 선택하지 않음 |
| 실제 owner | 단계별 원래/새 역할만 허용. 양 owner 설치 이후에는 모두 새 역할이어야 함 |
| 부분 생성 자원 | 단계상 확정된 예정 볼륨의 종류·세대·전환 표식, 예약 worker의 고정 ID/실행 사양이 일치. 그 이전 생성 응답 유실은 해당 단계가 같은 소유 표식을 재확인한 뒤 채택 |
| 공개 원본 지문 | 봉쇄 시 확정한 프로필/관리 전환/캐시가 유지. 공개 클러스터는 해당 단계에서 허용된 원래/계획된 값만 허용 |

이 검사는 대체 컨테이너를 만들기 전에 수행하고, 대체 실행기가 생존 볼륨의 Linux flock을 획득한 뒤
다시 수행한다. 고정 컨테이너 이름은 동시 생성자를 직렬화하고 flock은 같은 저장소에서의 실행을 직렬화한다.
실행 중인 기존 프로세스를 정지/삭제해 권한을 빼앗지 않는다. 알려지지 않은 같은 이름의 객체도 덮어쓰지 않는다.

## 바꾸는 것은 실행기 식별자뿐

대체 요청은 원래 요청 digest·이전 actor ID·확인한 기록 digest·새 nonce에 연결된다. 대체 컨테이너의
환경/명령·이미지·전환/복구 표식·마운트·UID·권한·네트워크·자원 제한을 확인한다. 이 공개 정보 자체가
새 보안 권한을 부여하지는 않으며, 실제 저장소/소유 상태와의 재검증이 필요하다.

처음 대체할 때 기록을 `executor-transition-2`로 확장해 `actor.predecessors`에 이전 ID를 남긴다.
전환 ID·목표·진행 단계·관리/실행 epoch·키 후보·예약 자원 이름/ID·봉쇄 증거는 유지한다. 식별자 변경을
상대 journal에 먼저 저장/fsync하고 생존 사본에 반영한 뒤 기존 전환을 이어간다. 새 epoch를 매번 만들지 않는다.
기존 스키마 1 기록은 계속 읽으며, 한 전환의 대체 이력은 최대 16개로 제한해 초과 시 조사를 요구한다.

생성 후 식별자 기록 전에 콘솔 응답을 잃었으면 동일한 복구 표식/사양의 고정 후보를 확인해 이어간다.
상대 사본에 식별자 변경만 먼저 저장된 경우에는 **그 정확한 고정 후보**에 해당하는 변경만 마저 확정한다.
일반적인 사본 불일치나 그 도중 후보까지 다시 유실된 불명확한 상황은 자동으로 추측하지 않는다.

## 새 보안 상태를 보존하는 완료 경로

완료한 실행기까지 삭제돼도 현재 owner·클러스터·고정 worker를 확인하고 같은 영수증만 반환한다.
새 actor 생성, metadata 복제, owner 재설치, 기존 관리 실행기 봉쇄를 반복하지 않는다. 완료 이후 새로
소비한 토큰·인증서 폐기·보안 checkpoint를 과거 값으로 되돌리지 않는다. 업무 POST의 일반 재전송이나
다른 authority/leaf 작업의 불확실한 busy 상태 해제도 제공하지 않는다.

## 명시적 사용과 로컬 재현

아래 `<project>`를 실제 프로젝트 ID로 바꾸고 살아 있는 새 시험 클러스터의 공개 anchor와 생존 볼륨을 지정한다.
시험 실행기가 이미 정리한 결과 디렉터리는 살아 있는 클러스터가 아니다.

```powershell
# 기존 컨테이너가 정지한 경우
.venv\Scripts\python.exe -m scripts.executor_cluster resume-takeover --anchor runtime/c02/<project>-console/anchor.json --site b --journal <project>-executor-b-g1-journal --owner <project>-executor-b-g1-owner --descriptor runtime/c02/<project>-console/cluster.json
# 컨테이너가 실제 유실된 경우: 증거 대조 후 명시적 대체
.venv\Scripts\python.exe -m scripts.executor_cluster recover-takeover --anchor runtime/c02/<project>-console/anchor.json --site b --journal <project>-executor-b-g1-journal --owner <project>-executor-b-g1-owner --descriptor runtime/c02/<project>-console/cluster.json

.venv\Scripts\python.exe -m scripts.test_executor_actor_loss spec-check --directory runtime/c02/c04/actor-loss-contract
.venv\Scripts\python.exe -m scripts.test_executor_actor_loss --directory runtime/c02/c04/actor-loss-reproduce
.venv\Scripts\python.exe -m pytest tests/test_executor_actor_loss.py tests/test_executor_transition.py -q
```

의도 기록 자체가 없으면 원래 요청을 복구했다고 추정하지 않는다. 권한 작업은 의도를 기록한 뒤 수행하므로,
현재 topology/owner가 그대로인지 확인한 새로운 명시적 `takeover`와, 기존 기록의 `recover-takeover`를 구분한다.
복구 기능이 없는 구 이미지에 새 환경 변수만 붙이는 이전은 지원하지 않는다.

## 검증과 한계

사전 실험 `c02-4ed0e3e1dd6e`는 기존 실행기 계약 8개와 유실 복구 검사 12개를 통과했다.
`after_intent`·`after_fence`·`volume_created`·`after_copy`·`owner_a_written`·`worker_created`·
`after_publish`·`after_complete`에서 실제 종료한 컨테이너를 ID로 삭제했다. 이름 변경된 기존 actor 거부,
식별자 기록 전 생성된 고정 후보의 채택, 같은 작업/epoch·예약 worker와 완료 후 공개 상태 보존을 확인했다.
이 실행은 동료 PR #19 결합 전/검사 표기 정리 전이며 최종 CA 실험 합계에 더하지 않는다.

신규 단위 34개는 단계별 식별자 이전·이력 제한·stale proof·사본/owner/원본/부분 볼륨 충돌·
동일 후보의 peer-only 식별자 기록·환경/표식 결합과 영수증을 검증한다. 기존 PID-1 재개 검사는 유지한다.
동료의 상시 mTLS PR #19를 보존 결합했고, 앱/탐지/정책 변경은 없다. 결합 시 Windows 경로 비교 실패는
테스트 기대값의 `Path` 표현으로 수정했다(Linux에서는 같은 값). 기존 HTTP 검사에서 발생한
WinError10053은 코드를 바꾸지 않은 단독 재실행에서 통과했으며 최종 전체 결과와 따로 기록한다.

결합 전체 회귀는 **Windows 1,354 통과·2 건너뜀·3 경고(232.99초)**,
**Linux Docker 1,356 통과·2 경고(139.68초)**와 Ruff 통과다. Windows 건너뜀은 기존 symlink 검사이며
경고는 기존 라이브러리 사용 중단 알림이다. 결합 단위 이미지에서 입력 126개 중 포함된 125개 지문을
대조했다(미포함 `.gitattributes` 1개). 기준 PR #19 대비 앱 변경은 없고 경로 기대값 3곳만 호환 수정했다.
새 CA 실험은 기존 C04 관리 graph를 대상으로 한다. PR #19의 별도 9서비스 상시 mTLS 프로필에
C04 자동 갱신·교체를 통합했다는 뜻은 아니며 해당 후속 범위는 유지한다.

### 최종 새 CA 실험

[`c04-actor-container-loss-windows-20261104.json`](infrastructure-results/c04-actor-container-loss-windows-20261104.json)은
`97bc043`의 코드로 실행한 새 프로젝트 `c02-9a91d2c2613e`의 공개 원자료다.
2026-11-04 12:57:37~13:23:56 UTC에 실행했으며, 이 전체 시간은 환경 준비를 포함해 운영 RTO 측정과 구분한다.

| 검증 | 실제 결과 |
|---|---|
| 통합 검사 | 컨테이너 유실 26 + 기존 실행기 15 + 옛 관리 저장소 제거 2 = 43개 통과 |
| 실제 장애 | 8개 지점 × 두 전환 = actor 컨테이너 16개 삭제, 미완료 대체 14회. 관리 프로세스 종료도 2회 |
| 같은 전환 | 각 작업 ID·다음 epoch·예약 worker ID 유지, 각 전환의 이전 actor ID 7개와 완료 actor ID 보존 |
| 새 콘솔 | 예상 거부를 포함한 독립 콘솔 호출 26회. 완료 재호출은 추가 actor를 생성하지 않음 |
| 키 계획·보안 상태 | Root·발급기·전체 JWK 교체 완료(authority epoch 1), 이전 JWK 요청 132개 거부. 완료 후 소비한 새 토큰·미만료 소비 토큰·폐기 인증서 재사용 거부, 새 nonce 발급과 최신 checkpoint 백업 검증 성공 |
| 실제 옛 저장소 제거 | 실행기 journal/owner 4개, 관리 볼륨 18개 제거. 최종 실행/관리 epoch 3·A 활성·양 세대 2 |
| 소스/이미지 | 캠페인 입력 113개 지문 보존, graph/executor 양 이미지 각각 포함된 코드 93개 대조·외부 입력 20개 구분. 결합 단위 이미지 125개 대조는 별도 기록 |
| 정리·보존 | 사전 실험·본 실험·단위 이미지의 3개 소유 범위에서 컨테이너/볼륨/네트워크/이미지 태그 잔여 0. 기존 `pod-forensics-20261025-control-plane`의 같은 ID/실행 상태와 ZIP 2개의 SHA256 보존 |

사전 실험·이전 Windows 실행·역사적 CA 실험은 최종 합계에 더하지 않는다. 공개 자료는 결과/식별자/지문만
포함하며 private runtime, 개인키, JWT와 로컬 환경 파일은 커밋하지 않는다. AWS·유료 LLM·실계정·OS 신뢰
설정 변경 없이 로컬에서 수행했다. 독립 팀원의 재현/검토 완료로 기록하지 않는다.

같은 물리 PC·부모 Docker·지정한 생존 journal과 이미지가 남는 조건이다. 컨테이너 유실을 물리 서버/데몬·
전체 디스크 유실·전원 장애 fsync·quorum·자동 선출 보장으로 확대하지 않는다. checksum은 손상 검출용이고
Docker 관리자 침해/전체 상태 rollback 방어는 아니다. socket을 가진 대체 actor도 신뢰된 관리자이며
UID/RO rootfs/capability 제한이 socket의 관리자 권한을 줄이지 않는다. 온라인 CA/leaf의 socket/vault 차단은
유지한다. Root/JWK/백업 키는 공개 복구 기록에 포함하지 않는다. 독립 팀원 검토와 운영 SLA/RTO/RPO는 별도다.
