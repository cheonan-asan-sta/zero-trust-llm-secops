# 부모 Docker 데몬 재시작 후 CA·DB·leaf 복구

2026-11-05 · I4·I6/C04 · [전환 실행기/worker 복구](parent-docker-recovery.md)의 후속

같은 Docker 데이터 영역이 살아 있는 재시작 뒤, 사전에 기록한 **같은 서비스와 저장소만** 명시적으로
시작한다. 대상은 두 CA·PostgreSQL 호스트와 내부 CA/DB, 게이트웨이, leaf, 관리 대기 서비스, 유지보수
worker, 운영자가 명시한 추가 workload다. Docker Desktop을 재시작하는 운영 명령은 제공하지 않는다.
임의 프로젝트 검색 결과 전체를 시작하거나 없어진 컨테이너·볼륨·인증서를 새로 만들지 않는다.

## 사전 식별 기록과 신뢰 경계

정상 상태의 `seal`은 양 실행기 기록/owner, 관리 사본과 인증된 최신 보안 checkpoint, DB 역할·동기 복제를
확인한 뒤 공개 manifest를 만든다. Docker Engine ID, 실행/관리 역할, 이미지와 컨테이너 전체 ID, 구성·환경
변수의 해시, 볼륨 사양, 내부 Engine ID를 고정한다. 환경 변수 원문·DB 행·개인키·토큰은 기록하지 않는다.
추가 workload는 이름과 전체 ID의 목록을 운영자가 명시한다. 공개 manifest는 Docker 데이터 영역 밖의
신뢰된 운영자 저장소에 보관하고, 장애 후 현재 값으로 다시 발급해 기존 신원 확인을 대체하지 않는다.
정상적인 이미지·구성·관리/실행 역할 변경을 끝낸 뒤에는 정상 상태에서 새 manifest를 보관한다.
관리 전환이 미완료인 상태를 이 서비스 명령으로 건너뛰거나 이전 manifest로 다른 세대를 복구하지 않는다.
seal 생성은 기존 Linux 관리 실행기와 같은 lease 안에서 수행한다. Windows 콘솔이 Linux 관리 경로를
자기 로컬 경로로 해석하지 않으며 기존 경로 범위 검사를 완화하지 않는다.

manifest checksum은 손상 검출이다. 악의적 Docker 관리자나 전체 저장소 snapshot rollback에 대한 인증이
아니다. 부모 socket을 사용하는 전용 복구 actor와 기존 worker는 신뢰 관리자이며, 온라인 CA/leaf에 socket이나
vault를 추가하지 않는다. actor는 별도 rootfs·network-none·읽기 전용 rootfs·권한 축소 설정을 확인한다.
기존 authority 조정기와 같은 Linux lease로 관리 변경을 직렬화한다.

## 복구 순서

| 단계 | 열기 전에 확인하는 조건 |
|---|---|
| 전체 사전 검사 | 같은 부모 Engine, 현재 실행/관리 역할, 모든 고정 서비스 ID/사양과 볼륨. 생존 작업·paused/불명 상태·알 수 없는 비공개 볼륨 writer 거부 |
| 접속 봉쇄 | 두 관리 사본 일치, pending/error/busy 없음, 암호화 checkpoint 인증·시퀀스/해시/권한 세대 일치. 기존 enabled 목록과 의도적 봉쇄 상태 보존 |
| 서비스 호스트 | 두 정지 호스트 시작, 내부 Engine ID·주소·CA/DB ID/사양·볼륨 대조 후 정지한 내부 서비스만 시작 |
| 데이터베이스/CA | 기존 primary/standby 역할·DB incarnation 유지, 동기 복제·재생 위치와 현재 보안 테이블 해시 확인, 양 CA TLS 건강 확인 |
| 업무/접속 | 명시한 workload·대기 서비스, 봉쇄된 게이트웨이 순서로 시작. `opening`을 먼저 내구 기록하고 원래 열려 있던 접속만 해제 |
| leaf/worker | 고정 leaf·worker 시작, 전체 실행 상태 확인 후 같은 cycle의 완료 영수증 기록 |

DB 승격·복원·보안 테이블 재조정, 예전 snapshot 복사, 키·인증서·역할 epoch 재생성, 불확실한 업무 POST
재전송을 하지 않는다. 동기 복제나 최신 보안 증거가 맞지 않으면 접속을 닫은 상태에서 조사한다.
leaf 자체의 pause 의도도 보존한다. 기존 내부 CA/DB의 `unless-stopped` 정책으로 먼저 살아난 프로세스도
게이트웨이 봉쇄 아래에서 같은 신원과 DB 상태를 검사한다.

## 중단과 재실행

공개 전용 journal은 단계·고정 actor ID·기존 봉쇄 상태·cycle·영수증을 fsync로 기록한다. 미완료 actor가
같은 ID로 정지해 있으면 같은 컨테이너를 재개한다. 살아 있는 actor를 kill하거나 lease를 삭제하지 않는다.
미완료 actor 자체가 유실됐으면 자동 대체하지 않고 조사한다. 이는 전환 실행기의 별도 유실 복구와 다른 경계다.

`opening` 이후 게이트웨이가 열렸다면 이전 checkpoint로 새 보안 상태를 되돌리거나 재봉쇄하지 않는다.
현재 호스트/DB 신원을 확인하고 남은 고정 서비스만 이어간다. 완료 재실행은 현재 상태를 확인하고 필요하면
멈춘 고정 worker만 시작해 같은 영수증을 반환하며, 새 토큰 소비·폐기를 지우지 않는다. 완료 후 다음 부모
재시작에서 대상 서비스가 모두 멈췄으면
새 cycle로 복구한다. 서비스/역할 ID는 그대로이며 journal은 이전 영수증 16개까지 보존한다.

일부 서비스만 살아 있는 새 장애, live-restore된 미완료 작업, 사본/owner 충돌, 다른 이미지/ID/볼륨,
미해결 보안 요청은 추측해 복구하지 않는다. 운영자가 실제 작업과 접속 경로를 조사해 정지·봉쇄 조건을
확인해야 한다. 일반적인 온라인 부분 장애 자동 복구나 자동 선출 기능으로 사용하지 않는다.

## 실행과 재현

새 프로필의 현재 descriptor와 실제 경로를 지정한다. 정리된 과거 실험 디렉터리는 실행 중인 클러스터가 아니다.
Docker 접속 자격은 기존 context/환경으로 설정하며 manifest에 넣지 않는다. 새 모듈을 포함한 이미지를 사용한다.

```powershell
# 장애 전 정상 상태: 추가 workload가 있으면 --extras <이름/전체 ID JSON 목록> 지정
.venv\Scripts\python.exe -m scripts.service_daemon_recovery seal --descriptor runtime/c02/<project>-console/cluster.json --seal runtime/c02/<project>-console/services-seal.json

# 같은 저장소의 부모 데몬이 돌아온 뒤 명시적으로 복구
.venv\Scripts\python.exe -m scripts.service_daemon_recovery recover --seal runtime/c02/<project>-console/services-seal.json

# Desktop 대신 별도 격리 dockerd만 재시작하는 실제 CA/DB 실험
.venv\Scripts\python.exe -m scripts.test_service_daemon_restart --directory runtime/c02/c04/service-daemon-reproduce
.venv\Scripts\python.exe -m pytest tests/test_service_daemon_recovery.py tests/test_service_recovery_checkpoint.py -q
```

검증 결과와 공개 원자료는 실험 완료 뒤 이 문서에 기록한다. 단위 검사는 잘못된 manifest/사양·역할/동기 복제·
checkpoint 인증/사본/pending 충돌과 접속 재개 이후 상태 보존을 다룬다. 실제 시험은 별도 privileged DinD의
같은 supervisor/데이터 볼륨 안에서 자식 dockerd에 SIGTERM을 보내며 사용자 Desktop과 기존 컨테이너는 유지한다.

같은 물리 PC·신뢰된 부모 데몬·생존 저장소/이미지가 필요하다. 전원 장애의 모든 시점, 물리 호스트/디스크 손실,
자동 quorum/선출, 운영 SLA/RTO/RPO, 독립 팀원 검토 완료를 보장하지 않는다. AWS·유료 LLM·실계정·OS 신뢰
설정을 사용하지 않으며 탐지 정책/평가 기준을 변경하지 않는다. 인프라 실행·측정은 채희주, 보안 상태 의미와
독립 재현은 김택희 담당으로 유지한다. 11/29 기능 동결·12/6 제출 가능본 일정과 전체 주간 완료는 구분한다.
