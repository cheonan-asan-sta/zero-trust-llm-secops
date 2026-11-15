# 고정 소스의 실제 systemd 통합 검증 재현

`scripts.run_infrastructure_native_batch`는 공유한 소스·Linux 의존성 tar와 **따로 전달받은 SHA256**, 소스의 test.lock SHA를 확인해 실제 로컬 검사를 묶어 실행한다. 특정 PC의 무시된 tmp 스크립트가 없어도 같은 계약으로 재현하기 위한 도구다. Python3.12/x86_64/Linux/systemd PID1/root인 격리 시험 호스트에서만 실행한다. 운영 설치·계정/정책 변경·클라우드 배포·과금 API 호출·8시간 soak를 시작하지 않는다.

소스/의존성 묶음은 승인한 출처에서 확보하고, 지문은 묶음과 독립적으로 확인한다. 지문 일치는 바이트 무결성이며 출처의 진위나 의존성 공급망 attestation을 자동 보장하지 않는다. 의존성 묶음은 검증 환경의 `site-packages` 트리이며 source의 test.lock과 제공자가 지정한 의존성 묶음이 맞는지도 확인해야 한다. 파일에 개인키·API키·토큰을 넣지 않는다.

```bash
python3 -m scripts.run_infrastructure_native_batch \
  --source-archive /path/source.tar --source-sha256 SOURCE_SHA256 \
  --dependencies-archive /path/dependencies.tar --dependencies-sha256 DEPENDENCY_SHA256 \
  --dependency-lock-sha256 TEST_LOCK_SHA256 \
  --output /path/fresh-native-results
```

실행기는 고정된 세 모듈만 실행한다. 임의 명령·모듈·개인키·환경변수를 받지 않는다.

| 묶음 | 검사 내용 | 고정 모듈 |
|---|---|---|
| bundle | 실제 exec·호출자/앱 연결·outbox·보관·암호화 복원·키 없는 재검증 | `run_exec_history_controls --bundle-observability` |
| provider | 정확한 systemd 실행 주체·runtime 키 공급자 이중화·신선도·부정 응답 거부 | `run_collector_provider_controls` |
| pam | 실제 sudo 출처·분리된 authentication 키·키 없는 검증/보관·반복/키 교체 시 중복 방지 | `run_pam_journal_controls --ledger` |

지문을 확인한 동일 FD에서 tar를 읽으며 총 크기·행 수·개별 파일 크기를 제한하고, 경로 이탈·드라이브 경로·중복 이름·symlink/hardlink·장치/FIFO를 거부한다. `/run/zt-pam-journal-v93-UUID`의 소유 소스를 사용하며 원래 소스 지문을 종료 때 대조한다. 종료 번호·조건 수·모듈 결과 지문·정리 확인을 `batch.json`에 저장한다. 집중 단위 시험과 실제 OS 통합 결과는 구분하며 이 조건 수를 F1 평가 분모로 쓰지 않는다.

모듈당 제한은540초다. timeout/예외/정리 영수증 누락 시 완료로 표시하지 않고 소유 소스를 보존한다. 이 경우 `snapshot_retained_for_unconfirmed_cleanup=true`이며 실제 해당 unit/프로세스의 종료와 소유 자원 정리를 확인한 후 소스를 정리한다. 운영 서비스나 호스트 전체를 강제 종료·prune하지 않는다. 정상 종료하고 모듈별 소유 unit/상태/공급자의 정리 확인이 모두 있을 때만 임시 소스를 제거한다. 로컬 root·커널·systemd 관리자는 시험의 신뢰 경계다.

Docker의 CA/DB/NGINX 수명주기 인수는 별도 `scripts.test_database_transport_runtime`를 사용한다. 이 실행기는 Docker 소켓·부모 Docker 데몬 제어 권한을 요구하지 않는다. 물리 다중 호스트·조직 SSO·운영 ACL·외부 재난 복구와 독립 탐지 성능 인수를 대신하지 않는다.
