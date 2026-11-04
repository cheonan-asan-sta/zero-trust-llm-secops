# mTLS 기반 로컬 지속 실행

기존 native TLS, `mtls_transport`, `pep_lab`, NGINX의 all-hops 경로에 app·수집기·worker·watchdog를 연결하는 local/test 전용 Docker 프로필입니다. 이전 시험 캠페인의 마지막 상태를 이어 쓰지 않고 새 프로젝트, 정적 임시 CA와 named volume을 만듭니다. 실제 IdP·EDR 연결, 탐지 모델·임계값 변경과 운영 배포는 포함하지 않습니다.

## 실행과 보존

저장소 루트에서 Docker Engine·Compose를 준비하고 실행합니다. 최초 실행의 이미지 빌드·가져오기에는 빌드 환경의 네트워크가 필요합니다. 실행 중 서비스에는 외부 네트워크나 호스트 공개 포트를 주지 않습니다.

```bash
python -m pip install -e '.[dev]'
python -m scripts.continuous_mtls_runtime up --directory runtime/c02/continuous-mtls
python -m scripts.continuous_mtls_runtime status --directory runtime/c02/continuous-mtls
```

최초 `up`은 `kmtls-<12자리 hex>` 프로젝트와 앱 이미지, 고정된 NGINX 이미지 및 전용 볼륨을 준비합니다. 수집기의 identity 출처 공개키를 서버 등록에 합치며, 세션 증명용 서명키와 관측용 서명키는 분리합니다. 같은 directory의 다음 `up`은 저장한 프로젝트·이미지·볼륨·키·spool을 재사용합니다. 소스 변경 재빌드나 인증서 재발급을 수행하지 않습니다.

호스트의 해당 directory에는 `runtime.json`, `compose.yaml`, `empty.env`가 생깁니다. 프로젝트 식별자·이미지·소스 해시와 실행 설정이며, 개인키·API 키는 호스트 파일로 내보내지 않고 초기화 입력을 통해 전용 Docker 볼륨에 저장합니다. `runtime/`은 Git 추적 대상이 아닙니다. `--directory`는 저장소의 `runtime/c02` 아래 경로를 사용합니다.

`up`은 9개 서비스의 실행 상태와 core mTLS `/health/live` 응답을 기다립니다. `status`의 서비스별 `running`, `restart_count`, `restart_policy`도 정책 적용·PEP 차단 성공을 뜻하지 않습니다. 아래 통합 검증으로 별도 확인합니다.

```bash
# 컨테이너와 프로젝트 네트워크를 내리고, 정책 DB·접수·spool·키 볼륨은 보존
python -m scripts.continuous_mtls_runtime down --directory runtime/c02/continuous-mtls
# 같은 directory로 up하면 보존한 상태로 다시 실행
python -m scripts.continuous_mtls_runtime up --directory runtime/c02/continuous-mtls
```

일회용 시험 상태까지 버릴 때만 `down --purge`를 사용합니다. 이 명령은 해당 프로젝트의 볼륨과 앱 이미지 태그를 삭제하므로 접수·정책·감사·키도 사라집니다. 초기화 도중 실패하여 `runtime.json`이 남은 경우도 해당 프로젝트의 존재하는 자원을 정리할 수 있습니다. purge한 descriptor는 다시 초기화하지 않으므로 다음 새 시험은 다른 directory로 시작합니다. 보존해야 하는 정책 DB의 복원·마이그레이션 절차를 대신하지 않습니다.

## 서비스와 신뢰 경계

| 서비스 | 역할과 연결 |
| --- | --- |
| `app` | native TLS API와 정책·접수 DB. gateway 및 승인된 operator의 mTLS 요청을 받음 |
| `gateway` | collector·bridge에서 받은 mTLS 요청을 core mTLS로 전달 |
| `proxy` | NGINX의 사용자 진입·인가·보호 자원 경로 |
| `bridge` | 인가·일회용 소비 검사와 core 연결 |
| `resource` | 보호 자원과 소비 결과·감사 확인 |
| `collector` | 전용 JSONL·SQLite spool에서 관측을 읽어 gateway에 mTLS로 전송 |
| `worker` | 지속 접수된 관측을 정책에 반영. 네트워크 없음 |
| `watchdog` | 요청 없이 증명 만료·출처·키 변경을 주기적으로 재검증. 네트워크 없음 |
| `operator` | 검증용 승인된 내부 probe·세션 발급 클라이언트. 외부 listener 없음 |

여섯 Docker 네트워크는 모두 `internal`입니다. 모든 서비스는 UID/GID `10001`, 읽기 전용 root filesystem, `cap_drop=ALL`, `no-new-privileges`, `init: true`, `restart: unless-stopped`로 실행합니다. 호스트 bind mount·Docker socket·privileged 권한은 사용하지 않습니다.

app·worker·watchdog는 같은 `/data/zero-trust.sqlite3`와 읽기 전용 `/signals/sources.json`을 사용합니다. worker·watchdog에는 TLS 개인키·API 키를 마운트하지 않습니다. collector는 자기 spool·관측 서명키, collector 전용 mTLS·API 인증 볼륨만 사용하며 core·사용자·자원 네트워크에 직접 연결하지 않습니다. 내부 operator는 시험 세션을 발급하고 core·사용자·자원 경로를 검사할 권한이 있으므로 일반 사용자 컨테이너로 취급하지 않습니다.

수집기는 접수 `202`를 보존하고 worker는 정책 완료를 별도로 기록합니다. watchdog는 만료를 보류하고 출처·키 무효화를 회수로 반영합니다. 어느 프로세스도 정상 관측·재시작·만료 뒤 새 허용이나 자동 정상화를 만들지 않습니다. 세부 계약은 [수집기](continuous-signal-collector.md), [주기적 재검증](periodic-session-revalidation.md), [접수·worker](m3-durable-signals.md)를 따릅니다.

runtime의 관측 append helper도 collector와 공유하는 `input.lock` 안에서 활성 입력을 다시 엽니다. 기본 8MiB EOF 회전과 ACK 행의 tombstone 정리는 collector spool에 적용하며, pending 봉투·중복 방지 이력을 잊지 않습니다. named volume의 입력을 직접 append·truncate하는 writer는 회전과 협력하지 않으므로 사용하지 않습니다. 수동 `compact`·`rotate`는 sender 종료 후 같은 spool·대상 URL·TLS 프로필로 수행합니다. 이 기능이 서버 inbox 상한을 비우거나 인증서·관측 서명키를 갱신하지는 않습니다.

## 장애·재시작 검증

```bash
python -m scripts.test_continuous_mtls_runtime --directory "runtime/c02/continuous-mtls-validation-$(date +%Y%m%d-%H%M%S)"
```

위 예시는 Bash의 현재 시각으로 매번 새 directory를 만듭니다. 다른 shell에서는 사용하지 않은 이름을 직접 지정합니다. 기존 `runtime.json`이 있으면 사용 중인 자료를 파괴하지 않도록 검증을 거부합니다. 지속 사용할 위 runtime directory와 구분합니다.

검증기는 별도의 새 프로젝트를 만들고 성공·실패 뒤 모두 정리를 시도합니다. `verification.json`에는 완료 여부, 검사별 근거, 이미지·소스·설정 해시와 해당 프로젝트 컨테이너·볼륨·네트워크의 잔여 수를 기록합니다. `completed: true`와 정리 결과를 함께 확인하며 정리 실패도 검증 실패입니다. 승인된 operator를 통해 다음 동작을 검사합니다.

- 호스트 공개 포트 없는 내부 mTLS의 정상 문서 전달과 서비스별 권한·네트워크 경계
- app 중단 중 관측 spool 보존, collector·worker 재시작 후 같은 봉투 재전송과 한 번의 정책 반영
- 동일 JSONL 입력의 중복 접수·정책 효과 방지와 무관한 주체의 접근 유지
- 새 관측 없이 증명 만료 보류 및 서명키 폐기 회수, 미사용 grant의 보호 자원 전달 차단
- 잘못된 서버 pin에서 접수하지 않고 보류한 뒤 같은 경로의 profile 수정으로 재전송
- app 재시작 후 회수 기록 유지와 후속 정상 관측으로 회수된 접근을 되살리지 않는 동작

자동 재시작 검사는 컨테이너 안의 Python 자식 프로세스를 `SIGKILL`하고 **같은 컨테이너 ID에서 Docker `RestartCount`가 증가**했는지를 확인하는 방식입니다. `docker stop`은 운영자가 정지한 상태여서 `unless-stopped`의 자동 복구 검사와 구분합니다. 프로세스 재시작 뒤에는 기존 DB·접수·spool과 이미 회수한 세션을 유지해야 합니다. 구체적인 통과 결과는 실제 검증 기록으로 확인하며, 실행 설정만으로 장애 복구가 입증되지는 않습니다.

2026-11-04 최종 [공개 검증 기록](infrastructure-results/continuous-mtls-macos-20261104.json)은 최신 `aitest 5d957aa`를 합친 코드로 실제 Docker 통합 검사 **17개**를 통과한 결과입니다. app·collector·worker·watchdog의 프로세스 종료 후 자동 재시작, 전송 복구, 증명 만료·서명키 폐기 후 미사용 grant의 문서 접근 **403**, 무관 주체의 정상 **200**, 서버 pin 오류와 복구를 확인했습니다. 이미지 안의 앱·스크립트 지문을 원본과 대조했고 시험 컨테이너·볼륨·망 잔여는 각각 **0**입니다. macOS arm64의 전체 회귀는 **1,322건 통과·기존 의존성 경고 1건**, Ruff도 통과했습니다. 이전 기준의 예비 성공 17개는 최종 합계에 더하지 않습니다. 팀장 환경의 독립 재현은 후속 확인입니다.

## 수명과 후속 통합

이 프로필의 CA·TLS 인증서는 생성 시점부터 2일짜리 정적 임시 재료입니다. 초기 세션 출처 키 등록은 1일, 관측 출처 키 등록은 7일이며 각 증명·관측 봉투에는 더 짧은 개별 만료가 있습니다. root CA 개인키는 초기 생성 이후 보관하지 않습니다. 같은 directory에서 `up`해도 수명을 연장하지 않으며, 유효기간 이후에는 검증 실패로 접근을 거부합니다. 계속 실행되는 프로세스와 무기한 유효한 신뢰 재료는 구분해야 합니다.

기존 C04 자동 발급·갱신·개인키·CA·JWK 교체 구현과 시험은 보존합니다. **그 자동 운영 경로를 이 프로필에 통합·검증한 것은 아닙니다.** 해당 후속 작업은 현재 profile·pin·등록의 세대를 일관되게 전환하고 수집기·worker·watchdog·PEP까지 다시 검증해야 합니다. 이 정적 프로필의 성공으로 C04 자동 교체, 물리 호스트 장애 복구, 원격 anti-rollback 또는 운영 고가용성이 완성됐다고 판단하지 않습니다.
