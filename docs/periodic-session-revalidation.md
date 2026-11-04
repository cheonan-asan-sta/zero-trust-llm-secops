# 주기적 세션 재검증

후속 [mTLS 기반 로컬 지속 실행](continuous-mtls-runtime.md)은 별도 Docker 프로필에서 앱·관측 수집기·worker·watchdog의 실행과 재시작을 연결한다. 아래는 watchdog 자체의 계약이며 Docker 운영 통합 미포함 표기는 그 최초 구현 범위다.

`scripts.session_watchdog`는 새 관측이나 업무 접근 요청이 없어도 기존 서명 세션의 증명 만료와 출처·키 유효성을 주기적으로 확인하는 local/test 프로세스다. 앱의 `ZeroTrustOperations.revalidate_sessions()`를 사용하며 기존 접근 검사와 같은 출처 지문 계약을 따른다.

[지속 수집기](continuous-signal-collector.md)는 JSONL 관측을 포착·전달하고, 서버 `signal_worker`는 접수한 관측을 처리한다. watchdog는 별도 프로세스로 기존 세션의 시간·등록 상태를 확인한다. API·수집기·worker를 실행하는 것만으로 watchdog가 자동 시작되지는 않는다.

## 상태 전이

| 기존 세션·조건 | 주기 재검증 결과 |
|---|---|
| `verified_source`, 서명 증명 만료 | `HOLD` / `HELD`, 기존 허용 무효화 |
| `verified_source`, 출처·키 삭제/비활성화/키 만료 또는 저장된 출처 지문과 현재 등록의 불일치 | `DENY` / `REVOKED` |
| 이미 `HELD`인 세션에서 이후 키 폐기·등록 변경 확인 | 더 강한 `DENY` / `REVOKED`로 전환 가능 |
| 이미 `REVOKED` | 추가 버전·기록 없음 |
| 아직 유효하거나 무서명 `demo` 세션 | 변경 없음 |
| 일회용 grant의 TTL만 만료 | 사용자 위험으로 판단하지 않고 세션 상태를 변경하지 않음. 다음 접근의 기존 토큰 만료 검사는 유지 |
| 공개키 등록 파손·읽기 실패 | 이번 재검증을 중단하고 오류 처리. 알 수 없는 상태를 임의의 폐기로 기록하지 않음 |

판정은 한 차례에 읽은 하나의 등록 스냅샷을 기준으로 한다. 파일이 검사 사이에 바뀌면 다음 검사에서 확인한다. 출처 지문에는 그 출처의 등록 내용이 포함되므로 현재 사용한 키 외의 등록 변경도 기존 접근 검사와 동일하게 영향을 줄 수 있다.

증명 만료로 보류할 때는 기존 재인증 challenge를 지우지 않는다. challenge 보존은 만료된 challenge의 재사용 허용이나 재인증 성공을 뜻하지 않는다. 폐기 전환은 challenge를 정리한다. 정상 등록이나 새 관측만으로 보류·회수 상태를 정상화하지 않으며 새 grant 발급·MFA 생략·위험 제한 해제는 수행하지 않는다.

## 실행

앱과 같은 Python 환경에서 **실제 앱이 사용하는 DB와 공개키 등록**을 지정한다. 개인키·API 키·외부 모델은 필요하지 않다.

| 설정 | 조건 |
|---|---|
| `APP_ENVIRONMENT` | `local` 또는 `test`. production은 실행 거부 |
| `ZERO_TRUST_DB_PATH` | API·관측 처리 worker가 사용하는 동일 SQLite 파일 |
| `TRUSTED_SIGNAL_SOURCES_PATH` | 그 세션의 출처를 관리하는 동일 공개키 등록 |

설정을 맞춘 셸에서 다음을 실행한다.

```sh
# 한 번 검사하고 종료
python -m scripts.session_watchdog --once

# 별도 프로세스로 반복 검사 (기본 간격 5초)
python -m scripts.session_watchdog --interval-seconds 5
```

SIGINT/Ctrl+C 또는 SIGTERM으로 종료한다. 간격은 0.01~60초를 허용한다. 시작 실패 또는 `--once` 검사 실패는 종료 코드 1이다. 반복 실행 중 등록·저장소 오류는 제한된 오류를 남기고 다음 주기에 다시 검사한다. 출력은 상태·집계 중심이며 세션 식별자·원본 관측·키·토큰을 노출하지 않는다.

정상 출력의 `checked`는 이번에 검사한 서명·미회수 세션 수이고, `changed`는 변경한 세션 수다. `held`와 `revoked`는 이번 전환 수이며 전체 보관 세션의 상태 개수가 아니다. 오류 출력은 `SIGNAL_REGISTRY_UNAVAILABLE`, `JOURNAL_UNAVAILABLE`, `CONFIG_OR_STORAGE_UNAVAILABLE` 같은 코드만 남긴다.

호스트에서 실행하는 앱에는 호스트의 실제 DB 경로를 사용한다. 앱이 Docker named volume을 사용한다면 같은 볼륨과 공개 등록을 읽도록 별도 실행 구성을 준비해야 한다. 경로 문자열이 같다는 이유로 호스트 기본 `runtime` DB가 컨테이너 DB와 같다고 가정하지 않는다. 이번 변경은 Docker/운영 프로필에 watchdog 서비스를 자동 추가하거나 프로세스 감시기를 설치하는 작업을 포함하지 않는다.

기본 5초는 검사 간격이며 처리·DB 잠금·프로세스 중단 시간을 포함한 실시간 보장이나 최대 회수 지연 SLA가 아니다. 기존 PEP는 watchdog 실행 여부와 별개로 다음 접근에서 증명·출처·토큰을 계속 검사한다.

## 저장과 감사

상태가 바뀐 세션만 버전을 증가시키고 같은 SQLite 트랜잭션에 `decision` 저널을 기록한다. 해당 journal entry의 `trigger`는 `periodic_revalidation`이며 이전 버전·사유·검사 시각을 함께 담는다. 기존 세션 이력 API의 버전·사유와 journal의 전환 근거를 대조한다. 새 trigger가 세션 응답 필드로 추가되는 것은 아니다.

등록 검증·후보 상태 전이·감사 기록이 모두 성공해야 변경을 commit한다. `BEGIN IMMEDIATE`와 최신 세션 상태를 기준으로 처리하므로 반복 검사나 여러 watchdog의 동시 실행이 같은 전환을 중복 기록하지 않는다. 유효한 세션과 이미 처리한 조건에는 매 poll마다 journal entry를 추가하지 않는다.

일반 평가 상한 200 이후에도 [보안 전용 전이](session-security-transitions.md)로 만료·출처 무효화를 최대 버전 204까지 기록한다. 기존 HOLD에 만료 사유를 추가하는 제한된 경우를 포함하며 새 ALLOW·grant·제한 하향은 없다. 유효한 204는 이미 DENY/REVOKED여서 반복 점검은 no-op이고 다른 후보의 검사를 막지 않는다. 이를 지원하는 모델을 앱·worker·watchdog·관리 도구에 함께 적용해야 한다.

다음은 정상 복구로 숨기지 않는 한계다.

- 저장 손상·알 수 없는 보안 전이 상태나 journal의 실제 행·segment·byte 한도 또는 저장 실패에는 해당 재검증 전체를 롤백하고 제한된 오류를 반환한다. 일부 세션만 갱신한 성공으로 표시하지 않는다. 활성 journal 10,000행은 전체 논리 이력 상한과 다르며 [정책 journal 이관](policy-journal-maintenance.md)의 유한 archive 한도를 함께 적용한다.
- 등록 파손 시 임의의 `REVOKED`를 생성하지 않는다. 기존 접근 경로의 실패 폐쇄는 유지하며, 등록이 복구된 뒤 다음 검사에서 다시 판정한다.
- journal/상태를 지우거나 옛 백업으로 회수를 되돌려 한계를 우회하지 않는다. DB 호환·복원 조건은 [M3 저장 계약](m3-durable-signals.md#저장중복재시작-계약)을 따른다.
- SQLite journal의 체크섬은 무결성 검사이며 호스트·저장소 관리자에 대한 원격 anti-rollback 보증은 아니다.

## 검증 범위

시험 결과·통과 수·실제 운영 프로필의 실행 여부는 해당 PR의 검증 기록을 따른다. 확인할 조건은 요청 없는 증명 만료, 키 폐기·등록 변경, 보류 후 폐기 강화, 200 이후 보안 전이와 204 회수 no-op, challenge 보존, demo·grant TTL 무변경, 반복/동시 실행 중복 방지, 등록 파손·잘못된 전이·저장 한도의 전체 롤백과 실제 별도 CLI 프로세스의 종료·재시도다.

탐지 규칙·임계값·정책·모델 설정과 실제 IdP/EDR 연동을 변경하지 않는다. 주기적 유효성 검사 통과와 탐지 품질 목표 달성, Docker 운영 통합·팀원 독립 재현을 별도로 기록한다.
