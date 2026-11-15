# 3주차 실행 환경 고정과 재시작 전 검증

11/6 [CA leaf 통합 인수](ca-runtime-acceptance.md)는 기존 고정 경로를 재사용하며
CA tool lock·reload script·16서비스 구조와 제어기 고정 신뢰 설정을 추가 대조한다.
기존9·관측14서비스 descriptor를 자동 승격하지 않는다.

11/6 후속 [C01 선택형 관측 프로필](persistent-monitoring.md)은 같은 검증 경로를 확장해
관측 tool/rules·14서비스 구조·도구 이미지/바이너리와 설치된 설정을 추가 고정한다. 아래 기본
9서비스 측정/근거는 당시 기록으로 보존한다.

2026-11-06 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.
11/16~11/22의 3주차 계획 중 선정 인프라 통합·버전/환경 고정을 앞당겨 진행한 기록이다.

## 기존 경로에서 바뀐 점

기존 지속 실행기는 최초 앱 이미지 ID와 Python 소스 지문을 기록했지만, 같은 환경을 다시 시작할 때
현재 호스트의 NGINX lock/Compose 생성 코드를 읽어 실행 설정을 다시 만들었다. 정책 데이터·정적
파일·빌드 입력의 변경과 볼륨에 설치된 프록시 설정 변경도 재시작 전에 함께 대조하지 않았다.

이번에는 선택한 **9개 서비스 mTLS 경로**의 소스·정책·빌드 입력·구성·실행 제약을 묶어 최초 생성 때
공개 release 기록으로 고정한다. 재시작은 그 기록과 현재 입력이 일치해야 허용한다. 앱/정책의
판단 로직·인가 API·평가 데이터·탐지 기준은 변경하지 않는다.

## 구현과 검증 경계

| 항목 | 고정·대조 방법 |
|---|---|
| 입력 파일 | app 전체(정책·데이터·정적 파일 포함), scripts Python 파일, infra/runtime 전체, Dockerfile·pyproject·dockerignore·NGINX lock/설정 |
| 실행 구조 | 고정 placeholder로 만든 9개 서비스 Compose 구조의 지문. 역할별 환경 변수·망·마운트·UID·권한·자원 제한 포함 |
| 앱 이미지 | 최초 빌드의 Docker image ID와 linux/amd64 확인. 복사된 app/scripts·pyproject는 이미지 내부 파일과 대조 |
| 프록시 | 기존 NGINX lock의 registry digest·linux/amd64를 확인한 뒤 실제 로컬 image ID 기록 |
| 재시작 | 입력 목록의 추가/삭제/이름 변경/내용·실행 구조 변경, 앱 태그 교체, 고정 이미지 부재/플랫폼 불일치 시 시작 거부 |
| 공개 설정 볼륨 | 읽기 전용 점검 job이 설치된 all-hops.conf 지문을 저장한 release와 대조. 불일치를 자동 덮어쓰지 않음 |
| 실행 manifest | 저장한 두 image ID로 재구성. 모든 서비스에 pull_policy=never·linux/amd64. 외부 이미지 자동 대체 없음 |
| 키·상태 | 정상 재개는 기존 named volume을 재사용. CA/leaf/API·서명키 재발급이나 보안 상태 초기화 없음 |

파일 지문은 Git checkout의 CRLF/LF 차이를 정규화한다. bytecode·문서·runtime 작업 파일은 release
입력에서 제외한다. image ID는 파일 정규화와 별도로 실제 Docker 식별자를 확인한다. 같은 입력의
완전한 바이트 재현 빌드나 SLSA·서명 검증을 입증한 것은 아니다.

호스트 Docker Engine·Compose·Windows/Python 설치 자체를 고정하거나 배포하지는 않는다.
CI 호스트의 개발 의존성 설치도 기존 정책을 유지한다. 이번 lock의 대상은 컨테이너 앱/프록시와
그 소스·빌드·실행 설정이며, 호스트 도구/운영체제까지 동일한 환경이라는 뜻은 아니다.

저장된 호스트 YAML은 실행 권한의 근거로 쓰지 않는다. 동일한 검증 코드가 기록된 image ID와
고정 구조를 사용해 다시 생성한다. 현재 NGINX lock을 읽어 예전 환경에 새 버전을 몰래 적용하지 않는다.
비밀값은 기존처럼 Linux 전용 볼륨에만 두고 release/보고서에는 원문을 포함하지 않는다.

## 실행과 변경 절차

```powershell
.venv/Scripts/python.exe -m scripts.continuous_mtls_runtime up --directory runtime/c02/my-locked-runtime
.venv/Scripts/python.exe -m scripts.continuous_mtls_runtime status --directory runtime/c02/my-locked-runtime
.venv/Scripts/python.exe -m scripts.continuous_mtls_runtime down --purge --directory runtime/c02/my-locked-runtime
```

처음 생성할 때만 앱 빌드와 digest 고정 프록시 이미지 준비에 네트워크를 사용한다. 이후 시작은
로컬 고정 이미지가 있어야 하며 이미지를 자동으로 다시 받지 않는다. 실제 서비스는 내부망 또는
network=none이며 호스트 포트·Docker socket·클라우드·유료 LLM을 사용하지 않는다.

이전 release 기록이 없는 환경은 **자동 승인/재봉인하지 않고 시작을 거부**한다. 상태 조회와
범위가 검증된 종료/정리는 가능하다. 소스/설정이 바뀌었다면 기존 파일을 고치거나 hash를 새로
써서 실행을 강제하지 말고, 백업·정지·검토 후 새 테스트 환경에서 인수 검증해야 한다.
이번 작업은 기존 DB를 새 환경으로 자동 이관하거나 운영 업데이트를 승인하는 절차가 아니다.

저수준 Docker 권한을 가진 신뢰 운영자가 직접 명령으로 gate를 우회하거나 release·코드·이미지를
함께 바꾸는 공격은 방어 범위 밖이다. release는 **신뢰 호스트의 지문 기록**이며 서명된 외부
승인이나 운영 보안 인증이 아니다. private key·registry의 정상 교체를 release가 봉쇄하지 않도록
동적 키/보안 상태 볼륨 전체를 정적 소스 lock으로 묶지 않는다. 해당 변경은 기존 mTLS·정책 검증을 따른다.

## 로컬 인수 시험

```powershell
.venv/Scripts/python.exe -m pytest tests/test_runtime_release.py tests/test_continuous_mtls_runtime.py -q
.venv/Scripts/python.exe -m scripts.test_continuous_mtls_runtime --directory runtime/c02/release-reproduce01
```

새 경로는 존재하지 않는 runtime/c02 하위 디렉터리를 사용한다. 첫 명령은 소스/정책/정적 파일·
dependency lock·topology 변경, 입력 추가/삭제·이미지/플랫폼·기록 누락·경로·설정 변경을 검사한다.
실제 Docker 실행은 다음을 기존 보안 회귀와 함께 시험한다.

1. release와 이미지 내부 입력을 대조한 뒤 9개 서비스를 시작한다.
2. 서비스를 모두 정지하고, 저장 기록의 내용/지문 변경·이전 형식·앱 태그 교체·공개 프록시 설정
   변경을 각각 주입한다. 단순 예외가 아니라 정확한 거부 사유와 **모든 서비스 정지 유지**를 확인한다.
3. YAML에 임의 서비스를 넣어도 고정 manifest로 재구성하며, 실제 실행 컨테이너가 두 image ID에
   일치하고 자동 pull이 꺼져 있는지 검사한다.
4. 재시작 전후 4개 자격/공개 등록 볼륨의 파일 지문이 같은지 확인한다. 비밀 원문은 보고하지 않는다.
5. 기존 41개 mTLS·소비/회수·수신함·재시작·장애 검사를 그대로 수행하고, 소유 자원만 정리한다.

이번 검사는 시작 전 사전 검사다. 이미 실행 중인 환경에서 불일치를 발견했다고 기존 프로세스를
자동 강제 종료하지 않는다. 지속적인 파일 감시/호스트 무결성·기존 실행 컨테이너의 모든 옵션
attestation·운영자 승인·장기 부하/성능 검증까지 구현한 것으로 확대하지 않는다.

실행 결과와 소스/이미지/검사·정리 근거는
[공개 로컬 원자료](infrastructure-results/runtime-release-lock-20261106.json)에 기록했다.
김택희의 독립 검토는 미완료이며 도구 보조 실행을 팀원 수동 재현으로 기록하지 않는다.

| 최종 로컬 인수 | 결과 |
|---|---|
| 새 고정/재개 검사 + 기존 mTLS 회귀 | 7 + 41 = 48/48 통과 |
| 고정 입력 파일 / 실행 서비스 | 145개 / 9개 |
| release 지문 | bed9a0db9ab3d6b9cd7910a512ecc66ed64edb26c422f7babb831b6552ade0f6 |
| app/scripts 이미지 내부 payload | 현재 소스와 일치 |
| 정리 후 소유 컨테이너·볼륨·네트워크 | 모두 0 |

로컬 실행은 기준 Git `2954347...` 위의 구현 중 소스(`source_dirty=true`)를 시험했다. 위 지문과
각 입력/설정·실제 이미지 ID를 공개 원자료에 보존했으며 최종 소스와 대조했다. 최종 PR/병합 후
CI의 정확한 head·checkout·전체 회귀/복구18·통합48·정리 결과는 PR 기록에 별도로 남긴다.

검증기 만료 경쟁 보완 전 고정 기능의 로컬 전체 회귀는 Linux **1,976 통과/경고2/588.09초**,
Windows **1,972 통과/4 skip/경고3/801.71초**다. 이후 추가한 검증기 회귀 7개는 아래 집중 검사와
최종 소스의 실제 통합·PR/병합 후 전체 CI로 확인한다. 위 수치를 최종 소스의 전체 회귀로 바꾸어
기록하지 않는다. 경고는 기존 FastAPI/Starlette httpx·Windows anyio portal·Mangum loop
deprecation이며 억제하지 않았다. 전체 회귀는 같은 호스트에서 일부 병행해 실행했으므로 성능 비교 수치가 아니다.

초기 실행은 21개 완료 뒤 기존 만료 대조 검사 `outage_expired_control_revived`에서 중단됐고,
소유 컨테이너·볼륨·네트워크는 모두 정리됐다. 기존 검증기에서 요청 전 ACTIVE를 읽은 뒤
watchdog이 HELD를 추가하면 정상적인 403/SESSION_NOT_AUTHORIZED도 실패 처리하는 경쟁
경로를 재현했다. 요청 후 검증된 이력의 기존 prefix·연속 version·HOLD/HELD·만료 사유를
다시 대조하도록 보완했다. 200 허용·실제 회수·설명되지 않는 변경은 계속 실패한다.
검증기 회귀 7개를 추가했고 전체 집중 91개/4.20초가 통과했다. 앱·정책·만료 기준과 요청 재시도는
변경하지 않았다. 초기 실패의 응답 세부값은 보관되지 않아 경쟁이 유일한 직접 원인이라고
확정하지 않으며, 실패 기록을 남기고 최종 소스에서 전체 통합을 재검증한다.

## 3주차 다음 항목

이번 범위는 C02/수집·worker·watchdog가 연결된 지속 실행 경로의 고정이다. C01 Prometheus/
Alertmanager 통합 프로필, CA 자동화와 동적 등록/키 변경의 인수 계약, 사건/감사/outbox 전체
저장 계약, C01~C03 최종 조건부 선정은 후속이다. [전체 잔여 표](app-state-recovery.md#3주차-잔여와-인계)를
유지하고 11/29 기능 동결·12/6 제출 가능본 목표를 변경하지 않는다.

## 공식 근거

- [Docker Compose service 명세](https://docs.docker.com/reference/compose-file/services/#pull_policy):
  로컬 image ID와 pull_policy=never를 명시해 재시작 시 외부 이미지로 대체하지 않도록 구성했다.
- [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/):
  실제 ID·OS/architecture·registry digest를 확인한다.
- [Compose 환경 변수 우선순위](https://docs.docker.com/compose/how-tos/environment-variables/envvars-precedence/):
  기존처럼 명시적 Compose 파일·빈 env-file·리터럴 환경 설정을 사용한다. 사용자 .env.local을 읽지 않는다.
