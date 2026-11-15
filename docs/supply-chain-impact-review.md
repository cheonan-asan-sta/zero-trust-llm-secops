# C03 실제 구성에 따른 취약점 영향 검토

후속 패치/현재 이미지 상태는 [런타임 패치 기록](supply-chain-priority-patches.md)을 따른다.
아래 내용과 200항목 JSON은 과거 이미지의 패치 전 snapshot으로 보존한다.

2026년 11월 5일 · 채희주 인프라·배포 이미지 담당 · Codex 도구 보조.

기존의 [발견 차이 200항목](supply-chain-findings-review.md)을 설치 파일·실행 권한·실제 기능과
공식 공급자 정보에 대조했다. **인프라 범위의 검토 기록은 작성했지만, 취약점 수정·실제 악용 성공·운영 승인으로
처리하지 않는다.** 앱의 입력 도달 가능성과 팀원 독립 검토는 인계한다. 앱·정책·탐지·의존성은 변경하지 않았다.

## 먼저 적용할 판단

- 우선 조치/검증 P1은 **17항목**이다. Python TLS/HTTP/tar 경로 3개와 실제 연결된 SQLite 14개다.
  위험도 점수나 실제 침해 17건이라는 뜻이 아니다. Python 3.12.15 기반 이미지를 그대로 재사용해도 된다는 결론이 아니다.
- pip 2개는 이 이미지/설치 설정에서 특정 공격 전제가 완화됨을 관측했다. 나머지 pip 4개는 빌드 입력과
  설치 과정의 조건부 위험이다. pip 전체가 안전하거나 취약점이 패치됐다고 표시하지 않는다.
- Debian TEMP 5항목은 모두 공급자 trixie 기록이 `open`이다. init/설치 부팅 조건이 없는 1항목과
  대화형·로컬 관리 조건이 필요한 4항목을 구분했다. TEMP ID를 오탐으로 삭제하지 않는다.
- gcc-14-base의 5항목은 이 바이너리 패키지에 문서만 존재하는 source-package 매칭이다. 같은 gcc-14 소스의
  libgcc/libstdc++ 10항목은 공유 라이브러리로 남으므로 함께 제외하지 않는다.
- 실제 악용 확인 **0**, 의존성 수정 **0**, 억제/예외 **0**이다. 이 숫자는 안전한 취약점 개수나 탐지 성능이 아니다.

전체 항목의 공급자 상태·실행 조건·우선순위는 [200항목 대장](supply-chain-impact-register.md),
[기계 판독 결과](infrastructure-results/c03-impact-review-20261105.json)에 남겼다.

## 정확히 검사한 대상

| 구분 | 실제 대상/경계 |
|---|---|
| 이미지 | `sha256:5a64e8c43d9e1712996f29ff9bf6adbb3b19270f67facea535ee428ec754fe54` |
| 보관 tar | SHA-256 `5d8dd0efd36b464767f465368d178d8a1ae692e7768d966188623cb5dc8940f7` 재확인 후 재사용 |
| 앱 소스 | 11/3 최초 검사 `b4660ad1915fc3e2d39159f003940ec085f9f19c`의 과거 앱 이미지 |
| 런타임 | Python 3.12.15, pip 25.0.1, Debian 패키지87·Python 배포44 = 131개 |
| 새 스캔 | 없음. 기존 200항목의 영향 조건 검토이며 신규 advisory 전체 탐색이 아님 |
| 현재 소스 대조 | PR #27 병합 `2e521657ed40375320c31c680022db91835938ef`의 앱/스크립트를 별도 AST 대조 |
| 확인하지 않은 대상 | 현재 배포 앱의 새 이미지, CA/DB/프록시/privileged DinD 이미지, 실제 호스트 OS·기업 환경 |

현재 소스에서 찾은 새 C04 mTLS 호출이 과거 이미지 안에도 있었다고 표현하지 않는다. 과거 이미지의
직접 참조 14개와 현재 소스의 72개를 구분했다. 직접 참조는 별칭 import/호출의 AST 관측이며 동적 호출,
서드파티 의존성 전체, 실제 사용자 입력 흐름을 완전히 분석한 결과가 아니다.

기존 로컬 `python:3.12-slim` cache도 별도 네트워크 없는 조회에서 **3.12.15**였다.
cache ID는 `sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1`이다.
원격 태그의 현재 내용이나 새 앱 빌드의 상태를 이 cache 조회로 단정하지 않는다. `FROM python:3.12-slim`이라는
이름만으로 패치 적용을 주장할 수 없으며, 후속 변경에서 실제 runtime 버전·고정 digest·새 스캔을 확인해야 한다.

## 확인 방법과 비용 경계

공식 Debian JSON과 PSF가 발행한 CVE 레코드 9개, GitHub Advisory pip 레코드 6개를 공개 HTTPS로 수집했다.
전체 원본 SHA-256·조회 시각·URL/응답 상태를 기록하고, 200항목과 필요한 구조화 사실만 공개했다.
Debian 원본 약88MB는 비공개 `runtime/c03/impact-20261105/sources`에 보존한다.
그 데이터는 현재 시점의 기록이므로 11/3 스캔 당시 DB 상태와 구분한다.

고정 이미지를 새로 설치/빌드하지 않고 불러온 뒤 다음 조건으로 **3회** 확인했다.

| 조건 | 실제 관측 |
|---|---|
| 네트워크 | Docker `network=none`, 외부 포트·socket·호스트 홈·자격증명 마운트 없음 |
| 권한 | UID/EUID10001, `NoNewPrivs=1`, effective/permitted/bounding capability 모두0, 비특권·비TTY |
| 쓰기 | rootfs 읽기 전용, `/tmp`·`/data`만 제한된 tmpfs, 원본/검사 스크립트 읽기 전용 |
| 재현 | 3회 JSON 바이트 동일, 고정 이미지 ID·종료0·실행 설정 대조 |
| 시험 입력 | 일반 파일 하나의 작은 tar 추출, 공개 base64 상수, in-memory SQLite compile option 조회 |
| 하지 않은 실행 | 악성 tar/SQL/인증서·권한 상승·서비스 공격·외부 엔드포인트·실계정 테스트 |

이 권한은 **검사 프로필에서 관측한 조건**이다. 모든 Compose/CA 관리자 컨테이너나 실제 호스트에
동일한 제약이 적용된다는 증거가 아니다. 원래 이미지 설정의 기본 명령은 uvicorn이지만 이번 probe가
운영 앱 요청을 실행한 것은 아니다. AWS·유료 LLM 호출·OS 신뢰 설정 변경은 없다.

최초 metadata 탐색1회, 정상 tar 표본 경로가 pip의 최상위 디렉터리 제거와 충돌해 실패한1회,
최종 probe 확정 전 중간 성공1회는 최종 3회에 더하지 않는다. 정상 표본을 `package/regular.txt`로
수정했으며 악성 archive로 방어를 우회하거나 앱/이미지를 수정하지 않았다.

## Python 9항목

| 항목 | 실제 영향 조건과 판단 | 후속 |
|---|---|---|
| CVE-2026-115557 · P1 | 3.12.15가 PSF 영향 범위에 든다. 외부 HTTPS/인증서 처리 기반의 패치 우선 항목이다. 현재 mTLS 소스에는 사설 CA·서버 pin 검사가 있어 특정 통신 경로의 전제가 더 좁아질 수 있지만, 공인 CA를 사용하는 빌드 다운로드까지 해소한 증거는 아니다 | 패치된 Python 기반 이미지 고정·재빌드·TLS/회수 회귀 |
| CVE-2026-103995 · P1 | HTTP 응답 길이/chunk 해석 문제. 과거 수집기는 urllib opener, 현재 mTLS 계층은 http.client 기반이다. 입력 framing 불일치의 실제 경로가 있으므로 단순 미사용 처리 불가. 악성 원격 응답 시험은 하지 않음 | 해당 Python branch의 backport/패치 확인·정상/거부 응답 회귀 |
| CVE-2026-114583 · P1 | `tar_filter`로 신뢰할 수 없는 archive를 추출하는 조건. 저장소의 git archive 추출은 `filter="data"`이고 pip는 실제 `data_filter` 호출을 확인했으나, 이것을 모든 tar 경로의 안전 증명으로 확대하지 않음 | 패치된 기반 이미지·외부 archive 수용 경계 검토 |
| CVE-2025-12781 · P2 | 실제 urlsafe decoder가 일반 base64 알파벳도 받아들임을 무해한 상수로 확인. 서명 경로에는 재인코딩 일치 검사도 있으므로 decoder의 관대한 동작만으로 인증 우회 확정 불가 | 앱 담당이 canonicalization/서명·중복 식별 의미를 독립 검토 |
| CVE-2026-3446 · P2 | 기본 decoder는 padding 이후 추가 입력을 허용하고 `validate=True`는 거부하는 것을 확인. 현재 인프라 일부 복원 경로는 엄격 검증을 쓰지만 모든 decoder가 동일하지 않음 | 신뢰 경계별 decoder·사전 인증/해시·재인코딩 조건 인계 |
| CVE-2025-15366 · P2 | imaplib의 외부 입력 명령 조건. 표준 라이브러리는 이미지에 남지만 앱/스크립트 직접 호출은 관측하지 못함 | 간접 의존성과 신규 메일 기능 도입 시 재검토 |
| CVE-2025-15367 · P2 | poplib의 외부 입력 명령 조건. 직접 사용 미관측을 패치/영향 없음으로 표시하지 않음 | 위와 같음 |
| CVE-2026-6019 · P2 | cookie 값을 `Morsel.js_output`으로 JavaScript에 출력하는 조건. 직접 사용 미관측 | 앱 HTML/의존성 경로 확인 시 재검토 |
| CVE-2026-3479 · P2 | 최신 PSF CVE 기록에 `disputed` 표시가 있고 의도한 get_data/open 신뢰 모델 설명으로 변경됐다. 발표 초기 문서만 보고 해결/미해결을 단정하지 않음 | 사용자 경로를 리소스 이름으로 넘기는 사용 여부 검토; 자동 억제 없음 |

PSF의 [TLS 공지](https://mail.python.org/archives/list/security-announce@python.org/thread/FNAJMZV6XQYLVPABNINDMF3VF66AYLW4/),
[tar 공지](https://mail.python.org/archives/list/security-announce@python.org/thread/43JOWPRAV5DI3VZ4FUEUAZOHCATXXOCK/),
[HTTP 원문 이슈](https://github.com/python/cpython/issues/150751),
[pkgutil 후속 이슈](https://github.com/python/cpython/issues/146121)를 대조했다.
[Python 3.12.16 릴리스](https://www.python.org/downloads/release/python-31216/)는 TLS·tar 두 항목의
보안 변경을 명시한다. **3.12.16으로 올리면 위 9개가 모두 해결된다는 결론은 아니다.** 브랜치별 후속
backport와 실제 공급 이미지의 포함 여부를 별도로 확인한다.

## pip 6항목: 실행 시점과 빌드 시점 구분

| 항목 | 관측한 조건 | 판단 |
|---|---|---|
| [GHSA-4xh5-x5gv-qwph](https://github.com/advisories/GHSA-4xh5-x5gv-qwph) | 실제 pip `untar_file`이 일반 tar 표본을 추출하며 `pip_filter`→`tarfile.data_filter`를 호출 | 이 Python/설치 경로에서 **fallback 전제 완화**, pip 패치 자체는 아님 |
| [GHSA-jp4c-xjxw-mgf9](https://github.com/advisories/GHSA-jp4c-xjxw-mgf9) | 이미지의 실제 install 옵션 parser에서 `disable_pip_version_check=True` | 이 구성에서 **self-check 전제 완화**. 옵션을 변경하거나 별도 설치 도구를 쓰면 재검토 |
| [GHSA-wf93-45jw-7689](https://github.com/advisories/GHSA-wf93-45jw-7689) | pip25.0.1은 공급자 영향 범위. 악성 wheel entry point 설치 조건 | 조건부 빌드 입력 위험 유지 |
| [GHSA-6vgw-5pg2-w6jp](https://github.com/advisories/GHSA-6vgw-5pg2-w6jp) | 악성 wheel을 설치하는 조건 | 조건부 빌드 입력 위험 유지 |
| [GHSA-58qw-9mgm-455v](https://github.com/advisories/GHSA-58qw-9mgm-455v) | tar/ZIP 복합 archive의 설치 해석 조건 | 조건부 빌드 입력 위험 유지 |
| [GHSA-qwm4-qh6w-59xr](https://github.com/advisories/GHSA-qwm4-qh6w-59xr) | 악성 package index와 URL 처리 조건, 특히 binary-only download 사용 여부 중요 | 일반 앱 요청의 원격 취약점으로 바꾸어 표현하지 않으며 빌드 입력 검토 유지 |

Dockerfile의 `pip install .`은 `USER secops` **이전**에 실행된다. 따라서 실행 컨테이너의 nonroot·read-only
설정이 빌드 중 악성 패키지의 영향을 자동으로 막지 않는다. 과거 빌드가 신뢰할 수 없는 package index나
wheel을 실제로 사용했다는 증거는 없고, 빌드 침해도 재현하지 않았다.
[pip 공식 옵션](https://pip.pypa.io/en/stable/cli/pip/#cmdoption-disable-pip-version-check)과 실제 parser 값을 함께 확인했다.
후속은 pip 버전/설치 입력 고정, 검증된 wheel/해시·builder 경계, runtime에서 설치 도구를 남길 필요의 검토다.

## Debian 185항목과 심각도 차이 78항목

실제 `dpkg-query`의 바이너리 버전과 **source package/source version**으로 매핑했다.
예를 들어 bash `5.2.37-2+b10`의 source version은 `5.2.37-2`다. `+b10`을 보안 패치 번호로 해석하지 않는다.
기록한 185항목의 현재 trixie 상태는 모두 `open`이다. urgency `unimportant` 51항목과
`not yet assigned` 134항목을 보존한다. 심각도 차이 78항목은 각각 46·32항목이다.
**urgency·no-dsa·오래된 CVE 번호만으로 영향 없음/수정 완료로 바꾸지 않았다.**

| TEMP 항목 | 실제 확인 | 인프라 판단 |
|---|---|---|
| [bash · TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF) | bash 존재, suid 아님. UID10001·NNP·cap0 조건 | 로컬 권한/호출 문맥 필요, 조건부 잔여 위험 |
| [shadow · TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) · 2패키지 | su는 실제 존재·suid이며 소유 패키지는 util-linux. probe는 비TTY/NNP | 단순 shadow 패키지명으로 영향 확정/제외 불가. 대화형 su·터미널 조건 필요 |
| [sysvinit · TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6) | init/systemd 실행 파일 없음. 이미지 기본 명령은 uvicorn | 이 이미지 프로필에 OS expert installer/부팅 전제 없음. 원래 공급자 open 상태는 유지 |
| [tar · TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5) | tar/rmt 실행 파일 존재, 원격 helper는 실행하지 않음 | 관리자가 해당 기능을 실행하는 조건을 검토; runtime nonroot만으로 삭제하지 않음 |

Debian은 자체 배포/패키지 관점의 triage임을 [공식 설명](https://security-team.debian.org/security_tracker.html)에
명시한다. 해당 source-package의 특정 기능이 검사한 바이너리에 들어 있는지, 어떤 입력에 노출되는지를
별도로 확인한다. systemd 프로세스 부재로 libsystemd0/libudev1의 14항목을 제외하지 않았고,
gcc-14-base의 문서-only 관측도 libgcc/libstdc++까지 확대하지 않았다.

### 실제 연결된 SQLite 14항목의 앱 인계

Python `_sqlite3`는 실제 `libsqlite3.so.0`에 연결됐고 SQLite 버전은 3.46.1이다.
일반 in-memory 조회에서 FTS3/4/5·FTS3_PARENTHESIS·RTree·Session compile option을 확인했다.
기능이 컴파일된 사실은 앱이 외부 입력으로 그 기능을 호출한다는 증거가 아니다.

| 항목 | 앱/복원 검토에 필요한 입력 조건 |
|---|---|
| CVE-2021-45346 | 변조 DB와 쿼리 조건, 공급자 dispute도 함께 대조 |
| CVE-2025-70873 | zipfile extension과 신뢰할 수 없는 ZIP 입력 |
| CVE-2026-119371·119376·119591 | 공격자가 제공하는 SQL 또는 DB view/표현식 |
| CVE-2026-119372 | FTS3/4의 특정 MATCH·snippet 조합 |
| CVE-2026-119373·119374 | FTS5 입력·손상 index/삭제 경로 |
| CVE-2026-119375 | 손상된 DB/WAL 파일의 수용·복원 경로 |
| CVE-2026-119377 | SQL 제공 가능성과 SQLite authorizer 의존 여부 |
| CVE-2026-119378 | RTree shadow table을 제어할 수 있는 입력 |
| CVE-2026-119379·50812·50813 | 외부 changeset/session extension API 경로 |

[Debian SQLite 기록](https://security-tracker.debian.org/tracker/source-package/sqlite3)과 선택한 CVE별
원문을 대조했다. 악성 DB/SQL을 실행하지 않았다. 채희주는 native library·기능 포함·파일/복원 신뢰 경계를
인계하고, 김택희는 실제 쿼리·parameter binding·authorizer·외부 DB/changeset 수용 여부를 독립 검토한다.

## 재현과 검증

공개 [입력 snapshot](infrastructure-results/c03-impact-inputs-20261105.json)은 공급자 구조화 사실과
고정 이미지 관측값을 담는다. 공개 snapshot은 공급자 서명이 아니라 운영자가 보관한 근거이며,
원본이 필요한 재검토에는 기록된 raw SHA-256과 출처를 확인한다. 이전 비교 JSON은 변경하지 않는다.

```powershell
.venv\Scripts\python.exe -m scripts.assess_supply_chain --input docs/infrastructure-results/c03-impact-inputs-20261105.json --input-sha256 97c6ef654e3cfae62207a7d1c879e5bd8a031b47ba050ace2a4beb484556669d --review docs/infrastructure-results/c03-findings-review-20261105.json --review-sha256 7008ffd6e02c886119ad91e54f8f6afe22c863d9f76be52f1830d2ee9286e3b2 --output runtime/c03/impact-new.json

.venv\Scripts\python.exe -m pytest tests/test_supply_chain_impact.py tests/test_supply_chain_review.py tests/test_supply_chain_comparison.py -q
```

종료0은 근거가 일치하는 **검토 보고서 생성**이며 보안 승인/취약점 게이트 통과가 아니다.
`security_gate_passed=false`와 `production_approved=false`를 유지한다. SHA-256·대상 이미지·패키지/
source version·공급자·범위·검사 권한·3회 관측·원본 200항목 연결이 맞지 않으면 거부하고 기존 출력을 덮어쓰지 않는다.
새 테스트38개와 기존 C03 69개, 집중 시험 **107개**가 통과했다. 전체 회귀는
**Windows 1,835 통과·2 건너뜀·기존 경고3(471.07초)**,
**Linux Docker 1,837 통과·기존 경고2(362.92초)**와 양쪽 Ruff 통과다.
두 전체 시험은 병행했으므로 시간 차이를 환경 성능 순위로 해석하지 않는다.
실제 공개 입력으로 Windows/Linux에서 각각 생성한 보고서는 바이트 동일했다.
단위 시험 이미지의 앱/스크립트/테스트 Python **178개**를 raw 지문으로 확인했다.
[실행 검증 요약](infrastructure-results/c03-impact-validation-20261105.json)에 로그·소스·관측 지문을 기록했다.

시험 컨테이너·단위 이미지 태그와 새로 불러온 과거 이미지 태그는 정리했다. 처음부터 보관하던 tar·스캐너
원자료·DB snapshot과 이번 vendor 원본은 근거로 보존한다. 기존 kind 컨테이너 ID/실행 상태와 두 ZIP의
지문을 유지했고 AWS·유료 LLM·실계정·OS 신뢰 설정 변경은 없다.

3회 실물 probe는 이미지 ID를 확인한 뒤 `python -I /probe.py`로 실행했다. 재현자는 먼저 같은 보관 tar의
지문을 확인하고, `scripts/supply_chain_runtime_probe.py`를 `/probe.py`에 읽기 전용으로 연결한다.
`docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges`
및 `/tmp`·`/data` tmpfs와 CPU/메모리/PID 제한을 유지한다. tar import는 기존 태그를 덮어쓰지 않도록
먼저 확인하며, 스캔 시 보관한 원본은 저장소 복제만으로 생기지 않는다.

## 다음 인프라 조치와 담당

1. 채희주: 패치 포함 Python runtime·digest를 실제 확인하고 builder/pip 입력을 고정한 별도 수정 PR을 만든다.
   전체 목록을 한 번에 0으로 만들려고 탐지/스캐너 억제나 무근거 예외를 추가하지 않는다.
2. 채희주: 새 앱 이미지·SBOM·두 스캐너 DB/버전을 다시 고정해 같은 조건으로 재검사한다.
   이번 과거 이미지 검토나 기존 CA/DB 실험을 새 이미지 성과로 바꾸지 않는다.
3. 김택희: 인계한 SQLite/base64/간접 기능의 실제 앱 입력 도달성과 상태 의미를 독립 대조한다.
   이 문서는 해당 작업을 대신 완료했다고 기록하지 않는다.
4. 공동: 새 고정 이미지의 mTLS·회수·복원 회귀와 독립 재현을 확인한 뒤 C03 선정/채택 근거를 갱신한다.
   기존 11/29 동결·12/6 제출 가능본 일정은 유지한다.
