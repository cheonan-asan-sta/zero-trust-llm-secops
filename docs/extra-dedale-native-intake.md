# DEDALE native syslog의 제한 수집·형식 검증 — v126

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 목표 active

**새 자료 수집과 재현 가능한 검사기를 완료했다. 탐지 성능 개선을 채택한 결과는 아니다.**
기존 공유 감사·VPN F1은 각각80%이며 원래1,681,815행의 수치·라벨·분모를 유지한다.
원래6영역·5축의 독립 인수, VPN FP42와 별도 Wheeler FN9, 공유 감사 Fox FN2는 남아 있다.
목표 전 push·새 CI·병합·유료 호출·AWS·8시간 soak는 계속 보류한다.

## 무엇을 확보했나

[DEDALE 발행 메타데이터](https://entrepot.recherche.data.gouv.fr/api/datasets/:persistentId/?persistentId=doi:10.57745/Y5JLDG)의
**3.0 버전**을 고정했다. 현재 확인한 release는2026-11-13이며 검색 결과의 옛2.0과 구분한다.
`license=null`만 보고 사용 조건을 추정하지 않고 해당 버전 `termsOfUse`의 CC BY4.0 명시를 확인했다.
출처: Lanvin, Maxime; Majorczyk, Frederic, *DEDALE: Dataset for Evaluating Detection of APT among Logs and Events*,
[DOI](https://doi.org/10.57745/Y5JLDG). 발행자는 Windows/Linux host 자료와 network 자료를 별도로 제공한다.
공격이 포함된 기간에도 정상 활동이 있어 기간 전체를 악성으로 채우지 않는다.

큰 PCAP·auditbeat·winlogbeat 전체를 받는 대신 사전 계약으로 syslog ZIP 하나를 선정했다.
정답 ZIP·userbehaviour/생성기·공격 시나리오·라벨링 코드 본문은 열지 않았다.

| 검증 항목 | 실제 결과 |
|---|---|
| 게시 파일 | `system_logs_syslog.zip`, file ID717890 |
| 완전한 ZIP 크기 |125,537,856바이트 |
| 게시 MD5 |`8223168b7cf857c40a2f0d84a1eab885` 일치 |
| 로컬 SHA256 |`d7b94d9c6df0dbe22ac31ccc0898471d05d4bc5bc290dc4c224c757c1c373ea7` |
| ZIP 목록 |674개 항목. 모든 항목의 본문·CRC를 개별 검증했다는 뜻은 아님 |
| 고정 선택 |이름 사전순 첫 일반 member 하나, 선택 변경·정답 기반 선택0 |
| 선택 member |`daily_syslog/D10_H0_2025-01-01T00_syslog_F217.jsonl.bz2` |
| 선택 member 무결성 |저장 바이트84,856·CRC32 `ce4b8f37`·SHA256 `ec0cab8cd6f59f94323e47d0a5fa83b2c3bc853ffcb281539b5930b7fb862bac` |
| 내부 bzip2 해제 |단일 완전 stream,1,884,161바이트·SHA256 `66b844e315ef5cb80c3b3998c222e52fbb4c0941121e25d1b313ea60f4277000` |
| 실제 형식 조사 |해제된 첫128개 물리 행, JSON 오류0. 나머지는 해시/EOF 확인만 수행 |
| 자료 역할 |개발 형식 probe. 학습·예측·정답 부여0, 새 독립 인수 사례0 |

처음에는 내부 bzip2를 JSON으로 오인해128개 **압축 바이트 조각**의 파싱 실패를 기록했다.
이 기록을 지우거나 원본 로그128개의 오류라고 해석하지 않았다. 원본·선택을 유지한
[해제 수정 계약](../infra/f1-lab/dedale-syslog-decoding-v126.json)을 native 본문 해석 전에 추가했다.
수정한 검사기는 끝까지 CRC·bzip2 EOF·크기·해시를 검증한다. 정상으로 채우거나 어려운 행을 버리지 않는다.

## 지금 확인한 근거와 아직 없는 것

선언한128행 모두 `message`·`program`·`host`·`logsource`·시각 필드가 있었고,
113행에는 양의 정수로 읽히는 `pid` 문자열이 있었다.15행의 PID는 없는 상태로 남긴다.
표본의 구조화 필드에는 UID/GID·검증한 사람 신원·기기 건강·현재 권한 정책이 없었다.
메시지 본문이나 다른 파일에도 관련 정보가 전혀 없다는 결론은 아니다.

`facility_label`·`severity_label`은 syslog 분류 이름이며 악성 정답이 아니다.
`@timestamp`·`timestamp`·`timestamp8601`의 존재만으로 센서 시각·수집 시각·프로젝트 앱 수신 시각을 같게 취급하지 않는다.
로그의 host/PID/program 역시 실제 사람·기기 신뢰·허용된 행위·정확한 실행 명령을 자동 증명하지 않는다.
과거 AIT 행에 이2025년 별도 자료의 신원을 붙이지 않는다.

이번 원본·선택 member·해제 source의 지문과 읽은128행의 지문은
[v126 노출 대장](../infra/f1-lab/observed-source-exposure-v126.json)에 추가했다.
기존 source ID/payload/pattern을 보존하며 DEDALE을 개발 관측으로 기록한다.
나머지 파일을 아직 안 읽었다는 이유만으로 같은 출처의 새 독립 최종 분할을 승인하지 않는다.

## VPN 후보와 다른 자료 검토

IANA의 고정 포트 범주만으로 R/S/Shaw/Wheeler training을 조사했다.
[IANA 범주](https://www.iana.org/assignments/service-names-port-numbers/)는 system0–1023,
user1024–49151, dynamic/private49152–65535다. user와 dynamic 양쪽에 training 위협이 있어
단독 정상 완화 기준으로 채택하지 않았다. 실제 포트/IP 값을 외우지 않았으며 등록 포트라는 이유로 신뢰하지 않는다.
새 head 적합·전체 탐지 재생·기존 위험 유지 변경은0이다.

OpTC는 [이전 스키마 검토](extra-optc-observation-review.md)의 후속으로 공개 폴더 목록을 더 확인했다.
native 본문/정답은 받지 않았고, 기존 문서의 결함·미상 PID/UUID·principal과 권한의 구분을 유지한다.
[발행자](https://github.com/FiveDirections/OpTC-data)의 결측이 있는 short 자료를 독립 평가로 선택하지 않았다.
[CERT](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)는 발행 메타데이터·README·체크섬만 확인했다.
별도 합성 내부자 위협 자료이며 원시·정답 다운로드0, 기존 AIT의 누락된 기기/권한 사실을 보완한 것은 아니다.

## 코드·검증·재현

[검사기](../scripts/inspect_dedale_syslog.py)와 [단일 bzip2 stream 처리](../scripts/f1_lab/nested_bzip2_probe.py)를 추가했다.
고정 source/계약 SHA·게시 MD5·첫 member·CRC·해제 EOF를 확인하고 출력의 덮어쓰기,
중복 ZIP 이름·숨은 이름 정규화·경로/링크·다중 stream·끝의 추가 바이트·잘린 stream·해제 과다를 거부한다.
잘못된 JSON·중복 key·비유한 수·비객체 행은 조사 prefix에 오류로 보존한다.
성공한 검사도 사람/권한 승인·탐지 TP·독립 인수로 승격하지 않는다.

관련 **Windows120건, Linux120건 통과**, 최종 실패/error/skip0이며 새46건+기존74건이다.
Linux 전체 Ruff+RUF100도 통과했다. 최초 Windows 경로 제어군 실패를 수정해
`orig_filename`과 정규화된 이름의 차이도 거부한다. 최초 Linux는 Ruff에서 멈췄으며 최종 실행과 구분한다.
Windows/Linux의 실제 native prefix·128행 지문·전체 해제 해시가 같았다.
이120건을 직전1,244건과 더해 프로젝트 전체 통과 수로 표현하지 않는다.
새 분류 모델·운영 기본 경로를 바꾸지 않아1,681,815행 탐지 재생을 반복하지 않았다.

이미 받은 ZIP에 대해 저장소 루트에서 실행한다. 출력은 새 경로를 사용한다.

```powershell
.venv\Scripts\python.exe -m scripts.inspect_dedale_syslog --source <검증할-system_logs_syslog.zip-경로> --intake infra/f1-lab/dedale-syslog-intake-v126.json --intake-sha256 e6f51d86426ef401fb58ec4fda7adc5e40bb4cd62fe97234a82e7c2dfe9135fa --decoding infra/f1-lab/dedale-syslog-decoding-v126.json --decoding-sha256 b2a34bab9364adf6d4679f5d2ced3fe5217e490e76477c4ee9253adef1996779 --directory runtime/f1/dedale-schema-reproduction-new
.venv\Scripts\python.exe -m pytest -q tests/test_nested_bzip2_probe.py tests/test_dedale_syslog_probe.py tests/test_f1_native_jsonl.py tests/test_f1_evaluation_preparation.py
```

다음에는 이 source의 시간 필드 의미·프로세스 연결·신원/권한 결측과 별도 라벨 대응 근거를 먼저 확인한다.
해당 검증 없이 학습·신뢰 보정·기존 지표 합산을 시작하지 않는다. 원래6영역/5축·95%/5% 조건은 그대로다.
이번 기능/검사 컨테이너2개는 모두 소유 ID를 확인해 제거했고 새 image build/pull·volume 삭제0이다.
요청한 오래된 Docker 정리는 [v122](extra-vpn-packet-data-review.md)에서 완료했다.

[공유 근거 JSON](infrastructure-results/extra-dedale-intake-v126-20261117.json) ·
[실제 Linux JUnit](infrastructure-results/extra-dedale-intake-v126-20261117.xml) ·
[원래 수집 계약](../infra/f1-lab/dedale-syslog-intake-v126.json)
