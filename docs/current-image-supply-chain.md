# 현재 앱과 관측 이미지 공급망 재검사

11월에 다시 수립한 개발 로드맵의 C03/I8 후속이다. 채희주 담당인 이미지·검사 환경 구성과 실행·측정,
원자료 검증을 묶는다. 개발 계획의 주차나 날짜를 완료 판정으로 사용하지 않는다.

## 실행 범위

현재 저장소의 Dockerfile로 앱 이미지를 빌드하고, 기존 관측 이미지 빌더로 그 위에 고정된
Prometheus/Alertmanager 도구를 추가한다. 실제 서비스를 기동하거나 운영 키를 만들지 않는다.
두 이미지의 Linux amd64·소스/런타임 설치 파일 LF 지문, Python/SQLite/pip/HTTP 패치23개,
관측 바이너리 지문과 앱 레이어 상속을 확인한다. 검증은 신뢰하는 로컬 호스트의 기록이며 원격 증명이 아니다.

과거 검사 DB와 결과를 보존한다. 공개 검사 도구의 고정 배포 자산 지문과 기존 서명 검증 기록을 다시
대조하고, 과거 DB를 별도 소유 볼륨에 복사한다. **복사본만 갱신**하고 앱 검사의 갱신된 DB를
다시 복사하여 관측 이미지에도 사용한다. 두 이미지의 실제 DB 파일 지문이 같아야 한다.
기존 Sigstore 검증을 재사용했음을 표시하며 새로운 서명 검증/출처 attestation으로 확대하지 않는다.

DB 준비 단계만 네트워크를 허용한다. 준비 뒤 버전/DB 상태·warm-up·각3회 검사·양/음성 대조군은
network none·UID10001·read-only root·capability 제거·CPU/메모리/PID 제한으로 실행한다.
현재 두 이미지에는 공통으로1536MiB /tmp tmpfs를 사용한다. 약934MB 관측 이미지의 레이어를
푸는 과정에서 기존512MiB 공간이 소진되어 조정한 값이다. CPU2·전체 메모리/메모리+swap2GiB·PID128
경계는 유지하며, 과거512MiB 조건의 실행시간과 직접 성능 비교하지 않는다.
Grype의 age validation을 끄지 않는다. 두 공급자의 DB 시각은 UTC이며 관측 시점 기준120시간 이내,
미래 편차 최대10분으로 검사한다.120시간은 Grype 기본 경계를 공통 비교 조건으로 선택한 것이며
Trivy의 기본 정책이라고 주장하지 않는다.

Trivy 이미지/대조군 분석은 명시적으로15분의 제한시간을 둔다. 현재 이미지의 최초 warm-up이
기본 제한시간에 도달해 실패한 기록을 보존한 뒤 적용한 실행 예산이며, 검사 생략이나 발견 억제가 아니다.
과거 기본 설정으로 수집한 실행시간과 직접 성능 비교하지 않는다. Windows의 Docker inspect 출력은
시스템 cp949 대신 UTF-8로 읽어 한글 호스트 경로가 포함되어도 소유권 검사·정리 근거를 보존한다.

[Grype DB 설정](https://oss.anchore.com/docs/reference/grype/configuration/)과
[Trivy DB 관리](https://trivy.dev/docs/latest/configuration/db/)를 참고한다.
[Trivy 제한시간 안내](https://trivy.dev/docs/v0.76/guide/references/troubleshooting/#timeout)도 따른다.

## 근거 검증과 해석

- 요약 파일은 별도로 확인한 SHA256으로 고정하고, 원본 JSON/metrics의 크기·지문을 대조한다.
- 같은 이미지 ID·검사기 버전·3반복과 warm-up의 패키지/발견 일치·명령 종료0을 확인한다.
- requests2.31.0/2.32.0의 특정 공지 존재/부재 대조군을 다시 검사한다. 다른 공지 전체의 음성은 아니다.
- 설치 metadata와 Debian/Python 식별의 누락/추가를 그대로 남긴다. 바이너리 내장 구성요소의 발견도
  보존하며 다른 ecosystem의 이름이 같다는 이유로 자동 합치지 않는다.
- 각 검사기의 모든 native package/version/advisory를 독립 영향 검토 대장으로 남긴다. 발견을
  삭제·억제하거나 버전 경고만으로 악용 가능성/패치 완료/오탐을 판정하지 않는다.
- 과거 패치 이미지와 DB 모두 달라질 수 있으므로 발견 수 증감을 패치 효과나 검사기 정확도로 해석하지 않는다.

이번 대상은 **앱과 Prometheus/Alertmanager 이미지 두 개**다. NGINX·CA·PostgreSQL·Lambda·테스트
이미지 전체를 검사한 것이 아니다. C03의 운영 선정, 김택희의 앱 입력 도달성/영향 독립 검토와
상대 환경 재현은 별도다. C01/C02 조건부 판정과 탐지 규칙·임계값·평가 기준선은 유지한다.

## 재현

```powershell
.venv/Scripts/python.exe -m scripts.test_current_supply_chain_runtime --directory runtime/c03/current-images-fresh
```

새 디렉터리만 허용한다. 원본 이미지/DB·다른 실습 컨테이너는 정리 대상이 아니다. 실행 중 생성한
검사 컨테이너·runner image·복사 DB는 소유 label을 확인해 정리하고, 입력 이미지와 tar/원자료는
재현을 위해 남긴다. 이미지·큰 DB·raw 결과를 GitHub에 올리지 않는다. AWS·유료 모델 호출은 없다.
후속 복사 컨테이너가 앞선 DB를 읽기 전용으로 참조하므로, 모든 검사 컨테이너를 먼저 정리한 뒤
복사 DB 볼륨을 제거한다. 정리 실패는 원래 검사 실패와 별도로 기록하고 성공으로 덮어쓰지 않는다.

## 결과

실제 로컬 실행 결과와 소스 지문은 검증 완료 후 별도 JSON으로 기록한다. 이 문서의 절차 정의만으로
현재 이미지 검사 완료나 운영 보안 게이트 통과로 처리하지 않는다.
