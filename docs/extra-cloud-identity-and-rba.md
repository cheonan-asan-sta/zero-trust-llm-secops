# extra: 서비스 호출 주체의 연결 근거와 RBA 수집

2026-11-12 · [v25 과거 이력 진단](extra-cloud-causal-context.md)의 후속이다.
**새 분류 성능·독립 평가·목표 달성 기록이 아니다.** 원래 여섯 영역, 원본 앱과 정답, 최종 자료 격리를 유지한다.

## AWSService의 실제 원래 주체를 확인할 수 있나

고정 CloudTrail 학습 원본20,711건을 [사전 감사 계약](../infra/f1-lab/cloud-identity-audit-protocol.json)에 따라 조사했다.
이미 관찰한 학습 자료만 사용하며 각 원본 SHA256을 실행 전후 확인했다.
[CloudTrail 공식 신원 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)에서
principal·세션·원래 신원·서비스 이름·위임 자원의 의미를 대조했다. 서비스 이름은 호출한 AWS 서비스 정보이며 원래 사용자의 식별자가 아니다.

| 원본의 주체 종류 | 행 수 | principal 있음 | ARN 있음 | 세션 발급 역할 ARN 있음 |
|---|---:|---:|---:|---:|
| AssumedRole | 15,241 | 15,241 | 15,241 | 15,241 |
| IAMUser | 1,957 | 1,957 | 1,952 | 0 |
| AWSAccount | 391 | 379 | 0 | 0 |
| AWSService | 3,107 | 0 | 0 | 0 |
| Unknown | 15 | 0 | 0 | 0 |

AWSService3,107건(정상3,059·공격48)에는 서비스 이름과 sharedEventID/requestID는 있지만
principal·ARN·계정·accessKeyId·credentialId·sourceIdentity·signInSessionArn·onBehalfOf·inScopeOf의 선언된 주체 연결 필드는 없었다.
이것은 조사한 정확한 필드 경로의 결과이며 모든 가능한 별칭/외부 자료까지 없다는 주장은 아니다.

principal/ARN/자격 식별자/세션 ARN/sharedEventID의 정확한 일치로 다른 종류의 알려진 주체와 연결되는 후보도0건이었다.
[공식 sharedEventID 설명](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)과 대조하며
이벤트 복제/동일 작업의 연관성을 신원·권한 검증으로 확대하지 않았다. 고유 후보가 있어도 검증 완료로 처리하지 않는 진단이다.
계정 하나·서비스 이름·출발 IP·가까운 시각·공격 이름만으로는 조인하지 않는다. 원시 식별자/자격 증명 출력·반출0이다.

따라서 v25의 모호한 공격48건에 principal 이력을 만들어 넣지 않았다.
현재 CloudTrail 프로필의 동시 품질 목표 미달은 그대로이며, 부족한 주체 근거를 임의 보완해 수치를 높이지 않는다.
현재 신뢰·기기 상태·자원 소유 정책·업무 승인·실제 권한 위반 정답을 새로 검증한 것은 아니다.

## 인증 영역을 위한 다른 공개 자료 수집

[발행자 RBA v1.0.0](https://zenodo.org/records/6782156)은 실제 로그인 행동에서 합성한 특징 자료다.
계정 탈취 여부는 원 서비스의 사고 대응 식별에 관한 라벨로 설명되며 알려진 공격 IP 플래그와 구분한다.
특징값 자체는 인공적이고 생산 IDS에 쓰지 말라는 발행자 제한이 있다. 연구용 오프라인 검토에만 사용한다.
실패 로그인·공격 IP·계정 탈취·인가 거부를 같은 정답으로 취급하지 않는다.

- 고정 record6782156·버전v1.0.0·CC-BY-4.0.
- 파일 `rba-dataset.zip`:1,093,700,330바이트, 발행자 MD5 `cc1b1078b3929650e6c08678caffcc57`.
- [자산 계약](../infra/f1-lab/public-assets-rba.json)과 [수집/검토 계약](../infra/f1-lab/rba-intake-protocol.json)을 본문 열람 전에 기록했다.
- 기존 수집기의 자산/range 상한만1GiB에서2GiB로 조정했다.4MiB 범위·정확한 Content-Range/길이·재시도8·1시간·여유 공간 검사와
  버전/라이선스/전체 크기/MD5/SHA 검증은 유지한다. 다른 출처/예상하지 않은 전체 응답은 받지 않는다.
- 범용 ZIP의512MiB 멤버 복사 상한은 그대로다. 큰 CSV를 통째로 풀지 않는다.

**v26 근거 시점에는 수집 진행 중이며 전체 체크섬 검증이 끝나지 않았다. CSV 본문 열람0이다.**
중간 progress와 살아 있는 도구 세션을 확인했지만 다운로드 완료나 최종 성능으로 기록하지 않는다.
최신 종료 결과는 `runtime/f1/public-rba-20261112/acquisition.json`과 실행 세션을 함께 확인해야 한다.

후속 순서는 전체 파일 검증→ZIP 인덱스 점검→별도 제한 리더로 헤더/첫128개만 개발 probe→
정답 의미·주체/시간/중복 분할 계약 검토다. 나머지 행은 그 전에 최종 평가로 읽거나 모델에 넣지 않는다.
부분 읽기만으로 CSV 전체 CRC를 확인했다고 쓰지 않는다. 관찰한 probe/주체를 미관찰 최종 자료로 재사용하지 않는다.

RBA는 인증/계정 탈취에 대한 보조 자료일 뿐 기존 기기·권한·측면 이동·유출·원격 영역과 부족한 승인/정책 정답을 대신하지 않는다.
여섯 영역의 독립 평가·최종 후보 선정·P/R/F1 각각95% 및 FPR5% 이하 달성은 계속 미완료다.

## 검증과 실행 구분

CloudTrail 감사와 수집 상한 변경의 관련 Windows227개·격리 Linux227개 검사를 수행했다.
정확한 연결의 모호성/계정 범위, 서비스 이름/IP로 잘못 연결하지 않음, 식별자 비노출,
변경된 소스/테스트 경로 거부,1GiB를 넘는 range의 오프셋/길이와2GiB 초과 사전 거부를 포함한다.
실제 대용량 네트워크 수집 성공은 이 모의 검사 통과와 구분한다.
Linux 실행 전후 소스 지문·소유 시험 컨테이너 정리를 확인한다. 데이터 수집 Python 프로세스는 Docker 자원이 아니다.
기존 장시간 시험은 [v15 정리 근거](infrastructure-results/extra-interrupted-cleanup-v15-20261112.json)의 미완료를 유지한다.
[v26 근거](infrastructure-results/extra-cloud-identity-rba-v26-20261112.json)에 실행별 결과·자료 지문·수집 중간 시점을 고정한다.
원본 앱·기존 라벨 유지, AWS·유료 API·GitHub 업로드0이다.
