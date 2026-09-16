# 기업 적용 준비도

## 현재 판정

버전 0.11.0은 OCSF 1.9.0 정규화와 Sigma 2.1 탐지 데이터 계보에 두 종류의 공개 공격 로그와 정상 로그를 이용한 정량 품질 게이트를 추가했다. 인증과 권한, 테넌트 격리, 요청 추적, 감사 무결성, 관측성과 자원 보호를 코드와 자동 테스트로 검증하고 KISA, 개인정보보호위원회, NIA, NIST, CISA, ENISA, OWASP와 MITRE 자료에서 도출한 18개 통제를 기계판독 대장으로 관리한다.

현재 통제대장은 구현 완료 9개, 부분 구현 5개, 계획 4개다. 가중 구현률은 63.89%지만 이는 인증이나 규정 준수율이 아니다. 공개 표본 12건에서는 Precision·Recall·F1 100%, 오탐률 0%, 파싱·OCSF 핵심 필드 매핑률 100%였지만, 이는 공개 양성 표본이 연결된 2개 규칙에 한정된다. 나머지 4개 규칙은 ‘표본 없음’으로 표시하며 규칙 상태도 계속 `test`다. 특정 기업의 IdP, SIEM, 전체 로그 분포, 개인정보 정책과 운영 절차가 연결되지 않았으므로 아직 운영 승인 또는 보안 인증을 받은 제품으로 간주하지 않는다.

## 적용한 보안 기준선

| 영역 | 구현 내용 | 검증 |
|---|---|---|
| 프로덕션 설정 | 인증이 꺼진 프로덕션 구성을 시작 단계에서 거부하고 API 문서를 비활성화 | 설정 검증 테스트 |
| 인증 | OIDC RS256 서명과 issuer, audience, exp, iat, sub 검증 | 정상·잘못된 audience 토큰 테스트 |
| 서비스 인증 | 원문 대신 SHA-256 해시를 저장하는 API 키 모드와 상수시간 비교 | 누락·정상 키 테스트 |
| 권한 | viewer, analyst, responder, admin 역할 계층 | 조회 허용·분석 거부 테스트 |
| 객체 접근 | 인증 토큰의 tenant_id로 결과·메트릭·검토 범위를 제한 | 테넌트 간 사건 조회 차단 테스트 |
| 감사 | 로컬 JSONL 기록을 SHA-256 해시 체인으로 연결하고 손상 시 추가 기록 거부 | 위변조·재시작 복원 테스트 |
| 클라우드 저장 | DynamoDB 항목에 테넌트 키와 payload 해시를 저장하고 테넌트 전용 인덱스로 조회 | 저장소 단위 테스트 |
| API 보호 | 허용 Host, 최대 1MiB 요청 본문, 보안 헤더, 분석 동시성 상한 | 헤더·과대 요청 테스트 |
| 추적성 | 모든 응답에 검증된 X-Request-ID를 반환하고 분석 결과에 요청·사용자 식별자 기록 | 요청 ID 회귀 테스트 |
| 관측성 | 경로별 요청 수와 응답시간을 관리자 전용 Prometheus 형식으로 제공 | 메트릭 엔드포인트 테스트 |
| 이벤트 정규화 | OCSF 1.9.0 Authentication·API Activity 분류, type UID, 원본 해시와 매핑 버전 | 클래스·해시·정답 분리·결정성 테스트 |
| 탐지 규칙 | Sigma 2.1 YAML, 수치·필드참조·필터 조건, 버전·승인·시험 메타데이터와 규칙집 해시 | 위협 5건·정상 3건 재생 및 미지원 규칙 거부 테스트 |
| 공개 로그 회귀 | 원본 커밋·라이선스·원본 및 표본 SHA-256을 고정하고 네트워크 없이 재생 | Splunk RDP·AWS 인증 실패 8건 탐지, Sentinel 정상 로그인 4건 오탐 0건 |
| 사고 상관분석 | 사용자·IP·30분 시간창으로 다중 규칙 및 다중 자원 반복 탐지를 Incident Finding 2005로 집계 | 순서 독립 사건 ID, 시간창·자원 임계값·공격 체인 테스트 |
| 탐지 품질 게이트 | 데이터셋별 기대 규칙·탐지·사고 수와 최소 품질 기준을 버전 관리 | Splunk RDP·AWS 인증 실패 8건, Sentinel 정상 4건, 규칙별 혼동행렬과 재현 지문 |
| 배포 입구 | Lambda 함수 URL의 기본·스크립트 배포 인증을 AWS IAM으로 고정 | 정적 구성 점검 |
| 통제 보증 | 18개 통제의 소유자·상태·기준·출처·증적·검토일과 SHA-256 대장 지문 | 스키마·중복·증적 경로·권한 테스트 |

통제 요약은 `/assurance/summary`, 관리자 상세 증적은 `/assurance/controls`에서 확인한다. `/health/ready`는 감사 로그, 통제대장, OCSF 매핑, Sigma 규칙집, 공개 표본 무결성과 정량 품질 게이트를 확인한다. 품질 기준 미달 시 준비 상태는 실패 폐쇄된다. 구현 완료 상태는 코드 또는 구성 증거와 자동 시험 증거가 모두 존재할 때만 허용한다. Sigma 통제는 공개 공격·정상 로그 회귀 증거가 연결되어 구현 완료로 판정했지만, 실제 조직 로그에서의 운영 승격은 별도 승인 대상이다.

## 운영 전 필수 게이트

다음 항목은 조직별 선택과 실제 운영 환경이 필요하므로 코드만으로 완료 처리하지 않는다.

1. 기업 IdP에서 발급한 실제 토큰으로 로그인, 역할 매핑, 사용자 비활성화와 키 회전을 시험한다.
2. API Gateway 또는 사내 게이트웨이에서 사용자·테넌트별 속도 제한, WAF, TLS 정책과 요청 로그를 적용한다.
3. 감사 이벤트를 SIEM과 변경 불가능한 보관소로 전송하고 보존 기간, 삭제 승인과 접근 권한을 확정한다.
4. 실제 데이터 분류에 맞춰 개인정보 최소화, 마스킹, 데이터 지역성과 LLM 공급자 전송 정책을 승인한다.
5. 운영 부하와 장애 조건에서 가용성, 백업 복원, RTO·RPO, 경보와 당직 절차를 훈련한다.
6. SAST, SCA, SBOM, 이미지 서명·스캔, DAST와 독립 침투시험의 발견 사항을 해소한다.
7. 모델 변경 승인, 프롬프트 공격 평가, 오탐·미탐 기준, 사람 검토 책임과 롤백 절차를 문서화한다.
8. 더 넓은 Loghub·OTRF·조직 로그 분포에서 파서 매핑률, 규칙별 precision·recall·FPR과 드리프트를 측정한 뒤 `test` 규칙의 `stable` 승격을 승인한다.

## 설계 기준

- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST SP 800-207A Cloud Native Access Control](https://csrc.nist.gov/pubs/sp/800/207/a/final)
- [OWASP API Security Top 10 2023](https://owasp.org/projects/api-security-project)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [KISA 제로트러스트 가이드라인 2.0](https://www.kisa.or.kr/2060204/form?page=1&postSeq=18)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
- [UK AI Cyber Security Code of Practice](https://www.gov.uk/government/publications/ai-cyber-security-code-of-practice)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OCSF 1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/v1.9.0)
- [Sigma Specification 2.1](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [OCSF 1.9.0 Incident Finding](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/events/findings/incident_finding.json)
- [Splunk Attack Data](https://github.com/splunk/attack_data)
- [Microsoft Sentinel Sample Data](https://github.com/Azure/Azure-Sentinel/tree/master/Sample%20Data)

NIST의 원칙에 따라 네트워크 위치만으로 신뢰하지 않고 사용자·서비스 신원과 자원 접근 정책을 요청마다 확인한다. OWASP API Security의 객체 수준 권한·인증 위험을 줄이기 위해 테넌트 범위 조회와 역할 검사를 각 API 함수에 적용한다.
