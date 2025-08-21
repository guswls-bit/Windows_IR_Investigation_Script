# 윈도우 Incident Response 자동 수집/분석 스크립트

이 저장소는 **Windows 환경에서 침해사고 대응(Incident Response)** 및 **디지털 포렌식**을 위한 PowerShell 자동화 스크립트를 제공합니다.  
해당 스크립트는 주요 아티팩트(Artifacts)를 수집하고, 자동 분석을 수행하여 **사고 분석 보고서**를 생성합니다.

---

## 📌 주요 기능

### 1. 아티팩트 수집
- **시스템 및 패치 정보**
  - `Get-ComputerInfo` → `system_info.txt`
  - `Get-HotFix` → `installed_hotfix.txt`
- **프로세스 & 서비스**
  - 실행 중인 프로세스 목록 → `process_list.csv`
  - 서비스 목록 → `service_list.csv`
- **네트워크 정보**
  - `netstat -ano` → `netstat.txt`
  - TCP/UDP 연결 정보 → `net_tcp.csv`, `net_udp.csv`
- **사용자 & 로그**
  - 로컬 사용자 계정 → `local_users.csv`
  - 보안 로그 최근 300개 → `security_log_recent.csv`
- **지속성(Persistence) 아티팩트**
  - 레지스트리 Run Key → `registry_run.txt`
  - 예약 작업 → `scheduled_tasks_raw.csv`

### 2. 자동 분석
- **프로세스 분석**
  - 코드 서명 여부 (서명됨 / 서명 안 됨)
  - 실행 경로 기반 의심 프로세스 탐지 (`AppData`, `Temp`, `Recycle.Bin` 등)
  - 결과 → `process_findings.csv`
- **네트워크 이상 징후 탐지**
  - 비정상 포트 리스닝 탐지
  - 서명되지 않은 프로세스의 네트워크 리스닝 탐지
  - 결과 → `net_findings.csv`
- **지속성(Persistence) 메커니즘 탐지**
  - 레지스트리 Run Key
  - 예약 작업
  - 서비스
  - 결과 → `persistence_findings.csv`
- **파일 해시 및 IOC 매칭**
  - 실행 파일의 SHA256 해시 계산
  - `iocs.txt`와 매칭하여 알려진 악성코드 탐지
  - 결과 → `file_hashes.csv`, `ioc_hits.csv`
- **Sysmon 이벤트 분석 (설치 시)**
  - 의심스러운 프로세스 생성 이벤트
  - 외부 네트워크 연결 이벤트
  - 결과 → `event_findings.csv`

### 3. 요약 보고서 생성
- 종합 분석 요약
  - 의심 프로세스
  - 비정상 네트워크 리스닝
  - 지속성 아티팩트
  - IOC 매칭 결과
  - Sysmon 탐지 이벤트  
- 결과 → `summary.csv`

---

## 📂 출력 구조

스크립트 실행 후 아래와 같은 구조로 결과가 생성됩니다.


