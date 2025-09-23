# ASA Secure Config Audit

Минималистичный аудитор конфигураций Cisco ASA на PowerShell 5.1.

## Возможности
- Поиск any-any, широких сервисов (22/3389/5900/8080/8443/9090/9000–9010).
- Анализ IPv6 ACL (`any6 any6`) и привязок ACL к интерфейсам.
- Проверка weak crypto (IKEv1/v2, RSA <2048, SA lifetime), слабых transform-set'ов.
- Управление: Telnet/SSH/HTTP/ASDM/REST API, AAA, SNMP (включая v3 strength).
- NAT: any→any, широкие static/twice NAT, partner→dmz эвристики.
- MPF/Inspect: bypass `no inspect`, legacy/loosened инспекции.
- Логи, threat-detection, CRL/OCSP, дубликаты/шэдоуинг/непривязанные ACL.
- Отчёт в консоль + JSON, опциональная гистограмма severity.

## Быстрый старт
```powershell
# 1) Снять блокировку и запустить
Unblock-File .\src\asa_audit.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\asa_audit.ps1 -Path ".\samples\asa_test_conf.txt" -All -Chart
```

## Точные параметры
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\asa_audit.ps1 `
  -Path "<asa_config.txt>" `
  -All `
  -OutJson ".\asa_audit_report.json" `
  -Chart

# либо выборочно
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\asa_audit.ps1 `
  -Path "<asa_config.txt>" `
  -Checks ACLAnyAny,ACLRedundancy,SNMPv3Strength
```

## Примеры
См. `samples/` (псевдо-конфиги для теста эвристик).

## Тесты
Pester 5 (минимум):
```powershell
Invoke-Pester .\tests\AsaAudit.Tests.ps1
```

## Лицензия
MIT — см. `LICENSE`.
