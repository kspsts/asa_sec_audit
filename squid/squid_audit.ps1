<#
  squid_audit.ps1 — PowerShell 5.1-совместимый аудит squid.conf
  Запуск:
    powershell -ExecutionPolicy Bypass -File .\squid_audit.ps1 -Path C:\etc\squid\squid.conf -Format Table
    powershell -ExecutionPolicy Bypass -File .\squid_audit.ps1 -Path C:\etc\squid\squid.conf -Format Json > report.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$Path,
  [ValidateSet('Table','Json')]
  [string]$Format = 'Table'
)

#----------------------------- Классы -----------------------------
class Acl {
  [string]$Name; [string]$Type; [string[]]$Args; [int]$Line; [string]$File
  Acl([string]$n,[string]$t,[string[]]$a,[int]$l,[string]$f){$this.Name=$n;$this.Type=$t;$this.Args=$a;$this.Line=$l;$this.File=$f}
}
class HttpRule {
  [string]$Action; [string[]]$Verbs; [string[]]$Terms; [string]$Raw; [int]$Line; [string]$File
  HttpRule([string]$a,[string[]]$v,[string[]]$t,[string]$r,[int]$l,[string]$f){$this.Action=$a;$this.Verbs=$v;$this.Terms=$t;$this.Raw=$r;$this.Line=$l;$this.File=$f}
}
class Model {
  [hashtable]$Acls = @{}
  [System.Collections.Generic.List[HttpRule]]$HttpAccess = [System.Collections.Generic.List[HttpRule]]::new()
  [System.Collections.Generic.List[HttpRule]]$HttpReplyAccess = [System.Collections.Generic.List[HttpRule]]::new()
  [System.Collections.Generic.List[string]]$SafePorts = [System.Collections.Generic.List[string]]::new()
  [System.Collections.Generic.List[string]]$SslPorts  = [System.Collections.Generic.List[string]]::new()
  [System.Collections.Generic.List[hashtable]]$HttpPorts = [System.Collections.Generic.List[hashtable]]::new() # @{Port=;Opts=;Line=;File=}
  [System.Collections.Generic.List[hashtable]]$SslBump   = [System.Collections.Generic.List[hashtable]]::new() # @{Raw=;Line=;File=}
  [System.Collections.Generic.List[pscustomobject]]$Records = [System.Collections.Generic.List[pscustomobject]]::new() # File/Line/Text
  [bool]$AuthRequiredUsed = $false
}
class Finding {
  [string]$Id; [string]$Severity; [Nullable[int]]$Line; [string]$File; [string]$Message; [string]$Recommendation; [string]$Evidence
  Finding([string]$id,[string]$sev,[Nullable[int]]$ln,[string]$file,[string]$msg,[string]$rec,[string]$ev){
    $this.Id=$id;$this.Severity=$sev;$this.Line=$ln;$this.File=$file;$this.Message=$msg;$this.Recommendation=$rec;$this.Evidence=$ev
  }
}

#----------------------------- Утилиты (.NET only) -----------------------------
function Test-FileExists {
  param([string]$FilePath)
  try { return [System.IO.File]::Exists($FilePath) } catch { return $false }
}
function Read-FileLines {
  param([string]$FilePath)
  try { return [System.IO.File]::ReadAllLines($FilePath) } catch { return @() }
}
function Get-DirFromPath {
  param([string]$PathIn)
  try { return [System.IO.Path]::GetDirectoryName($PathIn) } catch { return "" }
}
function Is-PathRooted {
  param([string]$P)
  try { return [System.IO.Path]::IsPathRooted($P) } catch { return $false }
}
function Join-PathSafe {
  param([string]$Base,[string]$Child)
  try { return [System.IO.Path]::GetFullPath(( [System.IO.Path]::Combine($Base,$Child) )) } catch { return $Child }
}
function GetFiles-ByMask {
  param([string]$Dir,[string]$Mask)
  try { return [System.IO.Directory]::GetFiles($Dir,$Mask,[System.IO.SearchOption]::TopDirectoryOnly) } catch { return @() }
}

function Load-Lines {
  param([string]$FilePath)
  if(-not (Test-FileExists $FilePath)){ throw "Файл не найден: $FilePath" }
  $raw = Read-FileLines $FilePath
  $out = New-Object System.Collections.Generic.List[pscustomobject]
  $buf = ''; $startLine = 0
  for($i=0;$i -lt $raw.Count;$i++){
    $ln = $i+1
    $line = [regex]::Replace($raw[$i], '\s*#.*$', '')
    $line = $line.TrimEnd()
    if([string]::IsNullOrWhiteSpace($line) -and -not $buf){ continue }
    if($line.EndsWith("\")){
      if(-not $buf){ $startLine = $ln }
      $buf += ($line.Substring(0,$line.Length-1) + ' ')
    } else {
      if($buf){
        $buf += $line
        $out.Add([pscustomobject]@{ Line=$startLine; Text=$buf.Trim() })
        $buf=''; $startLine=0
      } else {
        $out.Add([pscustomobject]@{ Line=$ln; Text=$line.Trim() })
      }
    }
  }
  if($buf){ $out.Add([pscustomobject]@{ Line=$startLine; Text=$buf.Trim() }) }
  return $out
}

function Resolve-Includes {
  param([string]$BaseFile, [hashtable]$Visited)

  if(-not $Visited.ContainsKey($BaseFile)){ $Visited[$BaseFile]=$true } else { return @() }

  $baseDir = Get-DirFromPath $BaseFile
  $lines = Load-Lines -FilePath $BaseFile
  $recs  = New-Object System.Collections.Generic.List[pscustomobject]

  foreach($rec in $lines){
    $ln   = [int]$rec.Line
    $text = [string]$rec.Text
    if(-not $text){ continue }

    $toks = $text -split '\s+'
    if(($toks.Count -ge 2) -and ($toks[0].ToLower() -eq 'include')){
      # поддерживаем шаблоны: include conf.d/*.conf
      $pattern = $toks[1]
      if(-not (Is-PathRooted $pattern)){ $pattern = Join-PathSafe $baseDir $pattern }

      $dir  = Get-DirFromPath $pattern
      if([string]::IsNullOrWhiteSpace($dir)){ $dir = $baseDir }
      $mask = try { [System.IO.Path]::GetFileName($pattern) } catch { $pattern }

      $files = GetFiles-ByMask -Dir $dir -Mask $mask
      foreach($f in $files){
        $nested = Resolve-Includes -BaseFile $f -Visited $Visited
        foreach($n in $nested){ $recs.Add($n) }
      }
      continue
    }

    $recs.Add([pscustomobject]@{ File=$BaseFile; Line=$ln; Text=$text })
  }

  return ,$recs
}

#----------------------------- Парсер -----------------------------
function Parse-SquidConfig {
  param([string]$RootFile)
  $m = [Model]::new()
  $visited = @{}
  $records = Resolve-Includes -BaseFile $RootFile -Visited $visited
  foreach($r in $records){ $m.Records.Add($r) }

  foreach($rec in $records){
    $ln = [int]$rec.Line
    $line = [string]$rec.Text
    $file = [string]$rec.File
    if(-not $line){ continue }

    $toks = $line -split '\s+'
    if(-not $toks){ continue }
    $head = $toks[0].ToLower()

    switch($head){
      'acl' {
        if($toks.Count -ge 3){
          $name = $toks[1]; $type = $toks[2]; $args = @()
          if($toks.Count -gt 3){ $args = $toks[3..($toks.Count-1)] }
          $acl = [Acl]::new($name,$type,$args,$ln,$file)
          $m.Acls[$name] = $acl
          if($name.ToLower() -eq 'safe_ports'){ foreach($a in $args){ $m.SafePorts.Add([string]$a) } }
          if($name.ToLower() -eq 'ssl_ports'){  foreach($a in $args){ $m.SslPorts.Add([string]$a) }  }
        }
      }
      'http_access' {
        if($toks.Count -ge 2){
          $action = $toks[1].ToLower()
          $rest = @(); if($toks.Count -gt 2){ $rest = $toks[2..($toks.Count-1)] }
          $verbs = @()
          if($rest.Count -gt 0 -and $rest[0] -match '^[A-Za-z]+$' -and @('CONNECT','GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','TRACE') -contains $rest[0].ToUpper()){
            $verbs = @($rest[0].ToUpper())
            if($rest.Count -gt 1){ $rest = $rest[1..($rest.Count-1)] } else { $rest = @() }
          }
          $rule = [HttpRule]::new($action,$verbs,$rest,$line,$ln,$file)
          $m.HttpAccess.Add($rule)
          $hasProxyAuth = $false
          foreach($t in $rest){ if($t.ToLower().TrimStart('!') -eq 'proxy_auth'){ $hasProxyAuth = $true; break } }
          if($hasProxyAuth){ $m.AuthRequiredUsed = $true }
        }
      }
      'http_reply_access' {
        if($toks.Count -ge 2){
          $action = $toks[1].ToLower()
          $rest = @(); if($toks.Count -gt 2){ $rest = $toks[2..($toks.Count-1)] }
          $rule = [HttpRule]::new($action,@(),$rest,$line,$ln,$file)
          $m.HttpReplyAccess.Add($rule)
        }
      }
      'http_port' {
        if($toks.Count -ge 2){
          $port = $toks[1]
          $opts = @(); if($toks.Count -gt 2){ $opts = $toks[2..($toks.Count-1)] | ForEach-Object { $_.ToLower() } }
          $m.HttpPorts.Add(@{ Port=$port; Opts=$opts; Line=$ln; File=$file })
        }
      }
      'ssl_bump' { $m.SslBump.Add(@{ Raw=$line; Line=$ln; File=$file }) }
      default { }
    }
  }
  return $m
}

#----------------------------- Проверки -----------------------------
function Run-SquidChecks {
  param([Model]$Model)
  $find = New-Object System.Collections.Generic.List[Finding]

  # 1) allow all/any и пустое allow
  foreach($r in $Model.HttpAccess){
    if($r.Action -eq 'allow'){
      if(-not $r.Terms -or $r.Terms.Count -eq 0){
        $find.Add([Finding]::new('SQ-ALLOW-EMPTY','HIGH',$r.Line,$r.File,'Разрешение без условий (http_access allow <пусто>)','Удалите правило или добавьте явные ACL; завершайте списком deny.',$r.Raw))
      }
      $termsLower = @(); foreach($t in $r.Terms){ $termsLower += $t.ToLower() }
      if($termsLower -contains 'all' -or $termsLower -contains 'any'){
        $find.Add([Finding]::new('SQ-ALLOW-ALL','HIGH',$r.Line,$r.File,'Широкое правило: http_access allow all/any','Сузьте до необходимых ACL и добавьте в конце "http_access deny all".',$r.Raw))
      }
    }
  }

  # 2) Нет финального deny all (http_access)
  if($Model.HttpAccess.Count -gt 0){
    $last = $Model.HttpAccess[$Model.HttpAccess.Count-1]
    $termsLower = @(); foreach($t in $last.Terms){ $termsLower += $t.ToLower() }
    $hasDenyAll = ($last.Action -eq 'deny') -and ($termsLower -contains 'all')
    if(-not $hasDenyAll){
      $find.Add([Finding]::new('SQ-NO-DENY-ALL','MED',$null,$last.File,"В конце списка правил нет явного 'http_access deny all'.","Добавьте финальное правило 'http_access deny all' после всех allow/deny.","Последняя строка: $($last.Raw) (line $($last.Line))"))
    }
  }

  # 3) CONNECT без SSL_ports
  foreach($r in $Model.HttpAccess){
    if($r.Action -ne 'allow'){ continue }
    if($r.Verbs -and ($r.Verbs -contains 'CONNECT')){
      $terms = @(); foreach($t in $r.Terms){ $terms += $t.ToLower().TrimStart('!') }
      if($terms -notcontains 'ssl_ports'){
        $find.Add([Finding]::new('SQ-CONNECT-NO-SSL_PORTS','HIGH',$r.Line,$r.File,"Разрешён CONNECT без ограничения ACL SSL_ports.","Добавьте 'SSL_ports' в правило CONNECT или запретите CONNECT.",$r.Raw))
      }
    }
  }

  # 4) Широкие Safe/SSL ports
  function Test-WideRangeLocal([string[]]$Parts){
    foreach($p in $Parts){
      if($p -match '^\d{1,5}-\d{1,5}$'){
        $lo,$hi = $p -split '-',2; $lo=[int]$lo; $hi=[int]$hi
        if($lo -le 1 -and $hi -ge 65535){ return $true }
        if(($hi-$lo) -ge 64000){ return $true }
      }
    }
    return $false
  }
  if($Model.SafePorts.Count -gt 0 -and (Test-WideRangeLocal $Model.SafePorts)){
    $line=$null;$file=$null
    if($Model.Acls.ContainsKey('safe_ports')){ $line=$Model.Acls['safe_ports'].Line; $file=$Model.Acls['safe_ports'].File }
    $find.Add([Finding]::new('SQ-SAFE-PORTS-WIDE','MED',$line,$file,'ACL safe_ports содержит слишком широкий диапазон.','Сузьте список до реально используемых портов.',($Model.SafePorts -join ' ')))
  }
  if($Model.SslPorts.Count -gt 0 -and (Test-WideRangeLocal $Model.SslPorts)){
    $line=$null;$file=$null
    if($Model.Acls.ContainsKey('ssl_ports')){ $line=$Model.Acls['ssl_ports'].Line; $file=$Model.Acls['ssl_ports'].File }
    $find.Add([Finding]::new('SQ-SSL-PORTS-WIDE','MED',$line,$file,'ACL ssl_ports содержит слишком широкий диапазон.','Оставьте только нужные TLS-порты (обычно 443/8443 и т.п.).',($Model.SslPorts -join ' ')))
  }

  # 5) Слишком широкие src ACL
  foreach($kv in $Model.Acls.GetEnumerator()){
    $acl = [Acl]$kv.Value
    if($acl.Type.ToLower() -eq 'src'){
      $broad = $false
      foreach($a in $acl.Args){ if(@('0.0.0.0/0','::/0') -contains $a){ $broad=$true; break } }
      if($broad){
        $find.Add([Finding]::new('SQ-ACL-BROAD-SRC','MED',$acl.Line,$acl.File,"ACL '$($acl.Name)' (src) охватывает все сети.",'Сузьте ACL до необходимых внутренних подсетей.',"acl $($acl.Name) src $($acl.Args -join ' ')"))
      }
    }
  }

  # 6) intercept/transparent порты
  foreach($p in $Model.HttpPorts){
    $hasIntercept = $false
    foreach($o in $p.Opts){ if(@('intercept','transparent','tproxy') -contains $o){ $hasIntercept=$true; break } }
    if($hasIntercept){
      $find.Add([Finding]::new('SQ-INTERCEPT','MED',[int]$p.Line,[string]$p.File,"http_port $($p.Port) использует intercept/transparent.",'Проверьте NAT/Firewall соответствие и ограничьте доступ; предпочитайте явный прокси.',"http_port $($p.Port) $($p.Opts -join ' ')"))
    }
  }

  # 7) Нет аутентификации
  foreach($r in $Model.HttpAccess){
    if($r.Action -ne 'allow'){ continue }
    $terms = @(); foreach($t in $r.Terms){ $terms += $t.ToLower().TrimStart('!') }
    if($terms.Count -gt 0 -and -not ($terms -contains 'proxy_auth' -or $terms -contains 'authenticated' -or $terms -contains 'auth' -or $terms -contains 'auth_required')){
      if(-not $Model.AuthRequiredUsed){
        $find.Add([Finding]::new('SQ-NO-AUTHZ','MED',$r.Line,$r.File,'Разрешающие правила без проверки аутентификации.','Добавьте proxy_auth REQUIRED (исключения — только для служебных ACL).',$r.Raw))
      }
      break
    }
  }

  # 8) ssl_bump all
  foreach($b in $Model.SslBump){
    if(($b.Raw -match '\ball\b') -and ($b.Raw -match '\b(bump|server-first)\b')){
      $find.Add([Finding]::new('SQ-SSL-BUMP-ALL','LOW',[int]$b.Line,[string]$b.File,"ssl_bump применяется к 'all'. Риски приватности/совместимости.",'Ограничьте ssl_bump доменами/категориями, используйте peek/splice.',$b.Raw))
    }
  }

  # 9) http_reply_access: нет deny all
  if($Model.HttpReplyAccess.Count -gt 0){
    $lastR = $Model.HttpReplyAccess[$Model.HttpReplyAccess.Count-1]
    $termsLower = @(); foreach($t in $lastR.Terms){ $termsLower += $t.ToLower() }
    $denyAll = ($lastR.Action -eq 'deny') -and ($termsLower -contains 'all')
    if(-not $denyAll){
      $find.Add([Finding]::new('SQ-NO-DENY-ALL-REPLY','LOW',$null,$lastR.File,"В конце 'http_reply_access' нет явного 'deny all'.","Добавьте финальное 'http_reply_access deny all'.","Последняя строка: $($lastR.Raw) (line $($lastR.Line))"))
    }
  }

  # 10) Расширенные проверки по всем строкам
  $extra = Run-ExtraChecks -Model $Model
  foreach($f in $extra){ $find.Add($f) }

  return ,$find
}

function Run-ExtraChecks {
  param([Model]$Model)
  $find = New-Object System.Collections.Generic.List[Finding]
  $records = $Model.Records
  if(-not $records -or $records.Count -eq 0){ return ,$find }

  # Агрегируем признаки TLS
  $hasTlsOutgoingOptions = $false
  $hasHttpsPort          = $false
  $hasSslProxyDirective  = $false   # любая sslproxy_*
  $hasSslBump            = $false
  $hasSslProxyCert       = $false
  $hasSslProxyKey        = $false
  $hasSslProxyCaFile     = $false

  foreach($rec in $records){
    $txt = [string]$rec.Text; $ln = [int]$rec.Line; $file = [string]$rec.File
    if(-not $txt){ continue }

    # ===== УЖЕ ИМЕЮЩИЕСЯ TLS-ПРОВЕРКИ =====
    if($txt -match '^\s*sslproxy_cert_error\s+allow\s+all'){
      $find.Add([Finding]::new('SQ-SSLPROXY-NOVERIFY','HIGH',$ln,$file,
        'Отключена проверка ошибок сертификатов: sslproxy_cert_error allow all.',
        'Удалите правило или оставьте точечные исключения по ACL.',
        $txt))
    }
    if($txt -match 'sslproxy_(flags|options).*DONT_VERIFY_PEER'){
      $find.Add([Finding]::new('SQ-SSLPROXY-DONT-VERIFY-PEER','HIGH',$ln,$file,
        'Отключена проверка TLS-пиров (DONT_VERIFY_PEER).',
        'Уберите DONT_VERIFY_PEER и включите стандартную проверку цепочки/hostname.',
        $txt))
    }
    if($txt -match '^\s*tls_outgoing_options\s+'){
      $hasTlsOutgoingOptions = $true
      $weak = $false
      if($txt -match 'min[-_ ]version\s*=\s*(ssl3|tls1(\.0)?|1\.0|1\.1)'){ $weak = $true }
      if($txt -match 'options\s*=\s*.*NO_TLSv1_2'){ $weak = $true }
      if($txt -match 'cipher\s*=\s*.*(RC4|NULL|MD5)'){ $weak = $true }
      if($weak){
        $find.Add([Finding]::new('SQ-TLS-OUT-WEAK','MED',$ln,$file,
          'Слабые параметры в tls_outgoing_options (версии/шифры).',
          'Задайте min-version=1.2/1.3, исключите слабые шифры, не отключайте TLSv1.2.',
          $txt))
      }
    }

    # ===== НОВОЕ: индикаторы TLS-конфигурации =====
    if($txt -match '^\s*https?_port\b'){ $hasHttpsPort = $true }          # httpS_port (и иногда https_port)
    if($txt -match '^\s*sslproxy_'){ $hasSslProxyDirective = $true }      # любые sslproxy_*
    if($txt -match '^\s*ssl_bump\b'){ $hasSslBump = $true }
    if($txt -match '^\s*sslproxy_cert\b'){ $hasSslProxyCert = $true }
    if($txt -match '^\s*sslproxy_key\b'){  $hasSslProxyKey  = $true }
    if($txt -match '^\s*sslproxy_cafile\b'){ $hasSslProxyCaFile = $true }

    # ===== ПРОЧИЕ УЖЕ ИМЕЮЩИЕСЯ ПРОВЕРКИ (без изменений) =====
    if($txt -match '^\s*http_access\s+allow\s+manager(\s|$)'){
      if($txt -notmatch '(localhost|to_localhost)'){
        $find.Add([Finding]::new('SQ-MANAGER-OPEN','HIGH',$ln,$file,
          'Доступ к manager разрешён не только с localhost.',
          'Ограничьте до localhost/to_localhost и затем запретите остальные.',
          $txt))
      }
    }
    if($txt -match '^\s*cachemgr_passwd\s+.+\s+all\s*$'){
      $find.Add([Finding]::new('SQ-CACHEMGR-ALL','MED',$ln,$file,
        'cachemgr_passwd выдан для "all".',
        'Ограничьте роли и источники, не используйте all.',
        $txt))
    }

    if($txt -match '^\s*snmp_port\s+'){
      $hasAccess = $false; $hasDenyAll = $false
      foreach($r2 in $records){
        $t2 = [string]$r2.Text
        if($t2 -match '^\s*snmp_access\s+') { $hasAccess = $true }
        if($t2 -match '^\s*snmp_access\s+deny\s+all\s*$'){ $hasDenyAll = $true }
      }
      if(-not $hasAccess -or -not $hasDenyAll){
        $find.Add([Finding]::new('SQ-SNMP-OPEN','MED',$ln,$file,
          'SNMP включён, но нет строгих snmp_access и финального deny all.',
          'Добавьте ACL источников и "snmp_access deny all" в конце.',
          $txt))
      }
    }

    if($txt -match '^\s*follow_x_forwarded_for\s+allow\s+all'){
      $find.Add([Finding]::new('SQ-FOLLOW-XFF-ALL','MED',$ln,$file,
        'Доверие к X-Forwarded-For для всех источников.',
        'Разрешайте XFF только от доверенных прокси по ACL.',
        $txt))
    }

    if($txt -match '^\s*(request_header_access|reply_header_access)\s+.+\s+allow\s+all\s*$'){
      $find.Add([Finding]::new('SQ-HEADER-ALLOW-ALL','LOW',$ln,$file,
        'Разрешение заголовков для всех (риск утечки).',
        'Пересмотрите: ограничьте конкретные заголовки и источники.',
        $txt))
    }

    if($txt -match '^\s*http_access\s+allow\s+.*\bdstdomain\s+(\.|\*)\s*$'){
      $find.Add([Finding]::new('SQ-DSTDOMAIN-ALL','HIGH',$ln,$file,
        'Разрешение на все домены через dstdomain . / *.',
        'Замените на перечень необходимых доменов/категорий.',
        $txt))
    }

    if($txt -match '^\s*never_direct\s+allow\s+all\s*$'){
      $find.Add([Finding]::new('SQ-NEVER-DIRECT-ALL','LOW',$ln,$file,
        'never_direct allow all — весь исходящий трафик через peer.',
        'Проверьте политику маршрутизации и сузьте ACL.',
        $txt))
    }

    if($txt -match '^\s*cache_peer\s+'){
      $hasCtl = $false
      foreach($r2 in $records){
        $t2=[string]$r2.Text
        if($t2 -match '^\s*(never_direct|always_direct|cache_peer_access)\s+'){ $hasCtl=$true; break }
      }
      if(-not $hasCtl){
        $find.Add([Finding]::new('SQ-CACHE-PEER-OPEN','MED',$ln,$file,
          'Есть cache_peer, но не видно ограничений (never/always_direct или cache_peer_access).',
          'Добавьте cache_peer_access и правила маршрутизации для контроля использования peer.',
          $txt))
      }
    }

    if($txt -match '^\s*(icap_enable|icap_service)\b'){
      foreach($r2 in $records){
        if([string]$r2.Text -match '^\s*adaptation_access\s+allow\s+all\s*$'){
          $find.Add([Finding]::new('SQ-ICAP-ALLOW-ALL','LOW',[int]$r2.Line,[string]$r2.File,
            'adaptation_access allow all с ICAP.',
            'Ограничьте по ACL, применяйте точечно.',
            [string]$r2.Text))
        }
      }
    }
  } # end foreach record

  # ===== НОВЫЕ ИТОГОВЫЕ TLS-ПРОВЕРКИ =====

  # 1) TLS нигде не задействован (ни ports, ни sslproxy, ни bump, ни tls_outgoing_options)
  if(-not $hasHttpsPort -and -not $hasSslProxyDirective -and -not $hasSslBump -and -not $hasTlsOutgoingOptions){
    # Привяжем к основному файлу, если известен
    $rootFile = $null
    if($records.Count -gt 0){ $rootFile = [string]$records[0].File }
    $find.Add([Finding]::new('SQ-TLS-NOT-CONFIGURED','LOW',$null,$rootFile,
      'В конфигурации не замечены TLS-настройки (работа без шифрования/валидации).',
      'Настройте TLS: https_port/ssl_bump при необходимости, tls_outgoing_options и sslproxy_cafile для проверки цепочки.',
      'No https_port/ssl_bump/sslproxy_*/tls_outgoing_options'))
  }

  # 2) Используется ssl_bump, но нет сертификата/ключа для MITM
  if($hasSslBump -and (-not $hasSslProxyCert -or -not $hasSslProxyKey)){
    $miss = @()
    if(-not $hasSslProxyCert){ $miss += 'sslproxy_cert' }
    if(-not $hasSslProxyKey){  $miss += 'sslproxy_key'  }
    $find.Add([Finding]::new('SQ-SSL-BUMP-NO-CERT','MED',$null,$null,
      'Включён ssl_bump, но отсутствуют обязательные параметры: ' + ($miss -join ', ') + '.',
      'Добавьте sslproxy_cert и sslproxy_key для корректного bump (перехвата TLS).',
      'ssl_bump present; missing: ' + ($miss -join ', ')))
  }

  # 3) Есть ssl_bump/sslproxy_*, но нет доверенного CA для проверки внешних серверов
  if(($hasSslBump -or $hasSslProxyDirective) -and (-not $hasSslProxyCaFile)){
    $find.Add([Finding]::new('SQ-SSLPROXY-NO-CAFILE','MED',$null,$null,
      'Отсутствует sslproxy_cafile — проверки цепочки серверных сертификатов могут работать некорректно.',
      'Укажите sslproxy_cafile с корневыми/промежуточными сертификатами, соответствующими вашей политике.',
      'sslproxy_* or ssl_bump present; missing sslproxy_cafile'))
  }

  return ,$find
}


#----------------------------- Вывод -----------------------------
function Write-Table {
  param([System.Collections.Generic.List[Finding]]$Findings)
  if(-not $Findings -or $Findings.Count -eq 0){ Write-Host "✔ Проблем не обнаружено."; return }
  "{0,-4}  {1,-22}  {2,-6}  {3}" -f 'SEV','ID','LINE','MESSAGE'
  ('-'*100)
  foreach($x in $Findings){
    $loc = $x.File; if($null -ne $x.Line){ $loc = "$($x.File):$($x.Line)" }
    "{0,-4}  {1,-22}  {2,-6}  {3}" -f $x.Severity, $x.Id, ($(if($null -ne $x.Line){$x.Line}else{'-'})), $x.Message
    "  ↳ at: {0}" -f $loc
    "  ↳ evidence: {0}" -f $x.Evidence
    "  ↳ fix: {0}" -f $x.Recommendation
  }
}
function Out-Json {
  param([System.Collections.Generic.List[Finding]]$Findings)
  $rows = @()
  foreach($f in $Findings){
    $rows += [pscustomobject]@{
      id = $f.Id; severity = $f.Severity; line = $f.Line; file = $f.File
      message = $f.Message; recommendation = $f.Recommendation; evidence = $f.Evidence
    }
  }
  $rows | ConvertTo-Json -Depth 4
}

#----------------------------- CLI -----------------------------
function Invoke-SquidAudit {
  param([string]$ConfPath,[string]$OutFormat='Table')
  $model = Parse-SquidConfig -RootFile $ConfPath
  $findings = Run-SquidChecks -Model $model

  if($OutFormat -eq 'Json'){ Out-Json -Findings $findings | Write-Output }
  else { Write-Table -Findings $findings }

  if($findings | Where-Object { $_.Severity -eq 'HIGH' }){ exit 2 }
  elseif($findings.Count -gt 0){ exit 1 }
  else{ exit 0 }
}

try { Invoke-SquidAudit -ConfPath $Path -OutFormat $Format }
catch {
  Write-Error $_.Exception.Message
  if($_.InvocationInfo){ Write-Error ("At: " + $_.InvocationInfo.PositionMessage) }
  exit 4
}
