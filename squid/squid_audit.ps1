<#
.SYNOPSIS
  Аудит squid.conf на небезопасные правила (PowerShell 5+/7).

.EXAMPLE
  pwsh ./squid_audit.ps1 -Path ./squid.conf -Format Table
  pwsh ./squid_audit.ps1 -Path ./squid.conf -Format Json > report.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$Path,
  [ValidateSet('Table','Json')]
  [string]$Format = 'Table'
)

#region Classes
class Acl {
  [string]$Name
  [string]$Type
  [string[]]$Args
  [int]$Line
  Acl([string]$n,[string]$t,[string[]]$a,[int]$l){ $this.Name=$n;$this.Type=$t;$this.Args=$a;$this.Line=$l }
}
class HttpRule {
  [string]$Action   # allow|deny
  [string[]]$Verbs  # CONNECT/GET/...
  [string[]]$Terms  # acl refs (может быть с !)
  [string]$Raw
  [int]$Line
  HttpRule([string]$a,[string[]]$v,[string[]]$t,[string]$r,[int]$l){$this.Action=$a;$this.Verbs=$v;$this.Terms=$t;$this.Raw=$r;$this.Line=$l}
}
class Model {
  [hashtable]$Acls = @{}
  [System.Collections.Generic.List[HttpRule]]$HttpAccess = [System.Collections.Generic.List[HttpRule]]::new()
  [System.Collections.Generic.List[string]]$SafePorts = [System.Collections.Generic.List[string]]::new()
  [System.Collections.Generic.List[string]]$SslPorts  = [System.Collections.Generic.List[string]]::new()
  [System.Collections.Generic.List[object]]$HttpPorts = [System.Collections.Generic.List[object]]::new() # @{Port=;Opts=;Line=}
  [System.Collections.Generic.List[object]]$SslBump   = [System.Collections.Generic.List[object]]::new() # @{Raw=;Line=}
  [bool]$AuthRequiredUsed = $false
}
class Finding {
  [string]$Id
  [string]$Severity  # HIGH|MED|LOW
  [Nullable[int]]$Line
  [string]$Message
  [string]$Recommendation
  [string]$Evidence
  Finding([string]$id,[string]$sev,[Nullable[int]]$ln,[string]$msg,[string]$rec,[string]$ev){
    $this.Id=$id;$this.Severity=$sev;$this.Line=$ln;$this.Message=$msg;$this.Recommendation=$rec;$this.Evidence=$ev
  }
}
#endregion

#region Utils
function Load-Lines {
  param([string]$FilePath)
  if(!(Test-Path -LiteralPath $FilePath)){ throw "Файл не найден: $FilePath" }
  $raw = Get-Content -LiteralPath $FilePath -Encoding UTF8 -ErrorAction Stop
  $out = New-Object System.Collections.Generic.List[object]
  $buf = ''
  $startLine = 0
  for($i=0;$i -lt $raw.Count;$i++){
    $ln = $i+1
    $line = $raw[$i] -replace '\s*#.*$',''
    $line = $line.TrimEnd()
    if([string]::IsNullOrWhiteSpace($line) -and -not $buf){ continue }
    if($line.EndsWith("\")){
      if(-not $buf){ $startLine = $ln }
      $buf += ($line.Substring(0,$line.Length-1) + ' ')
    } else {
      if($buf){
        $buf += $line
        $out.Add(@{ Line=$startLine; Text=$buf.Trim() })
        $buf=''; $startLine=0
      } else {
        $out.Add(@{ Line=$ln; Text=$line.Trim() })
      }
    }
  }
  if($buf){ $out.Add(@{ Line=$startLine; Text=$buf.Trim() }) }
  return $out
}

function Split-Tokens {
  param([string]$Text)
  # простой split по whitespace
  return ($Text -split '\s+')
}

function Test-BroadCidr {
  param([string]$Arg)
  return @('0.0.0.0/0','::/0') -contains $Arg
}

function Test-WideRange {
  param([string[]]$Parts)
  foreach($p in $Parts){
    if($p -match '^\d{1,5}-\d{1,5}$'){
      $lo,$hi = $p -split '-',2
      $lo=[int]$lo; $hi=[int]$hi
      if($lo -le 1 -and $hi -ge 65535){ return $true }
      if(($hi-$lo) -ge 64000){ return $true }
    } elseif($p -match '^\d{1,5}$'){
      continue
    }
  }
  return $false
}
#endregion

#region Parse
function Parse-SquidConfig {
  param($Lines)
  $m = [Model]::new()
  foreach($rec in $Lines){
    $ln = [int]$rec.Line
    $line = [string]$rec.Text
    if(-not $line){ continue }
    $toks = Split-Tokens $line
    if(-not $toks){ continue }
    $head = $toks[0].ToLower()
    switch($head){
      'acl' {
        if($toks.Count -ge 3){
          $name = $toks[1]; $type = $toks[2]; $args = @()
          if($toks.Count -gt 3){ $args = $toks[3..($toks.Count-1)] }
          $acl = [Acl]::new($name,$type,$args,$ln)
          $m.Acls[$name] = $acl
          if($name.ToLower() -eq 'safe_ports'){ $m.SafePorts.AddRange($args) }
          if($name.ToLower() -eq 'ssl_ports'){  $m.SslPorts.AddRange($args)  }
        }
      }
      'http_access' {
        if($toks.Count -ge 2){
          $action = $toks[1].ToLower()
          $rest = @()
          if($toks.Count -gt 2){ $rest = $toks[2..($toks.Count-1)] }
          $verbs = @()
          if($rest.Count -gt 0 -and $rest[0] -match '^[A-Za-z]+$' -and @('CONNECT','GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','TRACE') -contains $rest[0].ToUpper()){
            $verbs = @($rest[0].ToUpper()); $rest = $rest[1..($rest.Count-1)]
          }
          $rule = [HttpRule]::new($action,$verbs,$rest,$line,$ln)
          $m.HttpAccess.Add($rule)
          if($rest | ForEach-Object { $_.ToLower().TrimStart('!') } | Where-Object { $_ -eq 'proxy_auth' }){
            $m.AuthRequiredUsed = $true
          }
        }
      }
      'http_port' {
        if($toks.Count -ge 2){
          $port = $toks[1]
          $opts = @()
          if($toks.Count -gt 2){ $opts = $toks[2..($toks.Count-1)] | ForEach-Object { $_.ToLower() } }
          $m.HttpPorts.Add(@{ Port=$port; Opts=$opts; Line=$ln })
        }
      }
      'ssl_bump' {
        $m.SslBump.Add(@{ Raw=$line; Line=$ln })
      }
      default { }
    }
  }
  return $m
}
#endregion

#region Checks
function Run-SquidChecks {
  param([Model]$Model)
  $find = New-Object System.Collections.Generic.List[Finding]

  # 1) allow all/any и пустое allow
  foreach($r in $Model.HttpAccess){
    if($r.Action -eq 'allow'){
      if(-not $r.Terms -or $r.Terms.Count -eq 0){
        $find.Add([Finding]::new('SQ-ALLOW-EMPTY','HIGH',$r.Line,'Разрешение без условий (http_access allow <пусто>)',
          'Удалите правило или добавьте явные ACL; завершайте списком deny.',$r.Raw))
      }
      $termsLower = $r.Terms | ForEach-Object { $_.ToLower() }
      if($termsLower -contains 'all' -or $termsLower -contains 'any'){
        $find.Add([Finding]::new('SQ-ALLOW-ALL','HIGH',$r.Line,'Широкое правило: http_access allow all/any',
          'Сузьте до необходимых ACL и добавьте в конце "http_access deny all".',$r.Raw))
      }
    }
  }

  # 2) Нет финального deny all
  if($Model.HttpAccess.Count -gt 0){
    $last = $Model.HttpAccess[$Model.HttpAccess.Count-1]
    $hasDenyAll = ($last.Action -eq 'deny') -and (($last.Terms | ForEach-Object { $_.ToLower() }) -contains 'all')
    if(-not $hasDenyAll){
      $find.Add([Finding]::new('SQ-NO-DENY-ALL','MED',$null,
        "В конце списка правил нет явного 'http_access deny all'.",
        "Добавьте финальное правило 'http_access deny all' после всех allow/deny.",
        "Последняя строка: $($last.Raw) (line $($last.Line))"))
    }
  }

  # 3) CONNECT без SSL_ports
  foreach($r in $Model.HttpAccess){
    if($r.Action -ne 'allow'){ continue }
    if($r.Verbs -and ($r.Verbs -contains 'CONNECT')){
      $terms = $r.Terms | ForEach-Object { $_.ToLower().TrimStart('!') }
      if($terms -notcontains 'ssl_ports'){
        $find.Add([Finding]::new('SQ-CONNECT-NO-SSL_PORTS','HIGH',$r.Line,
          "Разрешён CONNECT без ограничения ACL SSL_ports.",
          "Добавьте 'SSL_ports' в правило CONNECT или запретите CONNECT.",
          $r.Raw))
      }
    }
  }

  # 4) Широкие Safe_ports / SSL_ports
  if((Test-WideRange -Parts $Model.SafePorts)){
    $line = ($Model.Acls['safe_ports']).Line
    $find.Add([Finding]::new('SQ-SAFE-PORTS-WIDE','MED',$line,
      'ACL safe_ports содержит слишком широкий диапазон.',
      'Сузьте список до реально используемых портов.',
      ($Model.SafePorts -join ' ')))
  }
  if((Test-WideRange -Parts $Model.SslPorts)){
    $line = ($Model.Acls['ssl_ports']).Line
    $find.Add([Finding]::new('SQ-SSL-PORTS-WIDE','MED',$line,
      'ACL ssl_ports содержит слишком широкий диапазон.',
      'Оставьте только нужные TLS-порты (обычно 443/8443 и т.п.).',
      ($Model.SslPorts -join ' ')))
  }

  # 5) Слишком широкие src ACL
  foreach($kv in $Model.Acls.GetEnumerator()){
    $acl = [Acl]$kv.Value
    if($acl.Type.ToLower() -eq 'src' -and ($acl.Args | Where-Object { Test-BroadCidr $_ })){
      $find.Add([Finding]::new('SQ-ACL-BROAD-SRC','MED',$acl.Line,
        "ACL '$($acl.Name)' (src) охватывает все сети.",
        'Сузьте ACL до необходимых внутренних подсетей.',
        "acl $($acl.Name) src $($acl.Args -join ' ')"))
    }
  }

  # 6) intercept/transparent порты
  foreach($p in $Model.HttpPorts){
    if(($p.Opts | Where-Object { @('intercept','transparent','tproxy') -contains $_ }).Count -gt 0){
      $find.Add([Finding]::new('SQ-INTERCEPT','MED',[int]$p.Line,
        "http_port $($p.Port) использует intercept/transparent.",
        'Проверьте NAT/Firewall соответствие и ограничьте доступ; предпочитайте явный прокси.',
        "http_port $($p.Port) $($p.Opts -join ' ')"))
    }
  }

  # 7) Отсутствие аутентификации в allow-правилах
  foreach($r in $Model.HttpAccess){
    if($r.Action -ne 'allow'){ continue }
    $terms = $r.Terms | ForEach-Object { $_.ToLower().TrimStart('!') }
    if($terms.Count -gt 0 -and -not ($terms -contains 'proxy_auth' -or $terms -contains 'authenticated' -or $terms -contains 'auth' -or $terms -contains 'auth_required')){
      if(-not $Model.AuthRequiredUsed){
        $find.Add([Finding]::new('SQ-NO-AUTHZ','MED',$r.Line,
          'Разрешающие правила без проверки аутентификации.',
          'Добавьте проверку proxy_auth REQUIRED (исключения — только для служебных ACL).',
          $r.Raw))
      }
      break
    }
  }

  # 8) Агрессивный ssl_bump на all
  foreach($b in $Model.SslBump){
    if($b.Raw -match '\ball\b' -and $b.Raw -match '\b(bump|server-first)\b'){
      $find.Add([Finding]::new('SQ-SSL-BUMP-ALL','LOW',[int]$b.Line,
        "ssl_bump применяется к 'all'. Риски приватности/совместимости.",
        'Ограничьте ssl_bump доменами/категориями, используйте peek/splice по политикам.',
        $b.Raw))
    }
  }

  return ,$find
}
#endregion

#region Output
function Write-Table {
  param([System.Collections.Generic.List[Finding]]$Findings)
  if(-not $Findings -or $Findings.Count -eq 0){
    Write-Host "✔ Проблем не обнаружено."
    return
  }
  "{0,-4}  {1,-18}  {2,-6}  {3}" -f 'SEV','ID','LINE','MESSAGE'
  ('-'*88)
  foreach($x in $Findings){
    "{0,-4}  {1,-18}  {2,-6}  {3}" -f $x.Severity, $x.Id, ($(if($null -ne $x.Line){$x.Line}else{'-'})), $x.Message
    "  ↳ evidence: {0}" -f $x.Evidence
    "  ↳ fix: {0}" -f $x.Recommendation
  }
}
function Out-Json {
  param([System.Collections.Generic.List[Finding]]$Findings)
  $Findings | ForEach-Object {
    [pscustomobject]@{
      id = $_.Id; severity = $_.Severity; line = $_.Line
      message = $_.Message; recommendation = $_.Recommendation; evidence = $_.Evidence
    }
  } | ConvertTo-Json -Depth 4
}
#endregion

#region CLI
function Invoke-SquidAudit {
  param([string]$ConfPath,[string]$OutFormat='Table')
  $lines = Load-Lines -FilePath $ConfPath
  $model = Parse-SquidConfig -Lines $lines
  $findings = Run-SquidChecks -Model $model

  if($OutFormat -eq 'Json'){ Out-Json -Findings $findings | Write-Output }
  else { Write-Table -Findings $findings }

  if($findings | Where-Object { $_.Severity -eq 'HIGH' }){ exit 2 }
  elseif($findings.Count -gt 0){ exit 1 }
  else{ exit 0 }
}

try {
  Invoke-SquidAudit -ConfPath $Path -OutFormat $Format
} catch {
  Write-Error $_.Exception.Message
  exit 4
}
#endregion

