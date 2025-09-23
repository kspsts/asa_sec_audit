# ASA Secure Config Audit (PS 5.1 compatible, ASCII-safe)
# Version: 0.5.1

[CmdletBinding()]
param(
  [string]$Path = "asa_config.txt",
  [switch]$All,
  [string[]]$Checks,
  [string]$OutJson = "asa_audit_report.json",
  [switch]$Chart
)

# ===================== Utils =====================

function Read-AsaConfig {
  param([string]$Path)
  $raw   = Get-Content -Raw -Encoding UTF8 -ErrorAction Stop $Path
  $lines = $raw -split "`r?`n"
  $idx   = [ordered]@{}
  foreach($pfx in @(
    'access-list','access-group','object ','object-group','telnet','ssh ',
    'http ','http server','enable password','username','passwd','aaa ',
    'snmp-server','logging ','threat-detection','icmp ',
    'crypto ikev1 policy','crypto ikev2 policy','crypto key','isakmp ',
    'crypto ipsec ikev1 transform-set','crypto map',
    'webvpn','policy-map','class-map','inspect ',
    'service password-encryption','ssh version',
    'rest-api','ipsec security-association ','split-tunnel-network-list',
    'vpn-tunnel-protocol','anyconnect ssl cipher','ssl cipher version',
    'ssl dh-group','dynamic-filter','botnet-traffic-filter',
    'ssl dtls-version','anyconnect dtls version','ssl cipher dtls','ssl key-exchange'
  )){
    $idx[$pfx] = $lines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($pfx)) }
  }
  [PSCustomObject]@{ Raw=$raw; Lines=$lines; Index=$idx }
}

function New-Finding {
  param(
    [string]$Id,[string]$Title,
    [ValidateSet('High','Medium','Low','Info')][string]$Severity,
    [bool]$Passed,[string[]]$Evidence=@(),[string]$Recommendation=''
  )
  [PSCustomObject]@{ Id=$Id;Title=$Title;Severity=$Severity;Passed=$Passed;Evidence=$Evidence;Recommendation=$Recommendation }
}

function Get-IndexLines {
  param($Cfg, $Key)
  if($Cfg -and $Cfg.Index -and $Cfg.Index.Contains($Key)) { @($Cfg.Index[$Key]) } else { @() }
}

function Write-AsaReport {
  param([PSCustomObject[]]$Findings,[string]$OutJson,[switch]$Chart)
  $sorted = $Findings | Sort-Object @{Expression='Passed';Descending=$true}, @{Expression='Severity';Descending=$true}, 'Id'
  foreach($f in $sorted){
    $state = if($f.Passed){ '[OK]' } else { '[ISSUE]' }
    $color = if($f.Passed){ 'Green' } elseif($f.Severity -eq 'High'){'Red'} elseif($f.Severity -eq 'Medium'){'Yellow'} else {'Cyan'}
    Write-Host "$state $($f.Severity) $($f.Id): $($f.Title)" -ForegroundColor $color
    if($f.Evidence){ $f.Evidence | Select-Object -First 8 | ForEach-Object { Write-Host "  > $_" -ForegroundColor DarkGray } }
    if(-not $f.Passed -and $f.Recommendation){ Write-Host "  Recommendation: $($f.Recommendation)" -ForegroundColor Magenta }
    Write-Host
  }
  $sorted | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $OutJson
  Write-Host "JSON report saved: $OutJson" -ForegroundColor Cyan

  if($Chart){
    $bySev = $Findings | Group-Object Severity | Sort-Object Name
    Write-Host "Severity histogram:" -ForegroundColor Cyan
    foreach($g in $bySev){ $bar = ('#' * $g.Count); Write-Host ("{0,-6} {1,3} | {2}" -f $g.Name,$g.Count,$bar) }
  }
}

# ============ Parsing: objects / groups ============

function Build-AsaObjects {
  param($Cfg)
  $lines = $Cfg.Lines
  $objectHosts   = @{}
  $objectSubnets = @{}
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*object\s+network\s+(\S+)'){
      $name = $matches[1]
      if(-not $objectHosts[$name]){ $objectHosts[$name] = [System.Collections.Generic.HashSet[string]]::new() }
      if(-not $objectSubnets[$name]){ $objectSubnets[$name] = [System.Collections.Generic.HashSet[string]]::new() }
      for($j=$i+1; $j -lt $lines.Count -and $lines[$j] -notmatch '^\s*object\s+(network|service)\b'; $j++){
        if($lines[$j] -match '\bhost\s+(\d{1,3}(?:\.\d{1,3}){3})\b'){ [void]$objectHosts[$name].Add($matches[1]) }
        elseif($lines[$j] -match '\bsubnet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\b'){
          [void]$objectSubnets[$name].Add("$($matches[1]) $($matches[2])")
        }
      }
    }
  }
  $groupHosts   = @{}
  $groupSubnets = @{}
  $groupRefs    = @{}
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*object-group\s+network\s+(\S+)'){
      $g = $matches[1]
      $groupHosts[$g]   = [System.Collections.Generic.HashSet[string]]::new()
      $groupSubnets[$g] = [System.Collections.Generic.HashSet[string]]::new()
      $groupRefs[$g]    = [System.Collections.Generic.HashSet[string]]::new()
      for($j=$i+1; $j -lt $lines.Count -and $lines[$j] -notmatch '^\s*object-group\s+(network|service)\b'; $j++){
        if($lines[$j] -match '^\s*network-object\s+host\s+(\d{1,3}(?:\.\d{1,3}){3})'){ [void]$groupHosts[$g].Add($matches[1]) }
        elseif($lines[$j] -match '^\s*network-object\s+object\s+(\S+)'){ [void]$groupRefs[$g].Add($matches[1]) }
        elseif($lines[$j] -match '^\s*network-object\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})'){ [void]$groupSubnets[$g].Add("$($matches[1]) $($matches[2])") }
      }
    }
  }
  foreach($g in $groupRefs.Keys){
    foreach($obj in $groupRefs[$g]){
      if($objectHosts.ContainsKey($obj)){ foreach($ip in $objectHosts[$obj]){ [void]$groupHosts[$g].Add($ip) } }
      if($objectSubnets.ContainsKey($obj)){ foreach($sn in $objectSubnets[$obj]){ [void]$groupSubnets[$g].Add($sn) } }
    }
  }
  [PSCustomObject]@{ ObjectHosts=$objectHosts; ObjectSubnets=$objectSubnets; GroupHosts=$groupHosts; GroupSubnets=$groupSubnets }
}

function Get-AllServerIPs {
  [OutputType([string[]])]
  param($Obj)
  $result = New-Object System.Collections.Generic.List[string]
  if($Obj -and $Obj.ObjectHosts){
    foreach($k in $Obj.ObjectHosts.Keys){ foreach($ip in $Obj.ObjectHosts[$k]){ if(-not $result.Contains($ip)){ [void]$result.Add($ip) } } }
  }
  if($Obj -and $Obj.GroupHosts){
    foreach($k in $Obj.GroupHosts.Keys){ foreach($ip in $Obj.GroupHosts[$k]){ if(-not $result.Contains($ip)){ [void]$result.Add($ip) } } }
  }
  return @($result) | Sort-Object -Unique
}

function Get-OutsideAcls { param($Cfg)
  if($Cfg.Index.Contains('access-group')){
    $Cfg.Index['access-group'] | Where-Object { $_ -match '^\s*access-group\s+\S+\s+in\s+interface\s+outside\b' }
  } else { @() }
}

# ================= ACL mini-parser =================

function Parse-AclLine {
  param([string]$Line)
  if($Line -notmatch '^\s*access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$'){ return $null }
  $name=$matches[1]; $action=$matches[2]; $proto=$matches[3]; $rest=$matches[4].Trim()
  $t = if([string]::IsNullOrWhiteSpace($rest)) { @() } else { $rest -split '\s+' }
  $idx=0
  $srcType='';$srcVal=''
  if($idx -lt $t.Count){
    switch ($t[$idx]) {
      'any' { $srcType='any'; $srcVal='any'; $idx++ }
      'host' { if($idx+1 -lt $t.Count){ $srcType='host'; $srcVal=$t[$idx+1]; $idx+=2 } else { $srcType='unknown'; $idx=$t.Count } }
      'object' { if($idx+1 -lt $t.Count){ $srcType='object'; $srcVal=$t[$idx+1]; $idx+=2 } else { $srcType='unknown'; $idx=$t.Count } }
      'object-group' { if($idx+1 -lt $t.Count){ $srcType='og'; $srcVal=$t[$idx+1]; $idx+=2 } else { $srcType='unknown'; $idx=$t.Count } }
      default {
        if($idx+1 -lt $t.Count -and $t[$idx] -match '^\d' -and $t[$idx+1] -match '^\d'){ $srcType='subnet'; $srcVal="$($t[$idx]) $($t[$idx+1])"; $idx+=2 }
        else { $srcType='unknown'; $srcVal=$t[$idx]; $idx++ }
      }
    }
  }
  $dstType='';$dstVal=''
  if($idx -lt $t.Count){
    switch ($t[$idx]) {
      'any' { $dstType='any'; $dstVal='any'; $idx++ }
      'host' { if($idx+1 -lt $t.Count){ $dstType='host'; $dstVal=$t[$idx+1]; $idx+=2 } else { $dstType='unknown'; $idx=$t.Count } }
      'object' { if($idx+1 -lt $t.Count){ $dstType='object'; $dstVal=$t[$idx+1]; $idx+=2 } else { $dstType='unknown'; $idx=$t.Count } }
      'object-group' { if($idx+1 -lt $t.Count){ $dstType='og'; $dstVal=$t[$idx+1]; $idx+=2 } else { $dstType='unknown'; $idx=$t.Count } }
      default {
        if($idx+1 -lt $t.Count -and $t[$idx] -match '^\d' -and $t[$idx+1] -match '^\d'){ $dstType='subnet'; $dstVal="$($t[$idx]) $($t[$idx+1])"; $idx+=2 }
        else { $dstType='unknown'; $dstVal=$t[$idx]; $idx++ }
      }
    }
  }
  $svc = if($idx -lt $t.Count){ ($t[$idx..($t.Count-1)] -join ' ') } else { '' }
  [PSCustomObject]@{
    Name=$name; Action=$action; Proto=$proto;
    SrcType=$srcType; Src=$srcVal; DstType=$dstType; Dst=$dstVal; Service=$svc; Raw=$Line
  }
}

function Is-SupersetRule {
  param($R1,$R2)
  if($R1.Action -eq 'deny' -and $R1.Proto -eq 'ip' -and $R1.SrcType -eq 'any' -and $R1.DstType -eq 'any'){ return $true }
  if($R1.Action -ne $R2.Action){
    if($R1.Action -eq 'permit' -and $R1.Proto -eq 'ip' -and $R1.SrcType -eq 'any' -and $R1.DstType -eq 'any'){ return $true }
    return $false
  }
  $protoSuperset = ($R1.Proto -eq 'ip') -or ($R1.Proto -eq $R2.Proto)
  if(-not $protoSuperset){ return $false }
  function scopeRank($type){ switch($type){ 'any'{3}; 'subnet'{2}; 'og'{2}; 'object'{2}; 'host'{1}; default{0} } }
  $srcWide = (scopeRank $R1.SrcType) -ge (scopeRank $R2.SrcType)
  $dstWide = (scopeRank $R1.DstType) -ge (scopeRank $R2.DstType)
  $svcWide = [string]::IsNullOrWhiteSpace($R1.Service) -or $R1.Service -match '\bany\b'
  return ($srcWide -and $dstWide -and $svcWide)
}

# ===================== Checks =====================

function Check-ACLAnyAny {
  param($Cfg)

  $acls   = @(); if($Cfg.Index.Contains('access-list')){ $acls = $Cfg.Index['access-list'] }
  $groups = @(); if($Cfg.Index.Contains('access-group')){ $groups = $Cfg.Index['access-group'] }

  # Map: ACL Name -> list of {Direction, Interface|global}
  $bindMap = @{}
  foreach($g in $groups){
    $m = [regex]::Match($g,'^\s*access-group\s+(?<name>\S+)\s+(?<dir>in|out)\s+(?:interface\s+(?<if>\S+)|global)\s*$', 'IgnoreCase')
    if($m.Success){
      $n = $m.Groups['name'].Value
      if(-not $bindMap.ContainsKey($n)){ $bindMap[$n] = New-Object System.Collections.Generic.List[object] }
      $ifc = if($m.Groups['if'].Success){ $m.Groups['if'].Value } else { 'global' }
      [void]$bindMap[$n].Add([PSCustomObject]@{ Direction=$m.Groups['dir'].Value; Interface=$ifc })
    }
  }

  $hits = @($acls | Where-Object { $_ -match '\bpermit\s+ip\s+any\s+any\b' })
  if(-not $hits -or $hits.Count -eq 0){
    return New-Finding 'ACL-ANY-ANY' 'Permit ip any any not found' 'Info' $true
  }

  $ev = New-Object System.Collections.Generic.List[string]
  $outsideIn = $false
  foreach($ln in $hits){
    $m = [regex]::Match($ln,'^\s*access-list\s+(?<name>\S+)\s+', 'IgnoreCase')
    $annot = $ln
    if($m.Success){
      $name = $m.Groups['name'].Value
      if($bindMap.ContainsKey($name)){
        $bindsTxt = ($bindMap[$name] | ForEach-Object { "[{0} {1}]" -f $_.Interface,$_.Direction }) -join ' '
        $annot = "$ln  $bindsTxt"
        if(($bindMap[$name] | Where-Object { $_.Interface -match '^outside$' -and $_.Direction -eq 'in' }).Count -gt 0){
          $outsideIn = $true
        }
      } else {
        $annot = "$ln  [UNBOUND]"
      }
    }
    [void]$ev.Add($annot)
  }

  $sev = if($outsideIn){ 'High' } else { 'Medium' }
  New-Finding 'ACL-ANY-ANY' 'Permit ip any any present' $sev $false ($ev | Select-Object -Unique) 'Remove any-any; restrict to needed ports/networks.'
}

function Check-DangerousServicesAnyAny {
  param($Cfg)
  $acls = @(); if($Cfg.Index.Contains('access-list')){ $acls = $Cfg.Index['access-list'] }
  if($acls.Count -eq 0){ return New-Finding 'ACL-DANG-SVC' 'Dangerous services exposure' 'Info' $true }

  $ports = @(22,3389,5900,8080,8443,9090)
  $hits = @()
  foreach($ln in $acls){
    $anySrc = ($ln -match '\sany\s') -or ($ln -match '\b0\.0\.0\.0\s+0\.0\.0\.0\b') -or ($ln -match '\bany6\b')
    if($ln -match '^\s*access-list\s+\S+\s+extended\s+permit\s+tcp\b' -and $anySrc){
      if($ln -match '\beq\s+(\d+)\b'){
        $p = [int]$matches[1]; if($ports -contains $p){ $hits += $ln; continue }
      }
      if($ln -match '\brange\s+9000\s+9010\b'){ $hits += $ln; continue }
    }
  }
  if($hits.Count -gt 0){
    New-Finding 'ACL-DANG-SVC' 'Dangerous TCP services exposed from any' 'High' $false $hits 'Close 22/3389/5900/8080/8443/9090 and 9000-9010 from any; allow only from trusted sources or via VPN.'
  } else {
    New-Finding 'ACL-DANG-SVC' 'No dangerous exposures detected' 'Info' $true
  }
}

function Check-ACLForServers {
  param($Cfg,$Obj)

  # --- собрать множество имён "серверных" объектов/групп ---
  $serverNames = [System.Collections.Generic.HashSet[string]]::new()
  if($Obj -and $Obj.ObjectHosts){ foreach($k in $Obj.ObjectHosts.Keys){ [void]$serverNames.Add($k) } }
  if($Obj -and $Obj.ObjectSubnets){ foreach($k in $Obj.ObjectSubnets.Keys){ [void]$serverNames.Add($k) } }
  if($Obj -and $Obj.GroupHosts){ foreach($k in $Obj.GroupHosts.Keys){ if($Obj.GroupHosts[$k].Count -gt 0){ [void]$serverNames.Add($k) } } }
  if($Obj -and $Obj.GroupSubnets){ foreach($k in $Obj.GroupSubnets.Keys){ if($Obj.GroupSubnets[$k].Count -gt 0){ [void]$serverNames.Add($k) } } }

  if($serverNames.Count -eq 0){
    return New-Finding 'SRV-ACL' 'Servers ACL check (objects/groups)' 'Info' $true
  }

  # --- строки ACL + карта привязок (name -> [ {Interface,Direction}... ]) ---
  $aclLines = @(); if($Cfg.Index.Contains('access-list')){ $aclLines = $Cfg.Index['access-list'] }

  $bindMap = @{}
  if($Cfg.Index.Contains('access-group')){
    foreach($g in $Cfg.Index['access-group']){
      $m = [regex]::Match($g,'^\s*access-group\s+(?<name>\S+)\s+(?<dir>in|out)\s+(?:interface\s+(?<if>\S+)|global)\s*$', 'IgnoreCase')
      if($m.Success){
        $n = $m.Groups['name'].Value
        if(-not $bindMap.ContainsKey($n)){ $bindMap[$n] = New-Object System.Collections.Generic.List[object] }
        $ifc = if($m.Groups['if'].Success){ $m.Groups['if'].Value } else { 'global' }
        [void]$bindMap[$n].Add([PSCustomObject]@{ Interface=$ifc; Direction=$m.Groups['dir'].Value })
      }
    }
  }

  # --- накопители находок по направлениям ---
  $evAnyToSrv = New-Object System.Collections.Generic.List[string]  # any -> server (экспозиция)
  $evSrvToAny = New-Object System.Collections.Generic.List[string]  # server -> any (подозрительно для jump-хостов и т.п.)

  foreach($ln in $aclLines){
    $p = Parse-AclLine -Line $ln
    if(-not $p -or $p.Action -ne 'permit'){ continue }

    # аннотация привязки
    $bindTxt = '  [UNBOUND]'
    if($bindMap.ContainsKey($p.Name)){
      $bindTxt = '  ' + (($bindMap[$p.Name] | ForEach-Object { "[{0} {1}]" -f $_.Interface,$_.Direction }) -join ' ')
    }

    # any -> server ?
    $isServerDst = (($p.DstType -in @('object','og')) -and $serverNames.Contains($p.Dst))
    $anySrc = ($p.SrcType -eq 'any' -or ($p.SrcType -eq 'subnet' -and $p.Src -match '^0\.0\.0\.0\s+0\.0\.0\.0$'))
    if($isServerDst -and $anySrc){
      [void]$evAnyToSrv.Add($ln + $bindTxt)
      continue
    }

    # server -> any ?
    $isServerSrc = (($p.SrcType -in @('object','og')) -and $serverNames.Contains($p.Src))
    $anyDst = ($p.DstType -eq 'any' -or ($p.DstType -eq 'subnet' -and $p.Dst -match '^0\.0\.0\.0\s+0\.0\.0\.0$'))
    if($isServerSrc -and $anyDst){
      [void]$evSrvToAny.Add($ln + $bindTxt + '  [Server as source -> any]')
      continue
    }
  }

  # --- простая проверка «широких» подсетей внутри server-групп (tsX/rdgX и пр.) ---
  $broadGroups = New-Object System.Collections.Generic.List[string]
  if($Obj -and $Obj.GroupSubnets){
    foreach($g in $Obj.GroupSubnets.Keys){
      foreach($sn in $Obj.GroupSubnets[$g]){
        $parts = $sn -split '\s+'
        if($parts.Count -ge 2){
          $mask = $parts[1]
          if($mask -eq '255.0.0.0' -or $mask -eq '255.255.0.0'){
            [void]$broadGroups.Add("object-group $g includes broad subnet $sn")
          }
        }
      }
    }
  }

  if($evAnyToSrv.Count -eq 0 -and $evSrvToAny.Count -eq 0){
    return New-Finding 'SRV-ACL' 'No server ANY exposure found' 'Info' $true
  }

  # --- вычислить severity: ANY->SERVER на outside in => High; только SERVER->ANY без outside in => Medium ---
  $outsideIn = $false
  foreach($l in ($evAnyToSrv + $evSrvToAny)){
    if($l -match '\[outside in\]'){ $outsideIn = $true; break }
  }
  $sev = 'High'
  if(-not $outsideIn -and $evAnyToSrv.Count -eq 0 -and $evSrvToAny.Count -gt 0){ $sev = 'Medium' }

  # --- собрать evidence ---
  $evid = New-Object System.Collections.Generic.List[string]
  if($evAnyToSrv.Count -gt 0){ [void]$evid.Add('[ANY -> SERVER]'); foreach($x in $evAnyToSrv){ [void]$evid.Add([string]$x) } }
  if($evSrvToAny.Count -gt 0){ [void]$evid.Add('[SERVER -> ANY]'); foreach($x in $evSrvToAny){ [void]$evid.Add([string]$x) } }
  if($broadGroups.Count -gt 0){ [void]$evid.Add('[GROUP CONTENT]'); foreach($x in $broadGroups){ [void]$evid.Add([string]$x) } }

  New-Finding 'SRV-ACL' 'Server-related ANY exposure (direction-aware)' $sev $false ($evid | Select-Object -Unique) `
    'Limit sources to trusted ranges; ensure server objects are on destination side; review group contents.'
}

function Check-AccessGroupBinding { param($Cfg)
  $bound = $Cfg.Index['access-group']
  if($bound){ New-Finding 'ACL-BIND' 'ACLs are bound to interfaces' 'Info' $true $bound }
  else      { New-Finding 'ACL-BIND' 'No access-group bindings' 'Medium' $false @() 'Bind ACLs to interfaces with access-group.' }
}

function Check-ACLRedundancy {
  param($Cfg)
  $acls = @()
  if($Cfg.Index.Contains('access-list')){ $acls = $Cfg.Index['access-list'] }
  if($acls.Count -eq 0){ return New-Finding 'ACL-REDUNDANCY' 'No ACLs found' 'Info' $true }

  $map = @{}
  foreach($ln in $acls){
    $p = Parse-AclLine -Line $ln
    if($p){ if(-not $map.ContainsKey($p.Name)){ $map[$p.Name] = [System.Collections.Generic.List[object]]::new() }; $map[$p.Name].Add($p) }
  }

  $duplicates = [System.Collections.Generic.List[string]]::new()
  $shadowed   = [System.Collections.Generic.List[string]]::new()
  $anyAnyAfter= [System.Collections.Generic.List[string]]::new()

  $boundNames = @()
  if($Cfg.Index.Contains('access-group')){
    foreach($ag in $Cfg.Index['access-group']){
      if($ag -match '^\s*access-group\s+(\S+)\s+in\s+interface\s+\S+'){ $boundNames += $matches[1] }
    }
  }
  $boundNames = $boundNames | Select-Object -Unique
  $unbound = ($map.Keys | Where-Object { $boundNames -notcontains $_ })

  foreach($name in $map.Keys){
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $rules = $map[$name]

    # any-any not last
    for($i=0;$i -lt $rules.Count; $i++){
      if($rules[$i].Action -eq 'permit' -and $rules[$i].Proto -eq 'ip' -and
         $rules[$i].SrcType -eq 'any' -and $rules[$i].DstType -eq 'any' -and
         $i -lt ($rules.Count-1)){
        $anyAnyAfter.Add("[$name] ANY-ANY not last: " + $rules[$i].Raw.Trim())
      }
    }

    for($i=0;$i -lt $rules.Count;$i++){
      $raw = ($rules[$i].Raw -replace '\s+',' ').Trim()
      if($seen.Contains($raw)){ $duplicates.Add("[$name] DUP: $raw"); continue } else { [void]$seen.Add($raw) }
      for($k=0;$k -lt $i;$k++){
        if(Is-SupersetRule -R1 $rules[$k] -R2 $rules[$i]){
          $shadowed.Add("[$name] SHADOW: " + $rules[$i].Raw.Trim() + "  [by] " + $rules[$k].Raw.Trim()); break
        }
      }
    }
  }

  if($duplicates.Count -or $shadowed.Count -or $unbound.Count -or $anyAnyAfter.Count){
    $evid = @()
    if($duplicates.Count){ $evid += ($duplicates | Select-Object -First 10) }
    if($shadowed.Count){   $evid += ($shadowed   | Select-Object -First 10) }
    if($unbound){          $evid += ($unbound    | ForEach-Object { "[UNBOUND] $_" } | Select-Object -First 10) }
    if($anyAnyAfter.Count){$evid += ($anyAnyAfter| Select-Object -First 10) }
    $rec = @()
    if($duplicates.Count){ $rec += 'Remove exact duplicate ACL lines.' }
    if($shadowed.Count){   $rec += 'Reorder: specific rules first, wide rules later; avoid any-any.' }
    if($unbound){          $rec += 'Remove or bind unused ACLs via access-group.' }
    if($anyAnyAfter.Count){$rec += 'Place "permit ip any any" strictly at the end of each ACL (if needed).' }
    New-Finding 'ACL-REDUNDANCY' 'Redundant/shadowed/unused ACLs detected' 'Medium' $false $evid ($rec -join ' ')
  } else {
    New-Finding 'ACL-REDUNDANCY' 'No redundancy detected (heuristic)' 'Info' $true
  }
}

function Check-Telnet { param($Cfg)
  $hits = $Cfg.Index['telnet']
  if($hits){ New-Finding 'MGMT-TELNET' 'Telnet enabled' 'High' $false $hits 'Disable telnet; use SSHv2 and restrict sources.' }
  else     { New-Finding 'MGMT-TELNET' 'Telnet disabled' 'Info' $true }
}

function Check-SSH { param($Cfg)
  $ssh = $Cfg.Index['ssh ']
  $ver = $Cfg.Index['ssh version']
  if($ver -and ($ver -match 'ssh version\s+1')){ return New-Finding 'MGMT-SSH' 'SSH version 1 enabled' 'High' $false $ver 'Use only SSH v2 and restrict sources.' }
  if(-not $ssh){ return New-Finding 'MGMT-SSH' 'SSH not configured' 'Low' $true }
  $wide = $ssh | Where-Object { $_ -match '\b0\.0\.0\.0\s+0\.0\.0\.0\b' -or $_ -match '\bany\b' -or $_ -match '\bmgmt\b' -or $_ -match '\sguest\b' }
  if($wide){ New-Finding 'MGMT-SSH' 'SSH allowed widely' 'Medium' $false $ssh 'Restrict SSH to management ranges only.' }
  else     { New-Finding 'MGMT-SSH' 'SSH sources restricted' 'Info' $true $ssh }
}

function Check-HTTPMgmt { param($Cfg)
  $httpOn = $Cfg.Index['http ']
  $server = $Cfg.Index['http server']
  if($server){
    $badZone = $httpOn | Where-Object { $_ -match '\sguest\b' -or $_ -match '\spartner\b' -or $_ -match '\b0\.0\.0\.0\s+0\.0\.0\.0\b' -or $_ -match '\bany\b' }
    if($badZone){ return New-Finding 'MGMT-HTTP' 'ASDM/HTTP allowed from guest/partner/wide' 'Medium' $false ($server+$badZone) 'Restrict HTTP/ASDM to inside or mgmt subnets; disable if not needed.' }
    if($httpOn){ New-Finding 'MGMT-HTTP' 'ASDM/HTTP restricted' 'Info' $true ($server+$httpOn) }
    else { New-Finding 'MGMT-HTTP' 'HTTP server enabled without rules' 'Medium' $false $server 'Add http <ip> <mask> <iface> or disable.' }
  } else { New-Finding 'MGMT-HTTP' 'HTTP server disabled' 'Info' $true }
}

function Check-PlainPasswords { param($Cfg)
  $plain = @()
  if($Cfg.Index.Contains('enable password')){ $plain += $Cfg.Index['enable password'] }
  if($Cfg.Index.Contains('username')){ $plain += ($Cfg.Index['username'] | Where-Object { $_ -notmatch '\bencrypted\b' }) }
  if($Cfg.Index.Contains('passwd')){ $plain += $Cfg.Index['passwd'] }
  if($plain){ New-Finding 'AUTH-PLAIN' 'Insecure passwords/enable' 'High' $false $plain 'Use enable secret and encrypted; prefer AAA.' }
  else      { New-Finding 'AUTH-PLAIN' 'No insecure password lines found' 'Info' $true }
}

function Check-AAA { param($Cfg)
  $auth = @()
  if($Cfg.Index.Contains('aaa ')){ $auth = $Cfg.Index['aaa '] | Where-Object { $_ -match 'aaa authentication (ssh|enable) console' } }
  if($auth){ New-Finding 'AAA-AUTH' 'AAA authentication configured' 'Info' $true $auth }
  else     { New-Finding 'AAA-AUTH' 'AAA not configured' 'Medium' $false @() 'Enable TACACS+/RADIUS; LOCAL fallback.' }
}

function Check-AAA-Use { param($Cfg)
  $aaaLocal = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa\s+authentication\s+(ssh|enable)\s+console\s+LOCAL\b' }
  $aaaTac   = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa\s+authentication\s+(ssh|enable)\s+console\s+\S+\b' -and $_ -notmatch '\bLOCAL\b' }
  $tacSrv   = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa-server\s+\S+\s+protocol\s+tacacs\+' }
  if($tacSrv -and $aaaLocal -and (-not $aaaTac)){
    New-Finding 'AAA-USAGE' 'TACACS defined but not used (LOCAL only)' 'Medium' $false (@($tacSrv)+@($aaaLocal)) 'Switch aaa authentication to TACACS with LOCAL fallback.'
  } else {
    New-Finding 'AAA-USAGE' 'AAA usage looks consistent' 'Info' $true
  }
}

function Check-AAA-Resilience { param($Cfg)
  $tac = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa-server\s+\S+\s+protocol\s+tacacs\+' }
  $plainLocal = @()
  if($Cfg.Index.Contains('username')){ $plainLocal = ($Cfg.Index['username'] | Where-Object { $_ -notmatch '\bencrypted\b' }) }
  if($tac -and $plainLocal){
    New-Finding 'AAA-RESILIENCE' 'TACACS present but weak local fallbacks exist' 'Medium' $false ($tac + $plainLocal | Select-Object -First 6) 'Use encrypted local users or disable excessive locals.'
  } else {
    New-Finding 'AAA-RESILIENCE' 'AAA fallback posture OK (heuristic)' 'Info' $true
  }
}

function Check-SNMP { param($Cfg)
  $snmp = @()
  if($Cfg.Index.Contains('snmp-server')){ $snmp = $Cfg.Index['snmp-server'] }
  if(-not $snmp -or $snmp.Count -eq 0){ return New-Finding 'SNMP' 'SNMP not present' 'Info' $true }
  $community = $snmp | Where-Object { $_ -match '^\s*snmp-server\s+community\s+(\S+)' }
  $public = $community | Where-Object { $_ -match '\bpublic\b|\bprivate\b' }
  $hosts = $snmp | Where-Object { $_ -match '^\s*snmp-server\s+host\b' }
  if($public){ return New-Finding 'SNMP' 'Community public/private used' 'High' $false $public 'Change community; limit managers and ACLs.' }
  if($snmp -and -not $hosts){ return New-Finding 'SNMP' 'SNMP without explicit hosts' 'Medium' $false $snmp 'Specify snmp-server host entries.' }
  $snmpv3user = $Cfg.Lines | Where-Object { $_ -match '^\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\b' }
  if($snmpv3user){ New-Finding 'SNMP' 'SNMPv3 present' 'Info' $true ($community+$hosts+$snmpv3user) }
  else { New-Finding 'SNMP' 'SNMPv3 not configured (v2c in use)' 'Medium' $false ($community+$hosts) 'Migrate to SNMPv3 (auth+priv); keep v2c only temporarily and restrict by ACL.' }
}

function Check-SNMPv3-Strength { param($Cfg)
  $u = $Cfg.Lines | Where-Object { $_ -match '^\s*snmp-server\s+user\s+\S+\s+\S+\s+v3\b' }
  if($u){
    $weak = $u | Where-Object { $_ -match '\bauth\s+md5\b' -or $_ -match '\bpriv\s+des\b' }
    if($weak){ return New-Finding 'SNMP-V3-WEAK' 'SNMPv3 weak (MD5/DES)' 'Medium' $false $weak 'Use SHA-256 (auth) and AES (priv).' }
    else { return New-Finding 'SNMP-V3-WEAK' 'SNMPv3 strong (heuristic)' 'Info' $true $u }
  }
  New-Finding 'SNMP-V3-WEAK' 'SNMPv3 not present' 'Info' $true
}

function Check-Logging { param($Cfg)
  $allLog = @()
  if($Cfg.Index.Contains('logging ')){ $allLog = $Cfg.Index['logging '] }
  $enabled = $allLog | Where-Object { $_ -match '^\s*logging\s+enable\b' }
  $hosts   = $allLog | Where-Object { $_ -match '^\s*logging\s+host\b' }
  $trap    = $allLog | Where-Object { $_ -match '^\s*logging\s+trap\s+\S+' }
  if($enabled -and $hosts -and $trap){ New-Finding 'LOGGING' 'Syslog configured' 'Info' $true ($enabled+$hosts+$trap) }
  elseif($enabled){ New-Finding 'LOGGING' 'Logging partially configured' 'Low' $false ($enabled+$hosts+$trap) 'Add logging host and logging trap.' }
  else { New-Finding 'LOGGING' 'Logging disabled' 'Medium' $false @() 'Enable logging and configure host/trap.' }
}

function Check-Logging-Drops { param($Cfg)
  $no1060x = $Cfg.Lines | Where-Object { $_ -match '^\s*no\s+logging\s+message\s+10(6015|6023)\b' }
  if($no1060x){
    New-Finding 'LOGGING-DENY' 'Deny log messages disabled (106015/106023)' 'Medium' $false $no1060x 'Avoid disabling base deny logs; restore defaults for incident response.'
  } else {
    New-Finding 'LOGGING-DENY' 'Base deny log messages enabled' 'Info' $true
  }
}

function Check-ThreatDetection { param($Cfg)
  $td = @(); if($Cfg.Index.Contains('threat-detection')){ $td = $Cfg.Index['threat-detection'] }
  $basic = $td | Where-Object { $_ -match 'basic-threat' }
  $disabled = $Cfg.Lines | Where-Object { $_ -match '^\s*no\s+threat-detection\s+statistics\s+\S+' }
  if($basic -and -not $disabled){ New-Finding 'THREAT-DET' 'Threat-detection basic enabled' 'Info' $true $basic }
  elseif($basic -and $disabled){ New-Finding 'THREAT-DET' 'Threat-detection with some statistics disabled' 'Low' $false ($basic+$disabled) 'Re-enable statistics unless there is a reason.' }
  else { New-Finding 'THREAT-DET' 'Threat-detection disabled' 'Low' $false @() 'Enable threat-detection basic-threat.' }
}

function Check-ICMP { param($Cfg)
  $icmp = @()
  if($Cfg.Index.Contains('icmp ')){ $icmp = $Cfg.Index['icmp '] }
  $wide = $icmp | Where-Object { $_ -match '^\s*icmp\s+permit\s+any\s+\S+' }
  if($wide){ New-Finding 'ICMP' 'ICMP permit any found' 'Low' $false $wide 'Restrict ICMP to required sources.' }
  else     { New-Finding 'ICMP' 'ICMP looks restricted/default' 'Info' $true }
}

function Check-ICMP-ACL-Outside {
  param($Cfg)
  $acls = @(); if($Cfg.Index.Contains('access-list')){ $acls = $Cfg.Index['access-list'] }
  $outsideBind = Get-OutsideAcls -Cfg $Cfg
  if(-not $outsideBind){ return New-Finding 'ICMP-ACL' 'Outside ACL not bound' 'Info' $true }
  $hits = $acls | Where-Object {
    $_ -match '^\s*access-list\s+OUTSIDE_IN\s+extended\s+permit\s+icmp\s+any\s+any\s+(echo|echo-reply|any)\b'
  }
  if($hits){
    New-Finding 'ICMP-ACL' 'ICMP permitted from any in OUTSIDE_IN' 'Low' $false $hits 'Limit ICMP types and/or source ranges.'
  } else {
    New-Finding 'ICMP-ACL' 'No broad ICMP permits in OUTSIDE_IN' 'Info' $true
  }
}

function Check-IPv6AnyAny { param($Cfg)
  $hits = $Cfg.Lines | Where-Object { $_ -match '^\s*access-list\s+\S+\s+extended\s+permit\s+ip\s+any6\s+any6\b' }
  if($hits){ New-Finding 'ACL6-ANY-ANY' 'IPv6 any6 any6 present' 'High' $false $hits 'Restrict IPv6 ACL and bind to interface.' } else { New-Finding 'ACL6-ANY-ANY' 'No IPv6 any-any' 'Info' $true }
}

function Check-VPN {
  param($Cfg)

  $ikev1pol = @(); if($Cfg.Index.Contains('crypto ikev1 policy')){ $ikev1pol = $Cfg.Index['crypto ikev1 policy'] }
  $ikev2pol = @(); if($Cfg.Index.Contains('crypto ikev2 policy')){ $ikev2pol = $Cfg.Index['crypto ikev2 policy'] }
  $hasCryptoMap = ($Cfg.Lines | Where-Object {
    $_ -match '^\s*crypto\s+map\s+\S+\s+\d+\s+' -or $_ -match '^\s*crypto\s+map\s+\S+\s+interface\s+\S+'
  })

  # Собираем только осмысленные evidence из секции webvpn: "webvpn enable <iface>"
  $webvpnEnable = New-Object System.Collections.Generic.List[string]
  for($i=0;$i -lt $Cfg.Lines.Count; $i++){
    if($Cfg.Lines[$i] -match '^\s*webvpn\b'){
      for($j=$i+1; $j -lt $Cfg.Lines.Count -and $Cfg.Lines[$j] -match '^\s+'; $j++){
        if($Cfg.Lines[$j] -match '^\s*enable\s+(\S+)'){
          [void]$webvpnEnable.Add("webvpn " + $Cfg.Lines[$j].Trim())
        }
      }
    }
  }

  if(($ikev1pol.Count -eq 0) -and ($ikev2pol.Count -eq 0) -and -not $hasCryptoMap -and ($webvpnEnable.Count -eq 0)){
    return New-Finding 'VPN-IKE' 'No VPN/IKE found' 'Info' $true
  }
  if($ikev1pol.Count -gt 0 -and $ikev2pol.Count -eq 0){
    return New-Finding 'VPN-IKE' 'IKEv1 only' 'Medium' $false $ikev1pol 'Migrate to IKEv2.'
  }
  if($ikev2pol.Count -gt 0 -and $ikev1pol.Count -gt 0){
    return New-Finding 'VPN-IKE' 'Both IKEv1 and IKEv2' 'Low' $false ($ikev1pol+$ikev2pol) 'Prefer IKEv2 only.'
  }
  if($hasCryptoMap -or $webvpnEnable.Count -gt 0){
    if($ikev2pol.Count -eq 0){
      $ev = @()
      if($hasCryptoMap){ $ev += $hasCryptoMap }
      if($webvpnEnable.Count -gt 0){ $ev += ($webvpnEnable | Select-Object -Unique) }
      return New-Finding 'VPN-IKE' 'VPN present (no explicit ikev2 policies found)' 'Low' $false $ev 'Define IKEv2 policies and prefer them.'
    }
  }
  return New-Finding 'VPN-IKE' 'IKEv2 present' 'Info' $true $ikev2pol
}

function Check-NATLoose { param($Cfg)
  $wide = $Cfg.Lines | Where-Object { ($_ -match '^\s*nat\s*\(') -and ($_ -match '\bany\b') -and ($_ -match '\bany\b') }
  if($wide){ New-Finding 'NAT-WIDE' 'Wide NAT any->any' 'Low' $false $wide 'Tighten NAT objects; avoid any->any.' }
  else     { New-Finding 'NAT-WIDE' 'NAT looks specific' 'Info' $true }
}

function Check-NAT-BroadObjects { param($Cfg)
  $hits = $Cfg.Lines | Where-Object {
    ($_ -match '^\s*nat\s*\(\S+,\S+\)\s+source\s+static\s+\S+\s+\S+\b') -and ($_ -match '\bobject-group\b' -or $_ -match '\b\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\b')
  }
  if($hits){
    New-Finding 'NAT-BROAD' 'Broad object-based static/twice NAT' 'Medium' $false $hits 'Scope NAT to specific hosts/ports; avoid group-to-group identity/static NAT.'
  } else {
    New-Finding 'NAT-BROAD' 'No broad object-based NAT detected' 'Info' $true
  }
}

function Check-WeakCrypto {
  param($Cfg)

  $lines = $Cfg.Lines
  $ev = New-Object System.Collections.Generic.List[string]
  $sev = 'Info'

  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*crypto\s+ikev1\s+policy\s+(\S+)'){
      $blk = @($lines[$i])
      for($j=$i+1; $j -lt $lines.Count -and $lines[$j] -match '^\s+(authentication|encryption|hash|group|lifetime)\b'; $j++){ $blk += $lines[$j] }
      $i = $j-1
      $b = $blk -join ' '
      if($b -match '\bencryption\s+des\b' -or $b -match '\bencryption\s+3des\b'){ $sev='High'; $ev.Add($blk -join ' ') }
      if($b -match '\bhash\s+md5\b' -or $b -match '\bhash\s+sha\b(?!256)'){ if($sev -ne 'High'){ $sev='Medium' }; $ev.Add($blk -join ' ') }
      if($b -match '\bgroup\s+(1|2|5)\b'){ if($sev -ne 'High'){ $sev='Medium' }; $ev.Add($blk -join ' ') }
    }
  }

  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*crypto\s+ikev2\s+policy\s+(\S+)'){
      $blk = @($lines[$i])
      for($j=$i+1; $j -lt $lines.Count -and $lines[$j] -match '^\s+(encryption|integrity|prf|group|lifetime)\b'; $j++){ $blk += $lines[$j] }
      $i = $j-1
      $b = $blk -join ' '
      if($b -match '\bintegrity\s+sha1\b' -or $b -match '\bintegrity\s+md5\b'){ if($sev -ne 'High'){ $sev='Medium' }; $ev.Add($blk -join ' ') }
      if($b -match '\bencryption\s+aes-cbc-128\b'){ if($sev -eq 'Info'){ $sev='Low' }; $ev.Add($blk -join ' ') }
      if($b -match '\bgroup\s+(1|2|5)\b'){ if($sev -ne 'High'){ $sev='Medium' }; $ev.Add($blk -join ' ') }
    }
  }

  $rsa = @(); if($Cfg.Index.Contains('crypto key')){ $rsa = $Cfg.Index['crypto key'] | Where-Object { $_ -match 'crypto\s+key\s+generate\s+rsa\b.*\bmodulus\s+(\d+)' } }
  foreach($r in $rsa){ if($r -match 'modulus\s+(\d+)'){ $m=[int]$matches[1]; if($m -lt 2048){ $sev='High'; $ev.Add($r) } } }

  $sa = $Cfg.Index['ipsec security-association '] | Where-Object { $_ -match 'lifetime\s+kilobytes\s+(\d+)' }
  foreach($s in $sa){ if($s -match 'kilobytes\s+(\d+)'){ $kb=[int]$matches[1]; if($kb -gt 8388608){ if($sev -eq 'Info'){ $sev='Low' }; $ev.Add($s) } } } # >8GB

  if($ev.Count -gt 0){
    New-Finding 'CRYPTO-WEAK' 'Weak/legacy crypto (IKE/SSH/SA)' $sev $false ($ev | Select-Object -Unique) 'Use IKEv2 with AES-GCM/SHA-256/DH>=14; RSA >=2048; reasonable SA lifetimes.'
  } else {
    New-Finding 'CRYPTO-WEAK' 'No weak crypto found (heuristic)' 'Info' $true
  }
}

function Check-IpsecTransformWeak { param($Cfg)
  $ts = $Cfg.Index['crypto ipsec ikev1 transform-set']
  $use = $Cfg.Index['crypto map']
  $weak = @()
  if($ts){
    foreach($l in $ts){
      if($l -match '\b3des\b' -or ($l -match '\bsha\b' -and $l -notmatch 'sha256') -or ($l -match '\bmd5\b')){ $weak += $l }
    }
  }
  if($weak.Count -gt 0){
    New-Finding 'IPSEC-TS-WEAK' 'Weak IPsec transform-set (3DES/SHA1/MD5)' 'High' $false ($weak + ($use | Where-Object { $_ -match 'set\s+ikev1\s+transform-set' })) 'Replace with AES-(GCM or CBC-256) and SHA-256 PRF; avoid SHA1/3DES/MD5.'
  } else {
    New-Finding 'IPSEC-TS-WEAK' 'No weak IPsec transform-sets found' 'Info' $true
  }
}

function Check-PolicyInspectLegacy { param($Cfg)
  $pm = @($Cfg.Lines | Where-Object { $_ -match '^\s*inspect\s+\S+' })
  $legacy = @($pm | Where-Object { $_ -match 'inspect\s+(rsh|xdmcp|netbios)\b' })
  if($legacy.Count -gt 0){
    New-Finding 'POLICY-LEGACY' 'Legacy/rare inspections enabled' 'Low' $false $legacy 'Remove unused inspections (rsh/xdmcp/netbios) to reduce attack surface.'
  } else {
    New-Finding 'POLICY-LEGACY' 'No legacy inspections found' 'Info' $true
  }
}

function Check-Inspect-Loosened { param($Cfg)
  $dns  = $Cfg.Lines | Where-Object { $_ -match '^\s*policy-map\s+type\s+inspect\s+dns\b' -or $_ -match '^\s*dns\s+' -or $_ -match '^\s*inspect\s+dns\b' }
  $weak = $Cfg.Lines | Where-Object { $_ -match 'no\s+protocol-enforcement\b' -or $_ -match 'no\s+rtp-conformance\b' -or $_ -match 'no\s+h245' }
  if($weak){
    New-Finding 'INSPECT-LOOSE' 'Inspection relaxations present (DNS/SIP/H323)' 'Medium' $false ($dns+$weak | Select-Object -Unique) 'Re-enable protocol enforcement and security options.'
  } else {
    New-Finding 'INSPECT-LOOSE' 'No inspection relaxations detected' 'Info' $true
  }
}

function Check-MPF-Bypass { param($Cfg)
  $classes = $Cfg.Lines | Where-Object { $_ -match '^\s*class-map\b' -or $_ -match '^\s*policy-map\b' -or $_ -match '^\s*service-policy\b' }
  $noinsp = $Cfg.Lines | Where-Object { $_ -match '^\s*no\s+inspect\b' }
  $catchAll = $Cfg.Lines | Where-Object { $_ -match '^\s*class\s+\S+\s*$' -and $_ -match '\bmatch\s+any\b' }
  $attach = $Cfg.Lines | Where-Object { $_ -match '^\s*service-policy\s+\S+\s+(inside|outside|global|dmz|mgmt|Management0/0)\b' }
  if($noinsp -and $catchAll -and $attach){
    New-Finding 'MPF-BYPASS' 'Inspection bypassed via no inspect (catch-all)' 'High' $false ($classes+$noinsp+$attach | Select-Object -Unique) 'Remove "no inspect" catch-all or scope minimally.'
  } else {
    New-Finding 'MPF-BYPASS' 'No global inspection bypass detected' 'Info' $true
  }
}

function Check-ServicePasswordEncryption {
  param($Cfg)
  $svc = $Cfg.Index['service password-encryption']
  if($svc){
    New-Finding 'PWD-ENC-TYPE7' 'service password-encryption enabled (Type 7)' 'Low' $false $svc 'Do not rely on Type 7. Prefer enable secret/AAA.'
  } else {
    New-Finding 'PWD-ENC-TYPE7' 'service password-encryption not set' 'Info' $true
  }
}

function Check-NAT-Partner-Risky {
  param($Cfg)
  $hits = $Cfg.Lines | Where-Object {
    ($_ -match '^\s*nat\s*\(partner,dmz\)') -and ($_ -match '\b(INTERNAL|INTERNAL-SUBNETS)\b')
  }
  if($hits){
    New-Finding 'NAT-PARTNER' 'Partner-to-DMZ NAT links internal subnets' 'Medium' $false $hits 'Avoid broad NAT from partner to internal; scope to specific hosts/ports.'
  } else {
    New-Finding 'NAT-PARTNER' 'No risky partner NAT detected' 'Info' $true
  }
}

function Check-RESTAPI { param($Cfg)
  $any = $Cfg.Lines | Where-Object { $_ -match '^\s*rest-api\s+client\s+0\.0\.0\.0\s+0\.0\.0\.0\b' }
  if($any){ New-Finding 'REST-API' 'REST API open to any' 'High' $false $any 'Restrict to mgmt/VPN subnets.' } else { New-Finding 'REST-API' 'REST API not wide-open' 'Info' $true }
}

function Check-WebVPNCiphers {
  param($Cfg)

  $weak = New-Object System.Collections.Generic.List[string]

  # 1) Явные слабые директивы (без заголовков "webvpn")
  $patterns = @(
    '^\s*ssl\s+encryption\s+.*\b(rc4|md5|3des|(?<![a-z])des(?![a-z]))\b', # rc4 / md5 / 3des / des
    '^\s*ssl\s+encryption\s+.*\bsha1\b',                                  # CBC+SHA1
    '^\s*ssl\s+cipher\s+dtlsv?1(?:\.0)?\b.*\b(rc4|md5|3des|(?<![a-z])des(?![a-z])|sha1)\b',
    '^\s*anyconnect\s+ssl\s+cipher\s+rc4-md5\b',
    '^\s*anyconnect\s+ssl\s+cipher\b.*\b(rc4|md5|3des|(?<![a-z])des(?![a-z])|sha1)\b'
  )
  foreach($line in $Cfg.Lines){
    foreach($rx in $patterns){
      if($line -match $rx){ [void]$weak.Add($line); break }
    }
  }

  # 2) Кастомные списки DTLS/TLS: ssl cipher dtls1 custom "<list>", ssl cipher custom "<list>"
  foreach($line in $Cfg.Lines){
    # DTLS custom
    if($line -match '^\s*ssl\s+cipher\s+dtls(v?1(?:\.0)?)\s+custom\s+"([^"]+)"'){
      $list = $matches[2] -split '[:;, ]+' | Where-Object { $_ }
      $bad  = @($list | ForEach-Object { $_.ToUpperInvariant() } |
                Where-Object { $_ -match 'RC4|MD5|3DES|(^|[-_])DES($|[-_])' -or $_ -match 'SHA(?!256|384|512)' })
      if($bad.Count -gt 0){ [void]$weak.Add($line + '  ! WEAK: ' + ($bad -join ', ')) }
    }
    # TLS custom (не DTLS)
    elseif($line -match '^\s*ssl\s+cipher\s+custom\s+"([^"]+)"'){
      $list = $matches[1] -split '[:;, ]+' | Where-Object { $_ }
      $bad  = @($list | ForEach-Object { $_.ToUpperInvariant() } |
                Where-Object { $_ -match 'RC4|MD5|3DES|(^|[-_])DES($|[-_])' -or $_ -match 'SHA(?!256|384|512)' })
      if($bad.Count -gt 0){ [void]$weak.Add($line + '  ! WEAK: ' + ($bad -join ', ')) }
    }
  }

  $weak = $weak | Select-Object -Unique

  if($weak.Count -gt 0){
    New-Finding 'WEBVPN-CIPHERS' 'Weak SSL cipher suite' 'High' $false $weak `
      'Use TLS1.2/1.3 with AES-GCM; remove RC4/MD5/3DES/DES and CBC+SHA1.'
  } else {
    New-Finding 'WEBVPN-CIPHERS' 'SSL ciphers look ok' 'Info' $true
  }
}

function Check-CA-CRL { param($Cfg)
  $crlOpt = $Cfg.Lines | Where-Object { $_ -match '^\s*crl\s+optional\b' }
  if($crlOpt){ New-Finding 'CA-CRL' 'CRL optional (revocation checking relaxed)' 'Medium' $false $crlOpt 'Enable strict CRL/OCSP revocation checking.' } else { New-Finding 'CA-CRL' 'CRL/OCSP not relaxed (heuristic)' 'Info' $true }
}

# ========== AnyConnect/SSL/DTLS extra checks ==========

function Check-AnyConnectSplitTunnel {
  param($Cfg)
  $gpSt = $Cfg.Lines | Where-Object { $_ -match '^\s*split-tunnel-network-list\s+value\s+(\S+)\b' }
  if(-not $gpSt){ return New-Finding 'AC-SPLIT' 'AnyConnect split-tunnel not configured (by GP)' 'Info' $true }

  $aclNames = @()
  foreach($l in $gpSt){ if($l -match 'value\s+(\S+)'){ $aclNames += $matches[1] } }
  $aclNames = $aclNames | Select-Object -Unique

  $broad = New-Object System.Collections.Generic.List[string]
  foreach($acl in $aclNames){
    $rx = '^\s*access-list\s+' + [regex]::Escape($acl) + '\s+standard\s+permit\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$'
    $lines = $Cfg.Lines | Where-Object { $_ -match $rx }
    foreach($ln in $lines){
      if($ln -match $rx){
        $mask = $matches[2]
        if($mask -eq '255.255.0.0' -or $mask -eq '255.0.0.0'){ [void]$broad.Add($ln) }
      }
    }
  }

  if($broad.Count -gt 0){
    return New-Finding 'AC-SPLIT' 'AnyConnect split-tunnel overly broad (/16 or wider)' 'Medium' $false ($broad | Select-Object -Unique) 'Narrow split-tunnel ACL; avoid /8 and /16.'
  } else {
    return New-Finding 'AC-SPLIT' 'AnyConnect split-tunnel looks scoped' 'Info' $true ($gpSt | Select-Object -First 4)
  }
}

function Check-AnyConnectProtocols {
  param($Cfg)
  $gpProto = $Cfg.Lines | Where-Object { $_ -match '^\s*vpn-tunnel-protocol\s+(.+)$' }
  if(-not $gpProto){ return New-Finding 'AC-PROTO' 'AnyConnect tunnel protocols (no explicit GP line)' 'Info' $true }
  $legacy = @($gpProto | Where-Object { $_ -match '\bdtls-sslv2\b' })
  $ikev1  = @($gpProto | Where-Object { $_ -match '\bikev1\b' })
  if($legacy.Count -gt 0 -or $ikev1.Count -gt 0){
    $ev = @()
    if($legacy){ $ev += $legacy }
    if($ikev1){  $ev += $ikev1  }
    return New-Finding 'AC-PROTO' 'AnyConnect allows legacy protocols (dtls-sslv2/ikev1)' 'Medium' $false $ev 'Disable dtls-sslv2 and ikev1; keep ikev2/ssl-client only.'
  } else {
    return New-Finding 'AC-PROTO' 'AnyConnect protocols OK (no legacy)' 'Info' $true $gpProto
  }
}

function Check-AnyConnectCiphersGP {
  param($Cfg)
  $gpWeak = $Cfg.Lines | Where-Object { $_ -match '^\s*anyconnect\s+ssl\s+cipher\s+rc4-md5\b' }
  if($gpWeak){
    return New-Finding 'AC-CIPHERS' 'AnyConnect weak SSL cipher in GP (RC4/MD5)' 'High' $false $gpWeak 'Use TLS 1.2+/AES-GCM; remove RC4/MD5.'
  } else {
    return New-Finding 'AC-CIPHERS' 'AnyConnect GP ciphers look OK' 'Info' $true
  }
}

function Check-SSLVersions {
  param($Cfg)
  $tls10 = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+cipher\s+version\s+tlsv1\b' }
  $tls11 = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+cipher\s+version\s+tlsv1\.1\b' }
  $hits = @($tls10 + $tls11)
  if($hits -and $hits.Count -gt 0){
    return New-Finding 'SSL-VERS' 'Deprecated TLS versions enabled (1.0/1.1)' 'High' $false $hits 'Disable TLS 1.0/1.1; keep TLS 1.2/1.3.'
  } else {
    return New-Finding 'SSL-VERS' 'Only modern TLS versions observed (heuristic)' 'Info' $true
  }
}

function Check-SSLDHGroup {
  param($Cfg)
  $weak = @($Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+dh-group\s+group[125]\b' })
  if($weak -and $weak.Count -gt 0){
    return New-Finding 'SSL-DH' 'Weak SSL DH group configured (<= group5)' 'Medium' $false $weak 'Use DH group14+ (2048 bit) or ECDHE.'
  } else {
    return New-Finding 'SSL-DH' 'SSL DH group looks modern (heuristic)' 'Info' $true
  }
}

function Check-DynFilterConfig {
  param($Cfg)
  $enabled = $Cfg.Lines | Where-Object { $_ -match '^\s*dynamic-filter\s+enable\b' -or $_ -match '^\s*botnet-traffic-filter\s+enable\b' }
  if(-not $enabled){ return New-Finding 'DYFILT' 'Dynamic/Botnet filter not enabled' 'Info' $true }
  $hasUpdate = $Cfg.Lines | Where-Object { $_ -match '^\s*dynamic-filter\s+(update|database|signed-list)\b' }
  if(-not $hasUpdate){
    return New-Finding 'DYFILT' 'Dynamic/Botnet filter enabled but no feeds configured' 'Low' $false $enabled 'Add update/signature source or disable the feature.'
  } else {
    return New-Finding 'DYFILT' 'Dynamic/Botnet filter configured with feeds' 'Info' $true ($enabled+$hasUpdate)
  }
}

function Check-DTLSVersion {
  param($Cfg)
  $hits = @()
  $hits += ($Cfg.Lines | Where-Object { $_ -match '^\s*anyconnect\s+dtls\s+version\s+dtlsv?1\.0\b' })
  $hits += ($Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+dtls-version\s+dtlsv?1\.0\b' })
  if($hits.Count -gt 0){
    return New-Finding 'DTLS-VERS' 'DTLS 1.0 enabled' 'High' $false $hits 'Use DTLS 1.2 or disable DTLS; prefer TLS1.2/1.3 with AEAD.'
  } else {
    return New-Finding 'DTLS-VERS' 'No DTLS 1.0 observed' 'Info' $true
  }
}

function Check-DTLSCiphersWeak {
  param($Cfg)
  $dtls = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+cipher\s+dtlsv?1\.0\s+encryption\s+' -or $_ -match '^\s*ssl\s+dtls\s+encryption\s+' -or $_ -match '^\s*anyconnect\s+ssl\s+cipher\s+' }
  $weak = @()
  foreach($l in $dtls){
    if($l -match '\brc4\b' -or $l -match '\bmd5\b' -or $l -match '\b3des-cbc\b' -or $l -match '\bdes-cbc\b' -or $l -match '\baes(128|256)-cbc\b.*\bsha1\b'){
      $weak += $l
    }
  }
  if($weak.Count -gt 0){
    return New-Finding 'DTLS-CIPHERS' 'Weak DTLS ciphers present (RC4/MD5/3DES/DES/CBC+SHA1)' 'High' $false ($weak | Select-Object -Unique) 'Prefer AES-GCM (AEAD) on DTLS 1.2; remove RC4/MD5/3DES/DES and CBC+SHA1.'
  } else {
    return New-Finding 'DTLS-CIPHERS' 'No obviously weak DTLS ciphers' 'Info' $true $dtls
  }
}

function Check-DTLSCipherPriority {
  param($Cfg)
  $prio = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+cipher\s+priority\s+\d+\s+encryption\s+\S+\s+authentication\s+\S+' }
  if(-not $prio -or $prio.Count -eq 0){ return New-Finding 'DTLS-PRIO' 'No explicit DTLS cipher priority found' 'Info' $true }
  $weakIdx = @()
  $gcmIdx  = @()
  foreach($l in $prio){
    if($l -match 'priority\s+(\d+)\b'){ $n=[int]$matches[1] } else { continue }
    if($l -match '\brc4\b|\bmd5\b|\b3des-cbc\b|\bdes-cbc\b|\baes(128|256)-cbc\b.*\bsha1\b'){ $weakIdx += $n }
    if($l -match '\baes(128|256)-gcm\b'){ $gcmIdx += $n }
  }
  if($weakIdx.Count -gt 0 -and $gcmIdx.Count -gt 0 -and ([int]([array]($weakIdx | Measure-Object -Minimum)).Minimum) -lt ([int]([array]($gcmIdx | Measure-Object -Minimum)).Minimum)){
    return New-Finding 'DTLS-PRIO' 'Weak DTLS cipher has higher priority than GCM' 'High' $false $prio 'Place GCM suites at the highest priority; remove weak suites.'
  } else {
    return New-Finding 'DTLS-PRIO' 'Cipher priority seems OK (heuristic)' 'Info' $true $prio
  }
}

function Check-SSLKeyExchange {
  param($Cfg)
  $ke = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+key-exchange\s+(\S+)\b' }
  if(-not $ke){ return New-Finding 'SSL-KE' 'No explicit SSL key-exchange directive' 'Info' $true }
  $rsaOnly = @($ke | Where-Object { $_ -match '\brsa\b' -and $_ -notmatch '\becdhe\b' })
  if($rsaOnly.Count -gt 0){
    return New-Finding 'SSL-KE' 'RSA key-exchange forced (no ECDHE/PFS)' 'Medium' $false $rsaOnly 'Prefer ECDHE for PFS; avoid static RSA-only key exchange.'
  } else {
    return New-Finding 'SSL-KE' 'Key exchange allows ECDHE/PFS (heuristic)' 'Info' $true $ke
  }
}

function Check-DTLSCompression {
  param($Cfg)
  $comp = $Cfg.Lines | Where-Object { $_ -match '^\s*anyconnect\s+dtls\s+compression\s+\S+\b' }
  if($comp){
    return New-Finding 'DTLS-COMP' 'DTLS compression enabled' 'Medium' $false $comp 'Disable DTLS compression.'
  } else {
    return New-Finding 'DTLS-COMP' 'No DTLS compression observed' 'Info' $true
  }
}

function Check-WebvpnTimeouts {
  param($Cfg)
  $ev = @()
  $uauth = $Cfg.Lines | Where-Object { $_ -match '^\s*timeout\s+uauth\s+\S+' }
  $sess  = $Cfg.Lines | Where-Object { $_ -match '^\s*anyconnect\s+session-timeout\s+(\d+)\b' }
  $idle  = $Cfg.Lines | Where-Object { $_ -match '^\s*anyconnect\s+idle-timeout\s+(\d+)\b' }
  if($uauth){ $ev += $uauth }
  if($sess){  $ev += $sess  }
  if($idle){  $ev += $idle  }
  if($ev.Count -gt 0){
    return New-Finding 'WEBVPN-TIME' 'Session/idle/uauth timeouts require review' 'Low' $false $ev 'Use shorter timeouts (e.g., session <= 240 min, idle <= 30–60 min).'
  } else {
    return New-Finding 'WEBVPN-TIME' 'No unusual WebVPN/AnyConnect timeouts observed' 'Info' $true
  }
}

function Check-LoggingDTLS {
  param($Cfg)
  $disabled = $Cfg.Lines | Where-Object { $_ -match '^\s*no\s+logging\s+message\s+7160(39|41)\b' }
  if($disabled){
    return New-Finding 'LOGGING-DTLS' 'DTLS/TLS negotiation logs disabled (716039/716041)' 'Low' $false $disabled 'Enable logging messages 716039/716041 to audit cipher negotiation.'
  } else {
    return New-Finding 'LOGGING-DTLS' 'DTLS/TLS negotiation logs enabled (heuristic)' 'Info' $true
  }
}

function Check-AnyConnectProfileCipher {
  param($Cfg)
  $pref = $Cfg.Lines | Where-Object { $_ -match '^\s*<PreferredDTLSCipher>\s*AES256-SHA\s*</PreferredDTLSCipher>\s*$' -or $_ -match 'PreferredDTLSCipher\s*>\s*AES256-SHA\s*<' }
  if($pref){
    return New-Finding 'AC-PROFILE' 'AnyConnect profile prefers AES256-SHA (CBC+SHA1)' 'Medium' $false $pref 'Remove PreferredDTLSCipher forcing CBC; allow GCM/AEAD.'
  } else {
    return New-Finding 'AC-PROFILE' 'No weak PreferredDTLSCipher in profile (heuristic)' 'Info' $true
  }
}

function Check-CertTrustpoint {
  param($Cfg)

  $bind = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+trust-point\s+\S+\s+\S+\s*$' }
  $tpBlocks = @()
  # собрать имена trustpoint
  $tpNames = @()
  foreach($b in $bind){ if($b -match 'ssl\s+trust-point\s+(\S+)\s+(\S+)'){ $tpNames += $matches[1] } }
  $tpNames = $tpNames | Select-Object -Unique

  # эвристика self-signed: enrollment self / DefaultASA
  $selfHints = New-Object System.Collections.Generic.List[string]
  for($i=0;$i -lt $Cfg.Lines.Count; $i++){
    if($Cfg.Lines[$i] -match '^\s*crypto\s+ca\s+trustpoint\s+(\S+)'){
      $name = $matches[1]
      $blk = @($Cfg.Lines[$i])
      for($j=$i+1; $j -lt $Cfg.Lines.Count -and $Cfg.Lines[$j] -match '^\s+'; $j++){ $blk += $Cfg.Lines[$j] }
      $i = $j-1
      if($tpNames -contains $name){
        foreach($l in $blk){
          if($l -match '\benrollment\s+self\b' -or $l -match 'subject-name\s+.*DefaultASA'){
            [void]$selfHints.Add("trustpoint $name : " + $l.Trim())
          }
        }
      }
    }
  }

  if(-not $bind -or $bind.Count -eq 0){
    return New-Finding 'CERT-TP' 'No ssl trust-point bound to interface(s)' 'Medium' $false @() 'Bind proper CA-issued trustpoint per interface: ssl trust-point <tp> <iface>.'
  }

  if($selfHints.Count -gt 0){
    return New-Finding 'CERT-TP' 'Self-signed/placeholder trustpoint in use (heuristic)' 'Medium' $false ($bind + ($selfHints | Select-Object -Unique)) 'Use CA-issued cert; avoid self-signed in production.'
  }

  New-Finding 'CERT-TP' 'Trustpoint bound (no obvious self-signed hints)' 'Info' $true $bind
}

function Check-AAA-Accounting {
  param($Cfg)

  $aaaSrvTac = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa-server\s+\S+\s+protocol\s+tacacs\+' }
  $authCfg   = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa\s+authentication\s+(ssh|enable)\s+console\s+\S+' }
  $acct      = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa\s+accounting\s+(command|connection|system)\s+\S+' }
  $authorCmd = $Cfg.Lines | Where-Object { $_ -match '^\s*aaa\s+authorization\s+command\s+\S+' }

  if($aaaSrvTac -and $authCfg -and (-not $acct)){
    return New-Finding 'AAA-ACCT' 'AAA accounting not configured' 'Medium' $false ($authCfg | Select-Object -First 3) 'Enable TACACS accounting (commands/system).'
  }
  if($aaaSrvTac -and (-not $authorCmd)){
    return New-Finding 'AAA-AUTHZ' 'AAA authorization for commands not configured' 'Medium' $false ($aaaSrvTac | Select-Object -First 3) 'Enable aaa authorization command (TACACS+).'
  }
  New-Finding 'AAA-ACCT' 'AAA accounting/authorization posture OK (heuristic)' 'Info' $true
}

function Check-NTP {
  param($Cfg)
  $ntp = $Cfg.Lines | Where-Object { $_ -match '^\s*ntp\s+server\s+\S+' }
  if(-not $ntp -or $ntp.Count -eq 0){
    return New-Finding 'NTP' 'No NTP servers configured' 'Low' $false @() 'Configure NTP for accurate logs/certs.'
  }
  New-Finding 'NTP' 'NTP servers present' 'Info' $true $ntp
}

function Check-VPNFilterDAP {
  param($Cfg)

  # наличие remote-access (webvpn или tunnel-group типа remote-access)
  $hasWebvpn = ($Cfg.Lines | Where-Object { $_ -match '^\s*webvpn\b' })
  $hasRA     = ($Cfg.Lines | Where-Object { $_ -match '^\s*tunnel-group\s+\S+\s+type\s+remote-access\b' })

  if(-not $hasWebvpn -and -not $hasRA){
    return New-Finding 'AC-VPN-FILTER' 'Remote access VPN not detected (heuristic)' 'Info' $true
  }

  # ищем vpn-filter и/или DAP
  $gpVpnFilter = $Cfg.Lines | Where-Object { $_ -match '^\s*group-policy\s+\S+\s+(internal|attributes)\b' -or $_ -match '^\s*vpn-filter\s+value\s+\S+' -or $_ -match '^\s*vpn-filter\s+\S+' }
  $vpnFilterAny = $Cfg.Lines | Where-Object { $_ -match '^\s*vpn-filter\s+(\S+|\s*value\s+\S+)\b' }
  $dap = $Cfg.Lines | Where-Object { $_ -match '^\s*dynamic-access-policy-record\b' }

  if((-not $vpnFilterAny -or $vpnFilterAny.Count -eq 0) -and (-not $dap -or $dap.Count -eq 0)){
    return New-Finding 'AC-VPN-FILTER' 'AnyConnect without vpn-filter/DAP' 'Medium' $false ($hasWebvpn | Select-Object -First 2) 'Apply vpn-filter per group-policy or use DAP to restrict user traffic.'
  }

  $ev = @()
  if($vpnFilterAny){ $ev += ($vpnFilterAny | Select-Object -First 5) }
  if($dap){ $ev += ($dap | Select-Object -First 5) }
  New-Finding 'AC-VPN-FILTER' 'AnyConnect access controls present (vpn-filter/DAP)' 'Info' $true $ev
}

function Check-ACLTimeRange {
  param($Cfg)
  $hits = $Cfg.Lines | Where-Object { $_ -match '^\s*access-list\s+\S+\s+\S+\s+.*\btime-range\s+\S+\b' }
  if($hits){
    New-Finding 'ACL-TIMERANGE' 'ACL entries with time-range (review schedules)' 'Info' $true ($hits | Select-Object -First 10)
  } else {
    New-Finding 'ACL-TIMERANGE' 'No ACL time-range entries found' 'Info' $true
  }
}

function Check-ProxyARP {
  param($Cfg)
  $noProxy = $Cfg.Lines | Where-Object { $_ -match '^\s*sysopt\s+noproxyarp(\s+\S+)?\s*$' }
  if($noProxy -and $noProxy.Count -gt 0){
    return New-Finding 'PROXY-ARP' 'Proxy ARP disabled (sysopt noproxyarp)' 'Info' $true $noProxy
  } else {
    # подсказка сильнее, если есть статические/identity NAT
    $natStatic = $Cfg.Lines | Where-Object { $_ -match '^\s*static\s+\(' -or $_ -match '^\s*nat\s*\(\S+,\S+\)\s+source\s+static\b' }
    $sev = if($natStatic){ 'Medium' } else { 'Low' }
    return New-Finding 'PROXY-ARP' 'Proxy ARP may be enabled (verify per interface)' $sev $false ($natStatic | Select-Object -First 3) 'Consider sysopt noproxyarp to avoid ARP exposure for NATs.'
  }
}

function Check-FailoverHygiene {
  param($Cfg)

  $fo = $Cfg.Lines | Where-Object { $_ -match '^\s*failover\b' }
  if(-not $fo){ return New-Finding 'FAILOVER' 'Failover not configured' 'Info' $true }

  $key   = $Cfg.Lines | Where-Object { $_ -match '^\s*failover\s+key(\s+hex)?\s+\S+' }
  $monif = $Cfg.Lines | Where-Object { $_ -match '^\s*monitor-interface\s+\S+' }
  $link  = $Cfg.Lines | Where-Object { $_ -match '^\s*failover\s+link\s+\S+\s+\S+' -or $_ -match '^\s*failover\s+interface-ip\s+\S+\s+' }

  $miss = @()
  if(-not $key){  $miss += 'failover key' }
  if(-not $monif){$miss += 'monitor-interface' }
  if(-not $link){ $miss += 'failover link/interface-ip' }

  if($miss.Count -gt 0){
    New-Finding 'FAILOVER' ('Failover configured but missing: ' + ($miss -join ', ')) 'Medium' $false (($fo | Select-Object -First 3) + ($key+$monif+$link)) 'Set failover key, monitor-interface, link/interface-ip.'
  } else {
    New-Finding 'FAILOVER' 'Failover configured (key/monitor/link present)' 'Info' $true ($key+$monif+$link)
  }
}

function Check-SameSecurity {
  param($Cfg)
  $same = $Cfg.Lines | Where-Object { $_ -match '^\s*same-security-traffic\s+permit\s+(intra-interface|inter-interface)\b' }
  if($same){
    New-Finding 'SAME-SEC' 'same-security-traffic permit enabled' 'Low' $false $same 'Keep only if required; review hairpin/inter-zone flows.'
  } else {
    New-Finding 'SAME-SEC' 'same-security-traffic not enabled' 'Info' $true
  }
}

function Check-ManagementAccess {
  param($Cfg)
  $mg = $Cfg.Lines | Where-Object { $_ -match '^\s*management-access\s+\S+\b' }
  if($mg){
    New-Finding 'MGMT-ACCESS' 'management-access enabled' 'Low' $false $mg 'Use only if needed (VPN mgmt through inside).'
  } else {
    New-Finding 'MGMT-ACCESS' 'management-access not set' 'Info' $true
  }
}

function Check-DMZtoInsideDeep {
  param($Cfg,$Obj)

  trap {
    Write-Error ("DMZ-INSIDE check failed: {0}" -f $_.Exception.Message)
    continue
  }

  # --- локальные utils (самодостаточно) ---
  function __NewSet { [System.Collections.Generic.HashSet[string]]::new() }
  function __Enum($x) { if($null -eq $x){ @() } elseif($x -is [System.Array]){ @($x) } else { @($x) } }
  function __Keys($h) { if($h -and $h.PSObject.Properties['Keys']){ @($h.Keys) } else { @() } }
  function __GetIndexLines { param($Cfg,$Key)
    if($Cfg -and $Cfg.Index -and $Cfg.Index.Contains($Key)){ @($Cfg.Index[$Key]) } else { @() }
  }
  function __IsRFC1918([string]$ip) {
    if([string]::IsNullOrWhiteSpace($ip)){ return $false }
    if($ip -match '^10\.') { return $true }
    if($ip -match '^192\.168\.') { return $true }
    if($ip -match '^172\.(1[6-9]|2\d|3[0-1])\.') { return $true }
    return $false
  }
  function __BindMap($Cfg){
    $map=@{}
    foreach($g in (__GetIndexLines $Cfg 'access-group')){
      $m=[regex]::Match($g,'^\s*access-group\s+(?<name>\S+)\s+(?<dir>in|out)\s+(?:interface\s+(?<if>\S+)|global)\s*$', 'IgnoreCase')
      if($m.Success){
        $n=$m.Groups['name'].Value
        if(-not $map.ContainsKey($n)){ $map[$n]=New-Object System.Collections.Generic.List[object] }
        $ifc= if($m.Groups['if'].Success){ $m.Groups['if'].Value } else { 'global' }
        [void]$map[$n].Add([PSCustomObject]@{ Interface=$ifc; Direction=$m.Groups['dir'].Value })
      }
    }
    $map
  }

  # --- вход ---
  $lines = __Enum($Cfg?.Lines)
  if($lines.Count -eq 0){
    return New-Finding 'DMZ-INSIDE' 'No lines to analyze' 'Info' $true
  }

  # --- nameif + security-level извлечение ---
  $ifMeta = @()   # [{Nameif='dmz'; Sec=0}, ...]
  $nameifs=@{}    # phys_if -> nameif
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*interface\s+(\S+)'){
      $phys=$matches[1]; $curName=$null; $curSec=$null
      for($j=$i+1;$j -lt $lines.Count -and $lines[$j] -match '^\s+';$j++){
        if($lines[$j] -match '^\s*nameif\s+(\S+)'){ $curName=$matches[1]; $nameifs[$phys]=$curName }
        elseif($lines[$j] -match '^\s*security-level\s+(\d+)\b'){ $curSec=[int]$matches[1] }
      }
      if($curName){ $ifMeta += [pscustomobject]@{ Nameif=$curName; Sec=$curSec } }
    }
  }

  # --- кандидаты интерфейсов DMZ/INSIDE ---
  $dmzIfSet = __NewSet
  foreach($n in __Enum($nameifs.Values)){ if($n -match '^(?i)(dmz|guest|partner|online|public)$'){ [void]$dmzIfSet.Add($n) } }
  foreach($m in $ifMeta){ if($m.Sec -ge 1 -and $m.Sec -le 99 -and $m.Nameif){ [void]$dmzIfSet.Add($m.Nameif) } }
  if($dmzIfSet.Count -eq 0){ [void]$dmzIfSet.Add('dmz') } # эвристика

  $insideIfSet = __NewSet
  foreach($n in __Enum($nameifs.Values)){ if($n -match '^(?i)(inside|internal|corp|intranet|lan|pci)$'){ [void]$insideIfSet.Add($n) } }
  if($insideIfSet.Count -eq 0){ [void]$insideIfSet.Add('inside') } # эвристика

  # --- карта привязок ACL ---
  $bindMap = __BindMap $Cfg

  # Если на DMZ-подобных интерфейсах нет привязанных ACL — отдельное замечание
  $dmzBound = @()
  foreach($acl in __GetIndexLines $Cfg 'access-group'){
    if($acl -match '^\s*access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)'){
      $iface=$matches[3]
      if($dmzIfSet.Contains($iface)){ $dmzBound += $acl }
    }
  }
  if($dmzIfSet.Count -gt 0 -and $dmzBound.Count -eq 0){
    $meta = if($ifMeta){ ($ifMeta | ForEach-Object { "$($_.Nameif) sec $($_.Sec)" }) } else { @() }
    return New-Finding 'DMZ-ACL-BIND' 'No ACL bound to DMZ-like interfaces' 'Info' $false $meta `
      'Bind an access-list to DMZ/online interfaces (access-group <ACL> in interface <nameif>).'
  }

  # --- ACL строки ---
  $aclLines = __GetIndexLines $Cfg 'access-list'
  if($aclLines.Count -eq 0){
    return New-Finding 'DMZ-INSIDE' 'No ACLs found for DMZ->inside analysis' 'Info' $true
  }

  $evStrict = New-Object System.Collections.Generic.List[string]  # DMZ -> INSIDE
  $evBroad  = New-Object System.Collections.Generic.List[string]  # DMZ -> ANY
  $evHints  = New-Object System.Collections.Generic.List[string]  # широкие подсети в группах

  # --- широкие подсети в группах ---
  foreach($g in __Keys($Obj?.GroupSubnets)){
    foreach($sn in __Enum($Obj.GroupSubnets[$g])){
      $parts=$sn -split '\s+'
      if($parts.Count -ge 2){
        $mask=$parts[1]
        if($mask -eq '255.0.0.0' -or $mask -eq '255.255.0.0'){
          if($g -match '(?i)dmz|guest|partner'){ [void]$evHints.Add("DMZ group $g includes broad subnet $sn") }
          if($g -match '(?i)inside|internal|corp|intranet|lan|pci'){ [void]$evHints.Add("INSIDE group $g includes broad subnet $sn") }
        }
      }
    }
  }

  foreach($ln in __Enum($aclLines)){
    $p = Parse-AclLine -Line $ln
    if(-not $p -or $p.Action -ne 'permit'){ continue }

    # аннотация привязки
    $bindTxt = '  [UNBOUND]'
    if($p.Name -and $bindMap -and $bindMap.ContainsKey($p.Name)){
      $bindTxt = '  ' + ((__Enum $bindMap[$p.Name]) | ForEach-Object { "[{0} {1}]" -f $_.Interface,$_.Direction } -join ' ')
    }

    # источник DMZ?
    $isDmzSrc =
      (($p.SrcType -in @('object','og')) -and $p.Src -and $dmzIfSet.Any({ $p.Name -match ('(?i)^{0}$' -f [regex]::Escape($_)) }) -or $dmzNameSet.Contains($p.Src)) -or
      ($p.SrcType -eq 'subnet' -and $p.Src -match '^172\.(1[6-9]|2\d|3[01])\.' -and $p.Name -and $p.Name -match '(?i)dmz') -or
      ($p.SrcType -eq 'host'   -and $p.Name -and $p.Name -match '(?i)dmz')

    # назначение INSIDE?
    if(-not (Get-Variable insideNameSet -Scope Local -ErrorAction SilentlyContinue)){
      $insideNameSet = __NewSet
      foreach($k in __Keys($Obj?.ObjectHosts)){ if($k -match '(?i)\b(inside|internal|corp|intranet|lan|pci)\b'){ $insideNameSet.Add($k) | Out-Null } }
      foreach($k in __Keys($Obj?.ObjectSubnets)){ if($k -match '(?i)\b(inside|internal|corp|intranet|lan|pci)\b'){ $insideNameSet.Add($k) | Out-Null } }
      foreach($k in __Keys($Obj?.GroupHosts)){ if($k -match '(?i)\b(inside|internal|corp|intranet|lan|pci)\b'){ $insideNameSet.Add($k) | Out-Null } }
      foreach($k in __Keys($Obj?.GroupSubnets)){ if($k -match '(?i)\b(inside|internal|corp|intranet|lan|pci)\b'){ $insideNameSet.Add($k) | Out-Null } }
    }

    $isInsideDst =
      (($p.DstType -in @('object','og')) -and $p.Dst -and $insideNameSet.Contains($p.Dst)) -or
      ($p.DstType -eq 'subnet' -and $p.Dst -and ($p.Dst -match '^\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,3}(?:\.\d{1,3}){3}$' -and (__IsRFC1918 ($p.Dst -split '\s+')[0])) ) -or
      ($p.DstType -eq 'host'   -and $p.Dst -and (__IsRFC1918 $p.Dst))

    $anyDst = ($p.DstType -eq 'any' -or ($p.DstType -eq 'subnet' -and $p.Dst -and $p.Dst -match '^0\.0\.0\.0\s+0\.0\.0\.0$'))

    if($isDmzSrc -and $isInsideDst){
      [void]$evStrict.Add($ln + $bindTxt)
    } elseif($isDmzSrc -and $anyDst){
      [void]$evBroad.Add($ln + $bindTxt + '  [DMZ -> ANY]')
    }
  }

  if($evStrict.Count -eq 0 -and $evBroad.Count -eq 0){
    return New-Finding 'DMZ-INSIDE' 'No DMZ->inside permits detected' 'Info' $true
  }

  # --- оценка широты сервисов ---
  function __IsWideService([string]$svc){
    if([string]::IsNullOrWhiteSpace($svc)){ return $true }
    if($svc -match '^\s*ip\s*$'){ return $true }
    if($svc -match '\brange\s+\d+\s+\d+\b'){ return $true }
    if($svc -match '\b(eq|lt|gt)\s+\d+\b'){ return $false }
    return $false
  }

  $sev='Medium'
  $outsideIn=$false; $insideIn=$false
  foreach($l in __Enum($evStrict + $evBroad)){
    if($l -match '\[outside in\]'){ $outsideIn=$true }
    if($l -match '\[inside in\]'){  $insideIn=$true }
  }
  if($evStrict.Count -gt 0){
    foreach($ln2 in __Enum($evStrict)){
      $p2 = Parse-AclLine -Line $ln2
      if($p2 -and (__IsWideService $p2.Service)){ $sev='High'; break }
    }
    if($sev -ne 'High' -and ($outsideIn -or $insideIn)){ $sev='High' }
  } elseif($evBroad.Count -gt 0){
    $sev='High'
  }

  # --- evidence ---
  $evid = New-Object System.Collections.Generic.List[string]
  if($evStrict.Count -gt 0){ [void]$evid.Add('[DMZ -> INSIDE]'); foreach($x in __Enum($evStrict)){ [void]$evid.Add([string]$x) } }
  if($evBroad.Count  -gt 0){ [void]$evid.Add('[DMZ -> ANY]');    foreach($x in __Enum($evBroad)){  [void]$evid.Add([string]$x) } }

  if($evid.Count -gt 0){
    New-Finding 'DMZ-INSIDE' 'DMZ to inside access permitted (direction-aware)' $sev $false ($evid | Select-Object -Unique) `
      'Minimize DMZ->inside access; keep least privilege, specific hosts/ports; prefer flow via proxies or outside.'
  } else {
    New-Finding 'DMZ-INSIDE' 'No DMZ->inside permits detected' 'Info' $true
  }
}

function Check-ServerEgressNAT {
  param($Cfg,$Obj)

  # --- helpers (null-safe, PS5.1-compatible) ---
  function _E($x){ if($null -eq $x){ @() } elseif($x -is [array]){ @($x) } else { @($x) } }
  function _Idx($cfg,$k){ if($cfg -and $cfg.Index -and $cfg.Index.Contains($k)){ @($cfg.Index[$k]) } else { @() } }
  function _Keys($h){ if($h -and $h.PSObject.Properties['Keys']){ @($h.Keys) } else { @() } }
  function _IsRFC1918([string]$ip){
    if([string]::IsNullOrWhiteSpace($ip)){ return $false }
    if($ip -match '^10\.'){ return $true }
    if($ip -match '^192\.168\.'){ return $true }
    if($ip -match '^172\.(1[6-9]|2\d|3[0-1])\.'){ return $true }
    $false
  }
  function _NameFromRef([string]$ref){
    if($ref -match '^(object|object-group)\s+(\S+)$'){ return $matches[2] }
    return $ref
  }

  $lines = @(); if($Cfg -and $Cfg.Lines){ $lines = @($Cfg.Lines) }
  if($lines.Count -eq 0){ return New-Finding 'SRV-NAT' 'No lines to analyze' 'Info' $true }

  # --- собрать "серверные" имена (эвристика) ---
  $serverNames = New-Object System.Collections.Generic.HashSet[string]
  $nameHint = '(?i)(server|srv|app|web|www|db|sql|rdp|ts|jump|bastion|proxy|gw|dmz)'

  foreach($k in _Keys($Obj.ObjectHosts)){ if($k -match $nameHint){ [void]$serverNames.Add($k) } }
  foreach($k in _Keys($Obj.ObjectSubnets)){ if($k -match $nameHint){ [void]$serverNames.Add($k) } }
  foreach($k in _Keys($Obj.GroupHosts)){ if($k -match $nameHint){ [void]$serverNames.Add($k) } }
  foreach($k in _Keys($Obj.GroupSubnets)){ if($k -match $nameHint){ [void]$serverNames.Add($k) } }

  if($serverNames.Count -eq 0 -and $Obj -and $Obj.GroupHosts){
    foreach($g in _Keys($Obj.GroupHosts)){
      if($g -match '(?i)(dmz|online|partner|inside|internal|corp|lan)'){
        foreach($h in _E($Obj.GroupHosts[$g])){ if($h){ [void]$serverNames.Add($h) } }
      }
    }
  }

  # --- парс NAT к outside (object-NAT, twice/sectional, policy, identity, route-lookup) ---
  $toOutsideNat  = New-Object System.Collections.Generic.List[string]
  $natSrcNames   = New-Object System.Collections.Generic.HashSet[string]
  $identityNat   = New-Object System.Collections.Generic.List[string]
  $policyNat     = New-Object System.Collections.Generic.List[string]
  $routeLookup   = New-Object System.Collections.Generic.List[string]

  $curObj = $null
  for($i=0; $i -lt $lines.Count; $i++){
    $ln = $lines[$i]

    if($ln -match '^\s*object\s+network\s+(\S+)'){ $curObj=$matches[1]; continue }

    if($curObj){
      if($ln -match '^\s*nat\s*\((?<src>\S+)\s*,\s*(?<dst>\S+)\)\s*(?<where>after-auto|manual)?\s*(?<type>dynamic|static|identity)\s+(?<what>interface|\S+)(?<tail>.*)$'){
        if($matches['dst'] -match '^(?i)outside'){
          $rec = "object network $curObj -> " + $ln.Trim()
          [void]$toOutsideNat.Add($rec)
          [void]$natSrcNames.Add($curObj)
          if($matches['type'] -match 'identity'){ [void]$identityNat.Add($rec) }
          if($matches['tail'] -match '\broute-lookup\b'){ [void]$routeLookup.Add($rec) }
        }
      }
      if($ln -notmatch '^\s+') { $curObj=$null }
      continue
    }

    if($ln -match '^\s*nat\s*\((?<srcif>\S+)\s*,\s*(?<dstif>\S+)\)\s*(?<where>after-auto|manual)?\s+source\s+(?<stype>dynamic|static|identity)\s+(?<sobj>(object-group|object)\s+\S+|\S+)(?<rest>.*)$'){
      if($matches['dstif'] -match '^(?i)outside'){
        $rec = $ln.Trim()
        [void]$toOutsideNat.Add($rec)
        [void]$natSrcNames.Add( (_NameFromRef $matches['sobj']) )
        if($matches['stype'] -match 'identity'){ [void]$identityNat.Add($rec) }
        if($matches['rest'] -match '\bdestination\s+(?<dtype>static|dynamic)\s+(?<dobj>(object-group|object)\s+\S+|\S+)\b'){
          [void]$policyNat.Add($rec)
        }
        if($matches['rest'] -match '\broute-lookup\b'){ [void]$routeLookup.Add($rec) }
      }
    }
  }

  if($toOutsideNat.Count -eq 0){
    return New-Finding 'SRV-NAT' 'No server egress NAT to outside detected (heuristic)' 'Info' $true
  }

  # --- ACL для исхода "к any"/широкие ---
  $aclLines = _Idx $Cfg 'access-list'
  $egressWide = New-Object System.Collections.Generic.List[string]
  $egressPortsWide = New-Object System.Collections.Generic.List[string]

  foreach($ln in $aclLines){
    if($ln -match '^\s*access-list\s+(\S+)\s+extended\s+permit\s+(?<proto>\S+)\s+(?<srcType>object-group|object|host|any|\S+)\s+(?<src>\S+)\s+(?<dstType>any|object-group|object|host|\S+)\s+(?<dst>\S+)(?<tail>.*)$'){
      $srcType=$matches['srcType']; $src=$matches['src']; $dstType=$matches['dstType']; $dst=$matches['dst']; $proto=$matches['proto']; $tail=$matches['tail']
      $srcName = _NameFromRef(("$srcType $src").Trim())
      $isNatSrc = ($natSrcNames.Contains($srcName) -or $serverNames.Contains($srcName))
      if(-not $isNatSrc){ continue }

      $isAnyDst = ($dstType -eq 'any' -or $dst -match '^0\.0\.0\.0(\s+0\.0\.0\.0)?$')
      $dstIsPublic = $false
      if($dst -match '^\d{1,3}(\.\d{1,3}){3}$'){ $dstIsPublic = -not (_IsRFC1918 $dst) }

      $hasPort = ($tail -match '\b(eq|lt|gt|range)\s+\d+')
      if($isAnyDst -and -not $hasPort){
        [void]$egressWide.Add($ln)
      } elseif($isAnyDst -and $proto -match '^(?i)ip$'){
        [void]$egressWide.Add($ln)
      } elseif($isAnyDst -and $proto -match '^(?i)tcp|udp$' -and -not $hasPort){
        [void]$egressWide.Add($ln)
      } elseif($isAnyDst -and $hasPort){
        [void]$egressPortsWide.Add($ln)
      } elseif($dstIsPublic -and -not $hasPort -and $proto -match '^(?i)ip|tcp|udp$'){
        [void]$egressWide.Add($ln)
      }
    }
  }

  # --- вывод ---
  $ev = New-Object System.Collections.Generic.List[string]
  [void]$ev.Add('[NAT to outside]')
  foreach($n in ($toOutsideNat | Select-Object -First 30)){ [void]$ev.Add($n) }

  if($identityNat.Count -gt 0){
    [void]$ev.Add('[Identity NAT to outside]')
    foreach($n in ($identityNat | Select-Object -First 10)){ [void]$ev.Add($n) }
  }
  if($routeLookup.Count -gt 0){
    [void]$ev.Add('[route-lookup present]')
    foreach($n in ($routeLookup | Select-Object -First 10)){ [void]$ev.Add($n) }
  }
  if($policyNat.Count -gt 0){
    [void]$ev.Add('[Policy NAT (destination match)]')
    foreach($n in ($policyNat | Select-Object -First 10)){ [void]$ev.Add($n) }
  }

  $sev = 'Medium'
  $rec = 'Ensure egress ACL restricts destinations/ports; avoid blanket PAT+permit to any; prefer proxy/egress filtering.'

  if($egressWide.Count -gt 0){
    [void]$ev.Add('[ACL allowing NATed servers -> ANY (wide)]')
    foreach($a in ($egressWide | Select-Object -First 20)){ [void]$ev.Add($a) }
    $sev = 'High'
  }
  if($egressPortsWide.Count -gt 0){
    [void]$ev.Add('[ACL allowing NATed servers -> ANY (ports limited)]')
    foreach($a in ($egressPortsWide | Select-Object -First 20)){ [void]$ev.Add($a) }
    if($sev -ne 'High'){ $sev = 'Medium' }
  }
  if($identityNat.Count -gt 0 -and $sev -ne 'High'){
    $sev = 'Medium'
    $rec += ' Avoid identity NAT to outside unless strictly required.'
  }

  New-Finding 'SRV-NAT' 'Server egress via NAT to outside (object/twice/policy, identity detection)' $sev $false $ev $rec
}

# ===================== Registry =====================

$CheckMap = [ordered]@{
  ACLAnyAny                 = { param($cfg,$obj) Check-ACLAnyAny        -Cfg $cfg }
  ACLDangerousServices      = { param($cfg,$obj) Check-DangerousServicesAnyAny -Cfg $cfg }
  ACLForServers             = { param($cfg,$obj) Check-ACLForServers    -Cfg $cfg -Obj $obj }
  ACLBinding                = { param($cfg,$obj) Check-AccessGroupBinding -Cfg $cfg }
  ACLRedundancy             = { param($cfg,$obj) Check-ACLRedundancy    -Cfg $cfg }
  ACLv6AnyAny               = { param($cfg,$obj) Check-IPv6AnyAny       -Cfg $cfg }

  Telnet                    = { param($cfg,$obj) Check-Telnet           -Cfg $cfg }
  SSH                       = { param($cfg,$obj) Check-SSH              -Cfg $cfg }
  HTTPMgmt                  = { param($cfg,$obj) Check-HTTPMgmt         -Cfg $cfg }

  PlainPasswords            = { param($cfg,$obj) Check-PlainPasswords   -Cfg $cfg }
  AAA                       = { param($cfg,$obj) Check-AAA              -Cfg $cfg }
  AAAUsage                  = { param($cfg,$obj) Check-AAA-Use          -Cfg $cfg }
  AAAResilience             = { param($cfg,$obj) Check-AAA-Resilience   -Cfg $cfg }

  SNMP                      = { param($cfg,$obj) Check-SNMP             -Cfg $cfg }
  SNMPv3Strength            = { param($cfg,$obj) Check-SNMPv3-Strength  -Cfg $cfg }

  Logging                   = { param($cfg,$obj) Check-Logging          -Cfg $cfg }
  LoggingDrops              = { param($cfg,$obj) Check-Logging-Drops    -Cfg $cfg }

  ThreatDetection           = { param($cfg,$obj) Check-ThreatDetection  -Cfg $cfg }
  ICMP                      = { param($cfg,$obj) Check-ICMP             -Cfg $cfg }
  ICMPCtrlOutsideACL        = { param($cfg,$obj) Check-ICMP-ACL-Outside -Cfg $cfg }

  VPN                       = { param($cfg,$obj) Check-VPN              -Cfg $cfg }
  WeakCrypto                = { param($cfg,$obj) Check-WeakCrypto       -Cfg $cfg }
  IpsecTransformWeak        = { param($cfg,$obj) Check-IpsecTransformWeak -Cfg $cfg }
  WebvpnCiphers             = { param($cfg,$obj) Check-WebVPNCiphers    -Cfg $cfg }
  CACRL                     = { param($cfg,$obj) Check-CA-CRL           -Cfg $cfg }

  NATLoose                  = { param($cfg,$obj) Check-NATLoose         -Cfg $cfg }
  NatPartnerRisk            = { param($cfg,$obj) Check-NAT-Partner-Risky -Cfg $cfg }
  NatBroadObjects           = { param($cfg,$obj) Check-NAT-BroadObjects -Cfg $cfg }

  InspectLegacy             = { param($cfg,$obj) Check-PolicyInspectLegacy -Cfg $cfg }
  InspectLoosened           = { param($cfg,$obj) Check-Inspect-Loosened -Cfg $cfg }
  MPFBypass                 = { param($cfg,$obj) Check-MPF-Bypass       -Cfg $cfg }

  RESTAPI                   = { param($cfg,$obj) Check-RESTAPI          -Cfg $cfg }

  AnyConnectSplitTunnel     = { param($cfg,$obj) Check-AnyConnectSplitTunnel -Cfg $cfg }
  AnyConnectProtocols       = { param($cfg,$obj) Check-AnyConnectProtocols   -Cfg $cfg }
  AnyConnectCiphers         = { param($cfg,$obj) Check-AnyConnectCiphersGP   -Cfg $cfg }
  SSLVersions               = { param($cfg,$obj) Check-SSLVersions           -Cfg $cfg }
  SSLDHGroup                = { param($cfg,$obj) Check-SSLDHGroup            -Cfg $cfg }
  DynFilterConfig           = { param($cfg,$obj) Check-DynFilterConfig       -Cfg $cfg }

  DTLSVersion               = { param($cfg,$obj) Check-DTLSVersion            -Cfg $cfg }
  DTLSCiphers               = { param($cfg,$obj) Check-DTLSCiphersWeak        -Cfg $cfg }
  DTLSPriority              = { param($cfg,$obj) Check-DTLSCipherPriority     -Cfg $cfg }
  SSLKeyExchange            = { param($cfg,$obj) Check-SSLKeyExchange         -Cfg $cfg }
  DTLSCompression           = { param($cfg,$obj) Check-DTLSCompression        -Cfg $cfg }
  WebvpnTimeouts            = { param($cfg,$obj) Check-WebvpnTimeouts         -Cfg $cfg }
  LoggingDTLS               = { param($cfg,$obj) Check-LoggingDTLS            -Cfg $cfg }
  ACProfileCipher           = { param($cfg,$obj) Check-AnyConnectProfileCipher -Cfg $cfg }

  CertTrustpoint             = { param($cfg,$obj) Check-CertTrustpoint     -Cfg $cfg }
  AAAAccounting              = { param($cfg,$obj) Check-AAA-Accounting     -Cfg $cfg }
  NTP                        = { param($cfg,$obj) Check-NTP                 -Cfg $cfg }
  VPNFilterDAP               = { param($cfg,$obj) Check-VPNFilterDAP        -Cfg $cfg }
  ACLTimeRange               = { param($cfg,$obj) Check-ACLTimeRange        -Cfg $cfg }
  ProxyARP                   = { param($cfg,$obj) Check-ProxyARP            -Cfg $cfg }
  FailoverHygiene            = { param($cfg,$obj) Check-FailoverHygiene     -Cfg $cfg }
  SameSecurity               = { param($cfg,$obj) Check-SameSecurity        -Cfg $cfg }
  ManagementAccess           = { param($cfg,$obj) Check-ManagementAccess    -Cfg $cfg }

  DMZtoInsideDeep = { param($cfg,$obj) Check-DMZtoInsideDeep -Cfg $cfg -Obj $obj }

  ServerEgressNAT = { param($cfg,$obj) Check-ServerEgressNAT -Cfg $cfg -Obj $obj }
}

# ===================== Menu =====================

function Show-Menu {
  param($Map)
  Write-Host "Select checks (comma) or 'all':" -ForegroundColor Cyan
  $i=1; $keys=@()
  foreach($k in $Map.Keys){ Write-Host ("{0}. {1}" -f $i,$k); $keys += $k; $i++ }
  Write-Host ""
  $sel = Read-Host "Input"
  if([string]::IsNullOrWhiteSpace($sel)){ return @() }
  if($sel -match '^\s*all\s*$'){ return $Map.Keys }
  $idx = $sel -split '[,\s]+' | Where-Object { $_ }
  $chosen = @()
  foreach($x in $idx){
    if($x -match '^\d+$'){ $n=[int]$x; if($n -ge 1 -and $n -le $keys.Count){ $chosen += $keys[$n-1] } }
    elseif($Map.Contains($x)){ $chosen += $x }
  }
  $chosen | Select-Object -Unique
}

# ===================== Main =====================

try {
  $cfg = Read-AsaConfig -Path $Path
  $obj = Build-AsaObjects -Cfg $cfg

  $toRun = @()
  if($All){ $toRun = $CheckMap.Keys }
  elseif($Checks){
    $toRun = $Checks | Where-Object { $CheckMap.Contains($_) }
    if(-not $toRun -or $toRun.Count -eq 0){
      Write-Host ("Unknown checks. Available: {0}" -f ($CheckMap.Keys -join ', ')) -ForegroundColor Yellow
      exit 1
    }
  } else {
    $toRun = Show-Menu -Map $CheckMap
    if(-not $toRun -or $toRun.Count -eq 0){ Write-Host "Nothing selected." -ForegroundColor Yellow; exit 0 }
  }

  $findings = @()
  foreach($name in $toRun){
    $fn = $CheckMap[$name]
    $findings += & $fn $cfg $obj
  }

  Write-AsaReport -Findings $findings -OutJson $OutJson -Chart:$Chart
}
catch {
  Write-Error "Audit error: $_"
}