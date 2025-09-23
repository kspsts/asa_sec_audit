# ASA Secure Config Audit (PS 5.1 compatible, ASCII-safe)
# Version: 0.2.1

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
  $servers = Get-AllServerIPs -Obj $Obj
  if(-not $servers){ return New-Finding 'SRV-ACL' 'Servers ACL check (objects/groups)' 'Info' $true }

  $aclLines = @()
  if($Cfg.Index.Contains('access-list')){ $aclLines = $Cfg.Index['access-list'] }

  $ev = New-Object System.Collections.Generic.List[string]

  foreach($ip in $servers){
    $esc = [regex]::Escape($ip)
    $lines1 = @($aclLines | Where-Object { ($_ -match '\bpermit\b') -and ($_ -match ("\b$esc\b")) -and (($_ -match '\bany\b') -or ($_ -match '\bany6\b') -or ($_ -match '\b0\.0\.0\.0\s+0\.0\.0\.0\b')) })
    foreach($l in $lines1){ if($null -ne $l){ [void]$ev.Add([string]$l) } }

    foreach($grp in $Obj.GroupHosts.Keys){
      if($Obj.GroupHosts[$grp].Contains($ip)){
        $grpEsc = [regex]::Escape($grp)
        $lines2 = @($aclLines | Where-Object { ($_ -match '\bpermit\b') -and ($_ -match ("\bobject-group\s+$grpEsc\b")) -and (($_ -match '\bany\b') -or ($_ -match '\bany6\b') -or ($_ -match '\b0\.0\.0\.0\s+0\.0\.0\.0\b')) })
        foreach($l in $lines2){ if($null -ne $l){ [void]$ev.Add([string]$l) } }
      }
    }
  }

  if($ev.Count -gt 0){
    New-Finding 'SRV-ACL' 'Servers reachable from ANY (ip/group)' 'High' $false ($ev | Select-Object -Unique) 'Limit sources to trusted ranges.'
  } else {
    New-Finding 'SRV-ACL' 'No server ANY exposure found' 'Info' $true
  }
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

function Check-VPN { param($Cfg)
  $ikev1pol = @(); if($Cfg.Index.Contains('crypto ikev1 policy')){ $ikev1pol = $Cfg.Index['crypto ikev1 policy'] }
  $ikev2pol = @(); if($Cfg.Index.Contains('crypto ikev2 policy')){ $ikev2pol = $Cfg.Index['crypto ikev2 policy'] }
  $hasCryptoMap = ($Cfg.Lines | Where-Object { $_ -match '^\s*crypto\s+map\s+\S+\s+\d+\s+' -or $_ -match '^\s*crypto\s+map\s+\S+\s+interface\s+\S+' })
  $hasWebvpn = ($Cfg.Lines | Where-Object { $_ -match '^\s*webvpn\b' })

  if(($ikev1pol.Count -eq 0) -and ($ikev2pol.Count -eq 0) -and -not $hasCryptoMap -and -not $hasWebvpn){
    return New-Finding 'VPN-IKE' 'No VPN/IKE found' 'Info' $true
  }
  if($ikev1pol.Count -gt 0 -and $ikev2pol.Count -eq 0){ return New-Finding 'VPN-IKE' 'IKEv1 only' 'Medium' $false $ikev1pol 'Migrate to IKEv2.' }
  if($ikev2pol.Count -gt 0 -and $ikev1pol.Count -gt 0){ return New-Finding 'VPN-IKE' 'Both IKEv1 and IKEv2' 'Low' $false ($ikev1pol+$ikev2pol) 'Prefer IKEv2 only.' }
  if($hasCryptoMap -or $hasWebvpn){
    if($ikev2pol.Count -eq 0){ return New-Finding 'VPN-IKE' 'VPN present (no explicit ikev2 policies found)' 'Low' $false (@($hasCryptoMap)+@($hasWebvpn)) 'Define IKEv2 policies and prefer them.' }
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

function Check-WebVPNCiphers { param($Cfg)
  $w = $Cfg.Lines | Where-Object { $_ -match '^\s*webvpn\b' -or $_ -match '^\s*ssl\s+encryption\s+' }
  $weak = $Cfg.Lines | Where-Object { $_ -match '^\s*ssl\s+encryption\s+rc4-md5\b' -or $_ -match '\b3des\b' -or $_ -match '\bmd5\b' -or $_ -match '\bsha1\b' }
  if($weak){ New-Finding 'WEBVPN-CIPHERS' 'Weak SSL cipher suite' 'High' $false ($w+$weak) 'Use TLS1.2/1.3 with AES-GCM.' } else { New-Finding 'WEBVPN-CIPHERS' 'SSL ciphers look ok' 'Info' $true $w }
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