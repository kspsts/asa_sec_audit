<# 
  asa_segments.ps1  — Inter-Segment Flow Analyzer for Cisco ASA
  PowerShell 5.1 compatible, ASCII-safe
  v0.1.1
#>

[CmdletBinding()]
param(
  [string]$Path = "asa_config.txt",
  [switch]$Html,
  [string]$HtmlPath = "asa_segments_report.html",
  [switch]$Csv,
  [string]$CsvPath = "asa_segments_matrix.csv",
  [switch]$ShowUnbound      # also list ACL lines from ACLs that are not bound
)

# ---------------- Utils ----------------
function _E($x){ if($null -eq $x){ @() } elseif($x -is [array]){ @($x) } else { ,$x } }
function _NewSet { [System.Collections.Generic.HashSet[string]]::new() }
function _IsRFC1918([string]$ip){
  if([string]::IsNullOrWhiteSpace($ip)){ return $false }
  if($ip -match '^10\.'){ return $true }
  if($ip -match '^192\.168\.'){ return $true }
  if($ip -match '^172\.(1[6-9]|2\d|3[0-1])\.'){ return $true }
  $false
}
function Read-AsaConfig {
  param([string]$Path)
  $raw   = Get-Content -Raw -Encoding UTF8 -ErrorAction Stop $Path
  $lines = $raw -split "`r?`n"
  $idx   = [ordered]@{}
  foreach($pfx in @(
    'access-list','access-group','object ','object-group','interface ',
    'nameif','security-level','ssh ','http ','icmp ','nat ','crypto ',
    'webvpn'
  )){
    $idx[$pfx] = $lines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($pfx)) }
  }
  [PSCustomObject]@{ Raw=$raw; Lines=$lines; Index=$idx }
}
function Get-IndexLines { param($Cfg,$Key)
  if($Cfg -and $Cfg.Index -and $Cfg.Index.Contains($Key)){ @($Cfg.Index[$Key]) } else { @() }
}

# ---------------- Parse interfaces/nameif ----------------
function Get-InterfaceMeta {
  param($Cfg)
  $meta = @()
  $lines = $Cfg.Lines
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*interface\s+(\S+)'){
      $phys = $matches[1]
      $nameif = $null; $sec = $null
      for($j=$i+1; $j -lt $lines.Count -and $lines[$j] -match '^\s+'; $j++){
        if($lines[$j] -match '^\s*nameif\s+(\S+)'){ $nameif=$matches[1] }
        elseif($lines[$j] -match '^\s*security-level\s+(\d+)\b'){ $sec=[int]$matches[1] }
      }
      if($nameif){ $meta += [pscustomobject]@{ Phys=$phys; Nameif=$nameif; Sec=$sec } }
    }
  }
  $meta
}

# ---------------- Build network objects/groups (names only) ----------------
function Build-AsaObjects {
  param($Cfg)
  $lines = $Cfg.Lines
  $objectNames = _NewSet
  $groupNames  = _NewSet
  for($i=0;$i -lt $lines.Count;$i++){
    if($lines[$i] -match '^\s*object\s+network\s+(\S+)'){ [void]$objectNames.Add($matches[1]) }
    if($lines[$i] -match '^\s*object-group\s+network\s+(\S+)'){ [void]$groupNames.Add($matches[1]) }
  }
  [PSCustomObject]@{ ObjectNames=$objectNames; GroupNames=$groupNames }
}

# ---------------- ACL binding map ----------------
function Get-AclBindings {
  param($Cfg)
  $map=@{}
  foreach($g in (Get-IndexLines $Cfg 'access-group')){
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

# ---------------- ACL mini parser ----------------
function Parse-AclLine {
  param([string]$Line)
  if($Line -notmatch '^\s*access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$'){ return $null }
  $name=$matches[1]; $action=$matches[2]; $proto=$matches[3]; $rest=$matches[4].Trim()
  $t = if([string]::IsNullOrWhiteSpace($rest)){ @() } else { $rest -split '\s+' }
  $idx=0
  $srcType='';$srcVal=''
  if($idx -lt $t.Count){
    switch ($t[$idx]) {
      'any' { $srcType='any'; $srcVal='any'; $idx++ }
      'host' { if($idx+1 -lt $t.Count){ $srcType='host'; $srcVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
      'object' { if($idx+1 -lt $t.Count){ $srcType='object'; $srcVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
      'object-group' { if($idx+1 -lt $t.Count){ $srcType='og'; $srcVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
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
      'host' { if($idx+1 -lt $t.Count){ $dstType='host'; $dstVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
      'object' { if($idx+1 -lt $t.Count){ $dstType='object'; $dstVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
      'object-group' { if($idx+1 -lt $t.Count){ $dstType='og'; $dstVal=$t[$idx+1]; $idx+=2 } else { $idx=$t.Count } }
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

# ---------------- Segment inference ----------------
$KnownSegments = @('DMZ','INET','LAN','PARTNER','WAN','WIFI','UNKNOWN')

function Map-NameToSegment([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ return 'UNKNOWN' }
  $n = $name.ToLowerInvariant()
  if($n -match '\b(dmz|online|public)\b'){ return 'DMZ' }
  if($n -match '\b(outside|inet|internet)\b'){ return 'INET' }
  if($n -match '\b(inside|lan|internal|corp|office|intranet|pci)\b'){ return 'LAN' }
  if($n -match '\b(partner|b2b)\b'){ return 'PARTNER' }
  if($n -match '\b(wan|mpls|isp|uplink)\b'){ return 'WAN' }
  if($n -match '\b(wifi|guest|wlan)\b'){ return 'WIFI' }
  'UNKNOWN'
}

function Build-InterfaceSegmentMap {
  param($IfMeta)
  $map=@{}
  foreach($i in $IfMeta){
    $seg = Map-NameToSegment $i.Nameif
    if($seg -eq 'UNKNOWN'){
      if($i.Sec -le 20){ $seg='INET' }
      elseif($i.Sec -le 70){ $seg='DMZ' }
      else{ $seg='LAN' }
    }
    $map[$i.Nameif] = $seg
  }
  $map
}

function Map-ObjOrTokenToSegment {
  param(
    [string]$type,  # any|host|subnet|object|og|unknown
    [string]$val,
    $ObjNames,
    $GrpNames
  )
  switch($type){
    'any'    { return 'INET' }
    'host'   { if(_IsRFC1918 $val){ return 'LAN' } else { return 'INET' } }
    'subnet' {
      $ip = ($val -split '\s+')[0]
      if(_IsRFC1918 $ip){ return 'LAN' } else { return 'INET' }
    }
    'object' { return (Map-NameToSegment $val) }
    'og'     { return (Map-NameToSegment $val) }
    default  { return (Map-NameToSegment $val) }
  }
}

# ---------------- HTML output (optional) ----------------
function Out-MatrixHtml {
  param($Matrix,$Samples,$HtmlPath)
  $segs = $Matrix.Keys | Sort-Object
  $head = "<!doctype html><html><head><meta charset='utf-8'><title>ASA Segment Matrix</title>
  <style>
  body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}
  table{border-collapse:collapse}
  th,td{border:1px solid #1f2937;padding:6px 10px}
  th{background:#111827}
  .z{color:#9ca3af}
  </style></head><body><h2>Inter-Segment Matrix</h2>"
  $html = New-Object System.Text.StringBuilder
  [void]$html.Append($head)
  [void]$html.Append("<table><tr><th>From \ To</th>")
  foreach($dst in $segs){ [void]$html.Append("<th>$dst</th>") }
  [void]$html.Append("</tr>")
  foreach($src in $segs){
    [void]$html.Append("<tr><th>$src</th>")
    foreach($dst in $segs){
      $cnt = if($Matrix[$src].ContainsKey($dst)){ $Matrix[$src][$dst] } else { 0 }
      $ex  = if($Samples.ContainsKey("$src->$dst")){ $Samples["$src->$dst"][0] } else { $null }
      $cell = if($cnt -gt 0){ "$cnt" } else { "<span class='z'>0</span>" }
      if($ex){
        $enc = [System.Net.WebUtility]::HtmlEncode($ex)
        $cell = "$cell<br/><span class='z' style='font-size:11px'>ex: $enc</span>"
      }
      [void]$html.Append("<td>$cell</td>")
    }
    [void]$html.Append("</tr>")
  }
  [void]$html.Append("</table>")
  [void]$html.Append("<p style='color:#9ca3af'>Counts = number of permit rules seen for that direction (bound ACLs only). Examples are first matching ACL lines.</p>")
  [void]$html.Append("</body></html>")
  Set-Content -Encoding UTF8 -Path $HtmlPath -Value $html.ToString()
  Write-Host "HTML saved: $HtmlPath" -ForegroundColor Cyan
}

# ---------------- Main analysis ----------------
try{
  $cfg     = Read-AsaConfig -Path $Path
  $ifMeta  = Get-InterfaceMeta -Cfg $cfg
  $if2seg  = Build-InterfaceSegmentMap -IfMeta $ifMeta
  $objs    = Build-AsaObjects -Cfg $cfg
  $bindMap = Get-AclBindings -Cfg $cfg

  $acls = Get-IndexLines $cfg 'access-list'
  $matrix = @{}       # matrix[src][dst] = count
  $samples = @{}      # samples["src->dst"] = [list of examples]
  foreach($s in $KnownSegments){ $matrix[$s] = @{} }

  $unbound = @()
  foreach($ln in $acls){
    $p = Parse-AclLine -Line $ln
    if(-not $p -or $p.Action -ne 'permit'){ continue }
    $aclName = $p.Name
    $bindings = if($bindMap.ContainsKey($aclName)){ @($bindMap[$aclName]) } else { @() }
    if($bindings.Count -eq 0){ if($ShowUnbound){ $unbound += $ln }; continue }

    foreach($b in $bindings){
      $iface = $b.Interface
      $dir   = $b.Direction  # in|out
      $ifaceSeg = if($if2seg.ContainsKey($iface)){ $if2seg[$iface] } else { Map-NameToSegment $iface }

      # Base segments by tokens
      $srcSegTok = Map-ObjOrTokenToSegment -type $p.SrcType -val $p.Src -ObjNames $objs.ObjectNames -GrpNames $objs.GroupNames
      $dstSegTok = Map-ObjOrTokenToSegment -type $p.DstType -val $p.Dst -ObjNames $objs.ObjectNames -GrpNames $objs.GroupNames

      # Direction-aware override
      if($dir -eq 'in'){ $srcSeg = $ifaceSeg; $dstSeg = $dstSegTok }
      else { $srcSeg = $srcSegTok; $dstSeg = $ifaceSeg }

      if($srcSeg -eq 'UNKNOWN'){ $srcSeg = $srcSegTok }
      if($dstSeg -eq 'UNKNOWN'){ $dstSeg = $dstSegTok }
      if(-not ($KnownSegments -contains $srcSeg)){ $srcSeg = 'UNKNOWN' }
      if(-not ($KnownSegments -contains $dstSeg)){ $dstSeg = 'UNKNOWN' }

      if(-not $matrix[$srcSeg].ContainsKey($dstSeg)){ $matrix[$srcSeg][$dstSeg] = 0 }
      $matrix[$srcSeg][$dstSeg]++

      $key = "$srcSeg->$dstSeg"
      if(-not $samples.ContainsKey($key)){ $samples[$key] = New-Object System.Collections.Generic.List[string] }
      if($samples[$key].Count -lt 5){
        $annot = "$ln [bind: $($iface)/$($dir)]"
        [void]$samples[$key].Add($annot)
      }
    }
  }

  # Console table
  $segs = $KnownSegments
  Write-Host "Inter-Segment Matrix (permit rules, bound ACLs only)" -ForegroundColor Cyan
  $row = "{0,-8}" -f "From\To"
  foreach($d in $segs){ $row += ("{0,8}" -f $d) }
  Write-Host $row
  foreach($s in $segs){
    $line = "{0,-8}" -f $s
    foreach($d in $segs){
      $cnt = if($matrix[$s].ContainsKey($d)){ $matrix[$s][$d] } else { 0 }
      $line += ("{0,8}" -f $cnt)
    }
    Write-Host $line
  }

  # CSV
  if($Csv){
    $rows=@()
    foreach($s in $segs){
      foreach($d in $segs){
        $cnt = if($matrix[$s].ContainsKey($d)){ $matrix[$s][$d] } else { 0 }
        $ex  = if($samples.ContainsKey("$s->$d")){ $samples["$s->$d"][0] } else { $null }
        $rows += [pscustomobject]@{ From=$s; To=$d; Count=$cnt; Example=$ex }
      }
    }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
    Write-Host "CSV saved: $CsvPath" -ForegroundColor Cyan
  }

  # HTML
  if($Html){
    Out-MatrixHtml -Matrix $matrix -Samples $samples -HtmlPath $HtmlPath
  }

  # Unbound, if requested
  if($ShowUnbound -and $unbound.Count -gt 0){
    Write-Host "`nUnbound ACL lines that look segment-relevant (not counted):" -ForegroundColor Yellow
    $unbound | Select-Object -First 40 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
  }
}
catch{
  Write-Error "Segment analysis error: $($_.Exception.Message)"
}