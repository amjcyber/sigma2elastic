$rulePath = "./sigma/rules/windows"
$rules = Get-ChildItem -Path $rulePath -Recurse | where {! $_.PSIsContainer }
$parser='./elastic-agent-parser.yml'
$sigmaSource='./sigma'
$output='./output-test'
$backend='es-qs'
$testLog = Test-Path './sigma2elastic.log'
if ($testLog -eq $true) { Remove-Item ./sigma2elastic.log}

foreach ($rule in $rules){

    $queryNoRegex = python3 ./sigma/tools/sigmac -t $backend -c $parser --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option keyword_whitelist="winlog.channel,winlog.event_id" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image" --backend-option keyword_base_fields="*" $rule.FullName

    if ($queryNoRegex -eq $null) { 
        # Log fails
        Write-Host "Problem translating "$rule.Name""
        Add-Content -Path ./sigma2elastic.log -Value "`nProblem translating "$rule.Name""
    }

    else {

        $query = python3 ./sigma/tools/sigmac -t $backend -c $parser --backend-option keyword_base_fields="*" --backend-option analyzed_sub_field_name=".text" --backend-option keyword_whitelist="winlog.channel,winlog.event_id" --backend-option case_insensitive_whitelist="*" --backend-option analyzed_sub_fields="TargetUserName, SourceUserName, TargetHostName, CommandLine, ProcessName, ParentProcessName, ParentImage, Image" --backend-option keyword_base_fields="*" $rule.FullName
        
        $ruleInfo = Get-Content $rule | ConvertFrom-Yaml

        if ($ruleInfo.level -eq "low") { $risk = 21 }
        if ($ruleInfo.level -eq "medium") { $risk = 47 }
        if ($ruleInfo.level -eq "high") { $risk = 73 }
        if ($ruleInfo.level -eq "critical") { $risk = 99 }

        $finalRule = @(

            [pscustomobject]@{
                id = $ruleinfo.id
                created_by = $ruleInfo.author
                name = $ruleInfo.title;
                tags = $ruleInfo.tags
                interval = "5m"
                description = $ruleInfo.description
                risk_score = $risk
                enabled = $true
                severity = $ruleInfo.level
                false_positives = $ruleInfo.falsepositives
                from = "now-720s"
                type = "query"
                language = "lucene"
                index = ("winlogbeat-*","logs-*")
                query = $query
                rule_id = $ruleinfo.id
                timestamp_override = "event.ingested"
                references = $ruleInfo.references
                note = "**Detection Rule without Regex for better understanding. Be careful, this way is case sensitive:**"+'`'+"$queryNoRegex"+'`'
            }
        )

        $ruleJson = $finalRule | ConvertTo-Json -Compress
        $ruleName = $rule.Name+".ndjson"
        Set-Content -Path $ruleName -Value $ruleJson
        Move-Item -Path $ruleName -Destination ./output-2/ -Force 

        # Log results
        Write-Host "Rule $ruleName has been translated succesfully"
        Add-Content -Path ./sigma2elastic.log -Value "`nRule $ruleName has been translated succesfully"

}
}