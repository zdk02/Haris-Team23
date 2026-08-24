# verify-deployment.ps1
#
# Asks AWS to confirm every claim made about the Haris deployment.
# Nothing here changes anything - all read-only.
#
# Runs in either place, unchanged:
#
#   CloudShell (the console session authenticates to the deployment account;
#   CloudShell has no named profiles, so pass nothing):
#       pwsh ./verify-deployment.ps1
#
#   A workstation with a named profile:
#       .\verify-deployment.ps1 -AwsProfile haris | Tee-Object -FilePath report\appendix\deployment-verification.txt
#
# The -AwsProfile parameter exists because the account you REACH and the account
# you MEANT are different claims. Section 1 proves the first one, and every
# section below it is meaningless if Section 1 is wrong: AWS does not error when
# you query the wrong account, it answers as though the world were empty. That
# failure mode - an empty result that reads exactly like "nothing was deployed" -
# is the reason this script prints the account before it prints anything else.
#
# Re-run before capturing report evidence, and again immediately before teardown.

param(
    # Empty = use ambient credentials (CloudShell, an EC2 role, an env var).
    [string]$AwsProfile = "",

    # The account this deployment is expected to live in. A parameter rather than
    # a constant so the script is a general tool, but with the real value as the
    # default so running it with no arguments still asserts something.
    [string]$AccountId = "007267918845",

    [string]$Region    = "us-east-1",
    [string]$Domain    = "haris-monitor.com",
    [string]$StackName = "haris",

    # The registry is deliberately NOT derived from $StackName: the repository is
    # created by hand, outside the stack, so it has its own lifecycle and could
    # legitimately be named differently.
    [string]$Repo     = "haris",
    [string]$ImageTag = "v1"
)

$ErrorActionPreference = "Continue"

# --------------------------------------------------------------------------
# CLI behaviour.
#
# ORDER MATTERS: $P must exist before anything is appended to it. Appending
# first and assigning second silently discards the flags - which is exactly how
# the pager kept firing after it had supposedly been turned off.
#
# --no-cli-pager  : the pager truncates long tables at one screenful. Piped
#                   output disables it automatically, so the corruption only
#                   appears on a bare run - i.e. exactly when you are least
#                   likely to notice it is different from the captured file.
# --color off     : ANSI escapes render as stray [0m in a captured file.
#
# Both default to "auto", meaning "behave differently depending on where the
# output goes". This appendix is a file, so pin both.
# --------------------------------------------------------------------------
$env:AWS_PAGER = ""

$P = @("--region", $Region, "--no-cli-pager", "--color", "off")
if ($AwsProfile) { $P += @("--profile", $AwsProfile) }

# --------------------------------------------------------------------------
# Resource names.
#
# Every stack-created resource follows "<stack>-<role>", so they are derived
# rather than repeated across seventeen sections. Kept in one block so the whole
# set can be checked against a `describe-stack-resources` listing at a glance.
# --------------------------------------------------------------------------
$Cluster    = "$StackName-cluster"
$ServiceNm  = "$StackName-service"
$TargetGrp  = "$StackName-tg"
$AlbName    = "$StackName-alb"
$ExecRole   = "$StackName-execution-role"
$ExecPolicy = "$StackName-execution"
$TaskRole   = "$StackName-task-role"
$LogGroup   = "/ecs/$StackName"
$BudgetName = "$StackName-monthly-gross"

function Section($n) { "`n" + ("=" * 70); "  $n"; ("=" * 70) }

# --------------------------------------------------------------------------
# Guard first. Read-only, so this warns rather than throws - but loudly, because
# every section below is describing whatever account we actually reached.
# --------------------------------------------------------------------------
$actual = aws sts get-caller-identity @P --query Account --output text 2>$null
if ($actual -ne $AccountId) {
    Write-Warning ("WRONG ACCOUNT: reached '$actual', expected '$AccountId'. " +
                   "Everything below describes the wrong account and will look " +
                   "like an empty deployment rather than an error.")
}

Section "1. IDENTITY - must be account $AccountId"
aws sts get-caller-identity @P --output json

Section "2. BUDGET - Credit and Refund must be false, or it never fires"
aws budgets describe-budgets --account-id $AccountId @P `
  --query "Budgets[0].{Name:BudgetName,Limit:BudgetLimit.Amount,IncludeCredit:CostTypes.IncludeCredit,IncludeRefund:CostTypes.IncludeRefund}" --output json
aws budgets describe-notifications-for-budget --account-id $AccountId --budget-name $BudgetName @P `
  --query "Notifications[].Threshold" --output json

Section "3. DOMAIN - AutoRenew must be false"
aws route53domains list-domains @P `
  --query "Domains[].{Name:DomainName,AutoRenew:AutoRenew,Expiry:Expiry}" --output json

Section "4. CERTIFICATE - must be ISSUED, apex + wildcard"
$certArn = aws acm list-certificates @P --query "CertificateSummaryList[0].CertificateArn" --output text
aws acm describe-certificate --certificate-arn $certArn @P `
  --query "Certificate.{Status:Status,Domains:SubjectAlternativeNames,Method:DomainValidationOptions[0].ValidationMethod}" --output json

Section "5. ECR - repository and images"
aws ecr describe-repositories --repository-names $Repo @P `
  --query "repositories[].{Name:repositoryName,Uri:repositoryUri,Encryption:encryptionConfiguration.encryptionType,TagMutability:imageTagMutability}" --output json
aws ecr describe-images --repository-name $Repo @P `
  --query "imageDetails[].{Tag:imageTags[0],Bytes:imageSizeInBytes,Media:imageManifestMediaType,Digest:imageDigest}" --output json

Section "6. REGISTRY SCANNING - the per-repo toggle is inert; this is the real setting"
aws ecr get-registry-scanning-configuration @P --output json

Section "6b. SCAN FINDINGS - the heading above promises these, so print them"
# Ask by tag first. That works whenever the tag names a single manifest, which
# is the case for any image built with --provenance=false.
#
# It does NOT work for a buildx default build: buildx pushes an OCI image INDEX,
# and ECR does not scan indexes, so the tag returns ScanNotFoundException. The
# console resolves the child manifest transparently; the CLI does not. The
# fallback below resolves it explicitly, so the appendix carries real counts
# either way - and once the submission image is pushed with --provenance=false
# the fallback stops firing and this section needs no maintenance.
#
# Note what BASIC scanning covers: OS packages from the distribution manifest.
# It does not read requirements.lock.txt, so Python dependencies are UNSCANNED.
# Language-level scanning needs Enhanced scanning (Amazon Inspector), scoped out
# on cost. Say that in the report rather than letting a reader assume otherwise.

$scanTarget = "imageTag=$ImageTag"
$counts = aws ecr describe-image-scan-findings --repository-name $Repo --image-id $scanTarget @P `
            --query "imageScanFindings.findingSeverityCounts" --output json 2>$null

if ($LASTEXITCODE -ne 0 -or -not $counts) {
    "Tag '$ImageTag' is not directly scannable - resolving the index's child manifest."
    $idx = aws ecr batch-get-image --repository-name $Repo --image-ids imageTag=$ImageTag `
             --accepted-media-types "application/vnd.oci.image.index.v1+json" `
                                    "application/vnd.docker.distribution.manifest.list.v2+json" `
             @P --query "images[0].imageManifest" --output text 2>$null

    # Attestation manifests declare platform unknown/unknown; the real image does
    # not. Selecting on platform rather than on size means this stays correct
    # once a second tag exists in the repository.
    $child = $null
    if ($idx) {
        $child = ($idx | ConvertFrom-Json).manifests |
                 Where-Object { $_.platform.architecture -ne "unknown" } |
                 Select-Object -First 1
    }

    if ($child) {
        $scanTarget = "imageDigest=$($child.digest)"
        "  tag '$ImageTag' -> $scanTarget"
        $counts = aws ecr describe-image-scan-findings --repository-name $Repo --image-id $scanTarget @P `
                    --query "imageScanFindings.findingSeverityCounts" --output json
    } else {
        Write-Warning "Could not resolve a scannable manifest for tag '$ImageTag'. No scan findings below."
        $scanTarget = $null
    }
}

if ($scanTarget) {
    $counts
    aws ecr describe-image-scan-findings --repository-name $Repo --image-id $scanTarget @P `
      --query "imageScanFindings.findings[?severity=='CRITICAL'].{CVE:name,Package:attributes[?key=='package_name']|[0].value}" --output table
}

Section "7. STACK - every resource must be CREATE_ or UPDATE_COMPLETE"
aws cloudformation describe-stack-resources --stack-name $StackName @P `
  --query "StackResources[].{Name:LogicalResourceId,Type:ResourceType,Status:ResourceStatus}" --output table
aws cloudformation describe-stacks --stack-name $StackName @P --query "Stacks[0].Outputs" --output table

Section "8. ECS SERVICE - 1/1 running; circuit breaker must be enabled"
aws ecs describe-services --cluster $Cluster --services $ServiceNm @P `
  --query "services[0].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition,CircuitBreaker:deploymentConfiguration.deploymentCircuitBreaker}" --output json

Section "9. TARGET HEALTH - must be healthy; stickiness must be enabled"
$tg = aws elbv2 describe-target-groups --names $TargetGrp @P --query "TargetGroups[0].TargetGroupArn" --output text
aws elbv2 describe-target-health --target-group-arn $tg @P `
  --query "TargetHealthDescriptions[].TargetHealth" --output json
aws elbv2 describe-target-group-attributes --target-group-arn $tg @P `
  --query "Attributes[?starts_with(Key, 'stickiness')]" --output json

Section "10. LISTENERS - :80 must redirect, :443 must carry the certificate"
$alb = aws elbv2 describe-load-balancers --names $AlbName @P --query "LoadBalancers[0].LoadBalancerArn" --output text
aws elbv2 describe-listeners --load-balancer-arn $alb @P `
  --query "Listeners[].{Port:Port,Protocol:Protocol,Action:DefaultActions[0].Type,SslPolicy:SslPolicy,Certs:Certificates[].CertificateArn}" --output json
aws elbv2 describe-load-balancer-attributes --load-balancer-arn $alb @P `
  --query "Attributes[?Key=='idle_timeout.timeout_seconds']" --output json

Section "11. EXECUTION ROLE - every action scoped to one ARN except GetAuthorizationToken"
aws iam get-role-policy --role-name $ExecRole --policy-name $ExecPolicy @P --output json

Section "12. TASK ROLE - this list MUST be empty. That is the least-privilege claim."
"Attached managed policies:"
aws iam list-attached-role-policies --role-name $TaskRole @P --query "AttachedPolicies" --output json
"Inline policies:"
aws iam list-role-policies --role-name $TaskRole @P --query "PolicyNames" --output json

Section "13. TASK DEFINITION - environment empty; BOTH secrets from Secrets Manager"
# Secrets must list HARIS_DASHBOARD_TOKEN *and* HARIS_AUDIT_KEY. Without the
# second one the deployed audit chain is unkeyed: corruption-evident, not
# tamper-evident - and THREAT_MODEL.md claims the latter.
aws ecs describe-task-definition --task-definition $StackName @P `
  --query "taskDefinition.{Cpu:cpu,Memory:memory,Env:containerDefinitions[0].environment,Secrets:containerDefinitions[0].secrets[].name,LogDriver:containerDefinitions[0].logConfiguration.logDriver}" --output json

Section "14. LOGS - retention must be set, and there must be recent events"
aws logs describe-log-groups --log-group-name-prefix $LogGroup @P `
  --query "logGroups[].{Name:logGroupName,Retention:retentionInDays}" --output json
aws logs describe-log-streams --log-group-name $LogGroup @P `
  --query "reverse(sort_by(logStreams,&lastEventTimestamp))[0].{Stream:logStreamName,LastEvent:lastEventTimestamp}" --output json

Section "15. DNS - apex AND www must both alias the load balancer"
# list-hosted-zones-by-name is a PREFIX match, so confirm the zone that came
# back is actually the one asked for before trusting the records under it.
$zoneId   = aws route53 list-hosted-zones-by-name --dns-name $Domain @P --query "HostedZones[0].Id" --output text
$zoneName = aws route53 list-hosted-zones-by-name --dns-name $Domain @P --query "HostedZones[0].Name" --output text
"Hosted zone: $zoneName ($zoneId)"
if ($zoneName.TrimEnd('.') -ne $Domain) {
    Write-Warning "Zone '$zoneName' is not '$Domain.' - the records below belong to a different zone."
}
aws route53 list-resource-record-sets --hosted-zone-id $zoneId @P `
  --query "ResourceRecordSets[?Type=='A'].{Name:Name,Alias:AliasTarget.DNSName}" --output json

Section "16. LIVE SITE - 301 on http, 200 on https, apex AND www"
# A curl code of 000 is not an HTTP status: it means the connection never
# happened at all, which for www means the DNS record does not exist.
curl.exe -s -o NUL -w "http  apex -> %{http_code}  redirect: %{redirect_url}`n" "http://$Domain"
curl.exe -s -o NUL -w "https apex -> %{http_code}`n" "https://$Domain"
curl.exe -s -o NUL -w "https www  -> %{http_code}`n" "https://www.$Domain"
curl.exe -s -w "`n" "https://$Domain/_stcore/health"

Section "17. NO STRAY SECURITY GROUP RULES - task SG should admit ONLY the ALB group"
$sg = aws cloudformation describe-stack-resource --stack-name $StackName --logical-resource-id TaskSecurityGroup @P `
  --query "StackResourceDetail.PhysicalResourceId" --output text
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg" @P `
  --query "SecurityGroupRules[?IsEgress==``false``].{Port:FromPort,FromCidr:CidrIpv4,FromGroup:ReferencedGroupInfo.GroupId}" --output json

# --------------------------------------------------------------------------
# Summary of the assertions that are easy to miss in seventeen sections of JSON.
# --------------------------------------------------------------------------
Section "SUMMARY"

function Check($label, $condition) {
    "{0}  {1}" -f $(if ($condition) { "PASS" } else { "FAIL" }), $label
}

$svc  = aws ecs describe-services --cluster $Cluster --services $ServiceNm @P `
          --query "services[0].deploymentConfiguration.deploymentCircuitBreaker.enable" --output text
$stky = aws elbv2 describe-target-group-attributes --target-group-arn $tg @P `
          --query "Attributes[?Key=='stickiness.enabled'].Value | [0]" --output text
$secs = aws ecs describe-task-definition --task-definition $StackName @P `
          --query "taskDefinition.containerDefinitions[0].secrets[].name" --output text
$arec = aws route53 list-resource-record-sets --hosted-zone-id $zoneId @P `
          --query "length(ResourceRecordSets[?Type=='A'])" --output text
$wwwc = curl.exe -s -o NUL -w "%{http_code}" "https://www.$Domain"

Check "account is $AccountId"                       ($actual -eq $AccountId)
Check "deployment circuit breaker enabled"          ($svc  -eq "true")
Check "target group stickiness enabled"             ($stky -eq "true")
Check "HARIS_AUDIT_KEY injected from Secrets Mgr"   ($secs -match "HARIS_AUDIT_KEY")
Check "apex and www A records both present"         ([int]$arec -ge 2)
Check "https://www.$Domain responds 200"            ($wwwc -eq "200")

Section "DONE"
"Any line above that does not match its heading is a real finding, not a formatting quirk."
if ($actual -ne $AccountId) {
    "`n*** THIS RUN QUERIED ACCOUNT $actual, NOT $AccountId. Discard this output. ***"
}