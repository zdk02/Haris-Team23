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
#       .\verify-deployment.ps1 -AwsProfile haris
#
# To capture the appendix file, do NOT use `Tee-Object` or `>` on Windows
# PowerShell 5.1: both write UTF-16, which renders as spaced-out garbage in most
# viewers and diff tools. Appendix B is read by a grader, so write UTF-8 with no
# BOM explicitly:
#
#   $out = .\verify-deployment.ps1 -AwsProfile haris | Out-String
#   [System.IO.File]::WriteAllText(
#       (Join-Path $PWD "report\appendix\deployment-verification.txt"),
#       $out, (New-Object System.Text.UTF8Encoding $false))
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

    # The tag whose scan findings section 6b reports. The DEPLOYED image is
    # referenced by digest, not by tag - the SUMMARY asserts that the digest this
    # tag points at is the digest the task definition runs, so scanning by tag
    # and describing the deployed bytes are the same statement rather than an
    # assumption.
    [string]$ImageTag = "v2"
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
# TagMutability must read IMMUTABLE. A mutable tag can be overwritten in place,
# which would make the deployment circuit breaker's rollback return to a NAME
# rather than to the bytes that were tested.
aws ecr describe-repositories --repository-names $Repo @P `
  --query "repositories[].{Name:repositoryName,Uri:repositoryUri,Encryption:encryptionConfiguration.encryptionType,TagMutability:imageTagMutability}" --output json
aws ecr describe-images --repository-name $Repo @P `
  --query "imageDetails[].{Tag:imageTags[0],Bytes:imageSizeInBytes,Media:imageManifestMediaType,Digest:imageDigest}" --output json

Section "6. REGISTRY SCANNING - the per-repo toggle is inert; this is the real setting"
aws ecr get-registry-scanning-configuration @P --output json

Section "6b. SCAN FINDINGS - the heading above promises these, so print them"
# Ask by tag first. That works whenever the tag names a single manifest, which
# is the case for any image built with --provenance=false - as the submission
# image is. The fallback below therefore no longer fires for the current tag;
# it is kept because v1 is still in the repository and is an OCI INDEX, and a
# reader re-running this against that tag would otherwise get nothing.
#
# Why an index cannot be scanned by tag: buildx's default export pushes an OCI
# image INDEX carrying a provenance attestation, and ECR does not scan indexes,
# so the tag returns ScanNotFoundException. The console resolves the child
# manifest transparently; the CLI does not.
#
# Note what BASIC scanning covers: OS packages from the distribution manifest.
# It does not read requirements.lock.txt, so Python dependencies are UNSCANNED.
# "No findings in application dependencies" is therefore a limit of the scanner,
# not a measured property. Language-level scanning needs Enhanced scanning
# (Amazon Inspector), scoped out on cost. Say that in the report rather than
# letting a reader assume otherwise.
#
# Also note the findings are scored against the CVE database AT SCAN TIME. BASIC
# does not re-scan automatically, so comparing two images scanned days apart
# compares two databases, not two images. Re-scan both before quoting a delta.

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
    aws ecr describe-image-scan-findings --repository-name $Repo --image-id $scanTarget @P `
      --query "imageScanFindings.{Scanned:imageScanCompletedAt,SourceUpdated:vulnerabilitySourceUpdatedAt}" --output json

    # Cross-reference: the scan above must describe the bytes the service is
    # actually running. Printed side by side so the appendix shows it rather
    # than asking the reader to trust it; the SUMMARY asserts it.
    $deployedImage = aws ecs describe-task-definition --task-definition $StackName @P `
                       --query "taskDefinition.containerDefinitions[0].image" --output text
    "scanned  : $scanTarget"
    "deployed : $deployedImage"
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

Section "13. TASK DEFINITION - environment empty; ALL THREE secrets from Secrets Manager; image by digest"
# Secrets must list HARIS_DASHBOARD_TOKEN, HARIS_AUDIT_KEY *and* HARIS_ALERT_WEBHOOK.
#
#   Without the second, the deployed audit chain is unkeyed: corruption-evident,
#   not tamper-evident - and THREAT_MODEL.md claims the latter.
#
#   Without the third, the Notifier's webhook channel is a silent no-op. A
#   blocked leak still reaches the dashboard banner, but leaves the container by
#   no route at all, and the operational log counts every send as `skipped`.
#
# Env must stay empty: a value here would appear in `describe-task-definition`
# output, which is exactly what the Secrets block exists to avoid.
#
# Image must be addressed by DIGEST rather than by tag, so the deployment
# circuit breaker rolls back to bytes that were tested rather than to whatever a
# name currently resolves to.
aws ecs describe-task-definition --task-definition $StackName @P `
  --query "taskDefinition.{Revision:revision,Cpu:cpu,Memory:memory,Image:containerDefinitions[0].image,Env:containerDefinitions[0].environment,Secrets:containerDefinitions[0].secrets[].name,LogDriver:containerDefinitions[0].logConfiguration.logDriver}" --output json

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

$svc   = aws ecs describe-services --cluster $Cluster --services $ServiceNm @P `
           --query "services[0].deploymentConfiguration.deploymentCircuitBreaker.enable" --output text
$stky  = aws elbv2 describe-target-group-attributes --target-group-arn $tg @P `
           --query "Attributes[?Key=='stickiness.enabled'].Value | [0]" --output text
$secs  = aws ecs describe-task-definition --task-definition $StackName @P `
           --query "taskDefinition.containerDefinitions[0].secrets[].name" --output text
$img   = aws ecs describe-task-definition --task-definition $StackName @P `
           --query "taskDefinition.containerDefinitions[0].image" --output text
$mut   = aws ecr describe-repositories --repository-names $Repo @P `
           --query "repositories[0].imageTagMutability" --output text
$tagDg = aws ecr describe-images --repository-name $Repo --image-ids imageTag=$ImageTag @P `
           --query "imageDetails[0].imageDigest" --output text
$arec  = aws route53 list-resource-record-sets --hosted-zone-id $zoneId @P `
           --query "length(ResourceRecordSets[?Type=='A'])" --output text
$wwwc  = curl.exe -s -o NUL -w "%{http_code}" "https://www.$Domain"

# Computed separately rather than inline: a multi-clause condition inside a
# function call argument is the kind of thing that silently becomes $true.
$allSecrets = ($secs -match "HARIS_DASHBOARD_TOKEN") -and
              ($secs -match "HARIS_AUDIT_KEY") -and
              ($secs -match "HARIS_ALERT_WEBHOOK")

# An empty $tagDg would make the -like match trivially true, so require it.
$scanMatchesDeployed = [bool]$tagDg -and ($img -like "*$tagDg")

Check "account is $AccountId"                          ($actual -eq $AccountId)
Check "deployment circuit breaker enabled"             ($svc  -eq "true")
Check "target group stickiness enabled"                ($stky -eq "true")
Check "all three task secrets injected"                $allSecrets
Check "image pinned by digest, not tag"                ($img -match "@sha256:")
Check "ECR repository is immutable"                    ($mut -eq "IMMUTABLE")
Check "scanned tag '$ImageTag' is the deployed image"  $scanMatchesDeployed
Check "apex and www A records both present"            ([int]$arec -ge 2)
Check "https://www.$Domain responds 200"               ($wwwc -eq "200")

Section "DONE"
"Any line above that does not match its heading is a real finding, not a formatting quirk."
if ($actual -ne $AccountId) {
    "`n*** THIS RUN QUERIED ACCOUNT $actual, NOT $AccountId. Discard this output. ***"
}