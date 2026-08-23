# verify-deployment.ps1
#
# Asks AWS to confirm every claim made about the Haris deployment.
# Nothing here changes anything - all read-only.
#
#   .\verify-deployment.ps1 | Tee-Object -FilePath report\appendix\deployment-verification.txt
#
# Re-run it after Stage 6, and again immediately before teardown.

$ErrorActionPreference = "Continue"
$P = "--profile", "haris", "--region", "us-east-1"
$ACC = "007267918845"

function Section($n) { "`n" + ("=" * 70); "  $n"; ("=" * 70) }

Section "1. IDENTITY - must be account $ACC"
aws sts get-caller-identity @P --output json

Section "2. BUDGET - Credit and Refund must be false, or it never fires"
aws budgets describe-budgets --account-id $ACC --profile haris `
  --query "Budgets[0].{Name:BudgetName,Limit:BudgetLimit.Amount,IncludeCredit:CostTypes.IncludeCredit,IncludeRefund:CostTypes.IncludeRefund}" --output json
aws budgets describe-notifications-for-budget --account-id $ACC --budget-name haris-monthly-gross --profile haris `
  --query "Notifications[].Threshold" --output json

Section "3. DOMAIN - AutoRenew must be false"
aws route53domains list-domains --region us-east-1 --profile haris `
  --query "Domains[].{Name:DomainName,AutoRenew:AutoRenew,Expiry:Expiry}" --output json

Section "4. CERTIFICATE - must be ISSUED, apex + wildcard"
$certArn = aws acm list-certificates @P --query "CertificateSummaryList[0].CertificateArn" --output text
aws acm describe-certificate --certificate-arn $certArn @P `
  --query "Certificate.{Status:Status,Domains:SubjectAlternativeNames,Method:DomainValidationOptions[0].ValidationMethod}" --output json

Section "5. ECR - repository, image, and scan findings"
aws ecr describe-repositories --repository-names haris @P `
  --query "repositories[].{Name:repositoryName,Uri:repositoryUri,Encryption:encryptionConfiguration.encryptionType}" --output json
aws ecr describe-images --repository-name haris @P `
  --query "imageDetails[].{Tag:imageTags[0],Bytes:imageSizeInBytes,Media:imageManifestMediaType}" --output json

Section "6. REGISTRY SCANNING - the per-repo toggle is inert; this is the real setting"
aws ecr get-registry-scanning-configuration @P --output json

Section "7. STACK - all 23 resources must be CREATE_ or UPDATE_COMPLETE"
aws cloudformation describe-stack-resources --stack-name haris @P `
  --query "StackResources[].{Name:LogicalResourceId,Type:ResourceType,Status:ResourceStatus}" --output table
aws cloudformation describe-stacks --stack-name haris @P --query "Stacks[0].Outputs" --output table

Section "8. ECS SERVICE - 1/1 running"
aws ecs describe-services --cluster haris-cluster --services haris-service @P `
  --query "services[0].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}" --output json

Section "9. TARGET HEALTH - must be healthy"
$tg = aws elbv2 describe-target-groups --names haris-tg @P --query "TargetGroups[0].TargetGroupArn" --output text
aws elbv2 describe-target-health --target-group-arn $tg @P `
  --query "TargetHealthDescriptions[].TargetHealth" --output json

Section "10. LISTENERS - :80 must redirect, :443 must carry the certificate"
$alb = aws elbv2 describe-load-balancers --names haris-alb @P --query "LoadBalancers[0].LoadBalancerArn" --output text
aws elbv2 describe-listeners --load-balancer-arn $alb @P `
  --query "Listeners[].{Port:Port,Protocol:Protocol,Action:DefaultActions[0].Type,SslPolicy:SslPolicy}" --output json
aws elbv2 describe-load-balancer-attributes --load-balancer-arn $alb @P `
  --query "Attributes[?Key=='idle_timeout.timeout_seconds']" --output json

Section "11. EXECUTION ROLE - every action scoped to one ARN except GetAuthorizationToken"
aws iam get-role-policy --role-name haris-execution-role --policy-name haris-execution --profile haris --output json

Section "12. TASK ROLE - this list MUST be empty. That is the least-privilege claim."
"Attached managed policies:"
aws iam list-attached-role-policies --role-name haris-task-role --profile haris --query "AttachedPolicies" --output json
"Inline policies:"
aws iam list-role-policies --role-name haris-task-role --profile haris --query "PolicyNames" --output json

Section "13. TASK DEFINITION - environment must be empty (no diagnostic overrides left)"
aws ecs describe-task-definition --task-definition haris @P `
  --query "taskDefinition.{Cpu:cpu,Memory:memory,Env:containerDefinitions[0].environment,Secrets:containerDefinitions[0].secrets[].name,LogDriver:containerDefinitions[0].logConfiguration.logDriver}" --output json

Section "14. LOGS - there must be recent events"
aws logs describe-log-streams --log-group-name /ecs/haris @P `
  --query "reverse(sort_by(logStreams,&lastEventTimestamp))[0].{Stream:logStreamName,LastEvent:lastEventTimestamp}" --output json

Section "15. LIVE SITE - 301 on http, 200 on https"
curl.exe -s -o NUL -w "http  -> %{http_code} redirect: %{redirect_url}`n" http://haris-monitor.com
curl.exe -s -o NUL -w "https -> %{http_code}`n" https://haris-monitor.com
curl.exe -s https://haris-monitor.com/_stcore/health

Section "16. NO STRAY SECURITY GROUP RULES - task SG should admit ONLY the ALB group"
$sg = aws cloudformation describe-stack-resource --stack-name haris --logical-resource-id TaskSecurityGroup @P `
  --query "StackResourceDetail.PhysicalResourceId" --output text
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg" @P `
  --query "SecurityGroupRules[?IsEgress==``false``].{Port:FromPort,FromCidr:CidrIpv4,FromGroup:ReferencedGroupInfo.GroupId}" --output json

Section "DONE"
"Any line above that does not match its heading is a real finding, not a formatting quirk."