# teardown.ps1
#
# Destroys the Haris deployment, and refuses to run against any other account.
#
#   CloudShell:    pwsh ./teardown.ps1
#   Workstation:   .\teardown.ps1 -AwsProfile haris
#
# WHY THE GUARD EXISTS
#
# `delete-stack` against an account that does not hold the stack fails with
# "Stack with id haris does not exist" - which reads exactly like "already gone,
# we are done". Close the terminal on that message and the real stack keeps
# running an ALB, a Fargate task and three public IPv4 addresses at roughly
# $2.10/day, indefinitely. The budget alarm does not stop it; a budget is a
# notification, not a brake.
#
# So the guard does not check which credentials were REQUESTED (--profile says
# that, and is often absent). It checks which account was actually REACHED.
# Those are different claims and only the second one is safe to delete on.
#
# WHAT THIS DOES NOT DELETE
#
# The ECR repository and the Secrets Manager secrets were created by hand,
# outside the stack, because they hold state that should outlive it. They
# therefore survive `delete-stack` and are listed at the end as commands to run
# deliberately - created by hand, removed by hand, symmetrically.

param(
    # Empty = ambient credentials (CloudShell). CloudShell has no named profiles.
    [string]$AwsProfile = "",

    [string]$AccountId = "007267918845",
    [string]$Region    = "us-east-1",
    [string]$StackName = "haris",

    # Skip the interactive confirmation. For scripted teardown only.
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$P = @("--region", $Region)
if ($AwsProfile) { $P += @("--profile", $AwsProfile) }

# --------------------------------------------------------------------------
# 0. The guard. Nothing below runs unless this passes.
# --------------------------------------------------------------------------
$actual = aws sts get-caller-identity @P --query Account --output text
if ($actual -ne $AccountId) {
    throw "WRONG ACCOUNT: reached '$actual', expected '$AccountId' - refusing to delete."
}
"Account confirmed: $actual"

# --------------------------------------------------------------------------
# 1. Show what is about to be destroyed, then ask.
# --------------------------------------------------------------------------
"`nResources in stack '$StackName':"
aws cloudformation describe-stack-resources --stack-name $StackName @P `
  --query "StackResources[].{Name:LogicalResourceId,Type:ResourceType}" --output table

if (-not $Force) {
    $answer = Read-Host "`nType the stack name ('$StackName') to confirm deletion"
    if ($answer -ne $StackName) { throw "Not confirmed - nothing deleted." }
}

# --------------------------------------------------------------------------
# 2. Delete the stack, and WAIT. Without the wait the script exits while
#    deletion is still in flight, so the confirmation below proves nothing.
# --------------------------------------------------------------------------
"`nDeleting stack '$StackName'..."
aws cloudformation delete-stack --stack-name $StackName @P
aws cloudformation wait stack-delete-complete --stack-name $StackName @P

# --------------------------------------------------------------------------
# 3. Confirm it is actually gone. describe-stacks must now FAIL.
# --------------------------------------------------------------------------
"`nConfirming the stack no longer exists:"
$ErrorActionPreference = "Continue"
$check = aws cloudformation describe-stacks --stack-name $StackName @P 2>&1 | Out-String
if ($check -match "does not exist") {
    "  OK - stack deleted."
} else {
    Write-Warning "  Stack still present. Read the output above before assuming this worked."
    $check
}

"`nRemaining billable resources in this account:"
aws elbv2 describe-load-balancers @P --query "LoadBalancers[].LoadBalancerName" --output json
aws ecs list-clusters @P --output json
aws ec2 describe-addresses @P --query "Addresses[].PublicIp" --output json
"(All three should be empty. An Elastic IP or load balancer left behind still bills.)"

# --------------------------------------------------------------------------
# 4. The by-hand resources. Printed, not executed - see the header.
# --------------------------------------------------------------------------
$prof = if ($AwsProfile) { " --profile $AwsProfile" } else { "" }
@"

------------------------------------------------------------------
Stage 2 - created by hand, so removed by hand. Run these when the
report evidence is captured and the submission is in.

  aws ecr delete-repository --repository-name haris --force --region $Region$prof

  aws secretsmanager delete-secret --secret-id haris/dashboard-token ``
      --force-delete-without-recovery --region $Region$prof

  aws secretsmanager delete-secret --secret-id haris/audit-key ``
      --force-delete-without-recovery --region $Region$prof

Kept deliberately (cheap, and deleting them is irreversible):
  * the Route 53 hosted zone   (~`$0.50/mo)
  * the registered domain      (auto-renew is off; it lapses on its own)
  * CloudWatch log group /ecs/haris - retention is 14 days, it empties itself

Check the Billing console tomorrow: the daily run rate should be near zero.
------------------------------------------------------------------
"@