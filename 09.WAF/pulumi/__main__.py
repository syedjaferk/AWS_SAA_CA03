import pulumi
import pulumi_aws as aws

# ─────────────────────────────────────────────────────────────
# WAFv2 Web Access Control List (Web ACL)
# ─────────────────────────────────────────────────────────────
# This Web ACL is configured for REGIONAL resources like Application Load Balancers (ALB) or API Gateways.
# If you need it for CloudFront, change scope to "CLOUDFRONT" and provider region to us-east-1.
web_acl = aws.wafv2.WebAcl(
    "waf-demo-acl",
    name="waf-demo-acl",
    scope="REGIONAL", 
    description="WAF demo with rate limiting and AWS managed rules",
    # By default, we ALLOW traffic that does not match any blocking rules
    default_action=aws.wafv2.WebAclDefaultActionArgs(
        allow=aws.wafv2.WebAclDefaultActionAllowArgs(),
    ),
    # Enables CloudWatch metrics for the overall Web ACL
    visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
        cloudwatch_metrics_enabled=True,
        metric_name="wafDemoAclMetrics",
        sampled_requests_enabled=True,
    ),
    rules=[
        # ─────────────────────────────────────────────────────────
        # Rule 1: Custom Rate-Based Rule
        # ─────────────────────────────────────────────────────────
        # Blocks any IP address that makes more than 1,000 requests per 5-minute window.
        aws.wafv2.WebAclRuleArgs(
            name="RateLimitRule",
            priority=1,
            action=aws.wafv2.WebAclRuleActionArgs(
                block=aws.wafv2.WebAclRuleActionBlockArgs(),
            ),
            statement=aws.wafv2.WebAclRuleStatementArgs(
                rate_based_statement=aws.wafv2.WebAclRuleStatementRateBasedStatementArgs(
                    limit=1000,
                    aggregate_key_type="IP",
                ),
            ),
            visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
                cloudwatch_metrics_enabled=True,
                metric_name="RateLimitRuleMetrics",
                sampled_requests_enabled=True,
            ),
        ),
        
        # ─────────────────────────────────────────────────────────
        # Rule 2: AWS Managed Rules (Core Rule Set)
        # ─────────────────────────────────────────────────────────
        # Protects against common vulnerabilities like OWASP Top 10 (SQLi, XSS, etc.).
        aws.wafv2.WebAclRuleArgs(
            name="AWS-AWSManagedRulesCommonRuleSet",
            priority=2,
            # override_action 'none' means the rule group acts according to its own configured actions (usually Block)
            override_action=aws.wafv2.WebAclRuleOverrideActionArgs(
                none=aws.wafv2.WebAclRuleOverrideActionNoneArgs(),
            ),
            statement=aws.wafv2.WebAclRuleStatementArgs(
                managed_rule_group_statement=aws.wafv2.WebAclRuleStatementManagedRuleGroupStatementArgs(
                    name="AWSManagedRulesCommonRuleSet",
                    vendor_name="AWS",
                ),
            ),
            visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
                cloudwatch_metrics_enabled=True,
                metric_name="AWSManagedRulesCommonRuleSetMetrics",
                sampled_requests_enabled=True,
            ),
        ),
    ]
)

# ─────────────────────────────────────────────────────────────
# WAF Association (Example)
# ─────────────────────────────────────────────────────────────
# To actually attach this WAF to an ALB, uncomment the code below 
# and replace 'your-alb-arn' with the actual ARN of your Application Load Balancer.
#
# waf_alb_association = aws.wafv2.WebAclAssociation(
#     "waf-alb-association",
#     resource_arn="your-alb-arn-goes-here",
#     web_acl_arn=web_acl.arn,
# )

# ─────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────
pulumi.export("waf_acl_arn", web_acl.arn)
pulumi.export("waf_acl_id", web_acl.id)
pulumi.export("waf_acl_capacity", web_acl.capacity)
