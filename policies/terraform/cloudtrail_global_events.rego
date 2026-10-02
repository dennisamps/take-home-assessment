# METADATA
# title: CloudTrail trails must record global service events
# description: Prevents the supplied defect include_global_service_events = false, which drops IAM and STS events such as role assumption and policy changes. Traces to threat-model.md T5.
# custom:
#   id: ACCT-TF-005
#   severity: HIGH
#   input:
#     selector:
#       - type: terraform-raw
package user.accounts_api.cloudtrail_global_events

import rego.v1

resources(type) := [block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type == type
]

deny contains res if {
	some trail in resources("aws_cloudtrail")
	trail.attributes.include_global_service_events.value == false
	res := result.new("include_global_service_events must not be false; IAM and STS activity would go unrecorded.", trail)
}
