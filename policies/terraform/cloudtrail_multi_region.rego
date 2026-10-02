# METADATA
# title: CloudTrail trails must cover all regions
# description: Prevents the supplied defect is_multi_region_trail = false, which leaves activity in every other region unrecorded. Traces to threat-model.md T5.
# custom:
#   id: ACCT-TF-004
#   severity: HIGH
#   input:
#     selector:
#       - type: terraform-raw
package user.accounts_api.cloudtrail_multi_region

import rego.v1

resources(type) := [block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type == type
]

deny contains res if {
	some trail in resources("aws_cloudtrail")
	not multi_region(trail)
	res := result.new("is_multi_region_trail must be true; an attacker with valid credentials will simply work in an unlogged region.", trail)
}

multi_region(trail) if trail.attributes.is_multi_region_trail.value == true
