# METADATA
# title: RDS instances must take a final snapshot when deleted
# description: Prevents the supplied defect skip_final_snapshot = true, which lets one terraform destroy or one stolen credential delete the database with no copy left. Traces to threat-model.md T2 and T5.
# custom:
#   id: ACCT-TF-003
#   severity: HIGH
#   input:
#     selector:
#       - type: terraform-raw
package user.accounts_api.rds_final_snapshot

import rego.v1

resources(type) := [block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type == type
]

deny contains res if {
	some db in resources("aws_db_instance")
	db.attributes.skip_final_snapshot.value == true
	res := result.new("skip_final_snapshot must not be true; set final_snapshot_identifier so deletion leaves a recoverable copy.", db)
}
