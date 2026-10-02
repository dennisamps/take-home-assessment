# METADATA
# title: RDS instances must keep automated backups for at least 7 days
# description: Prevents the supplied defect backup_retention_period = 0, which disables automated backups and point-in-time recovery. Traces to threat-model.md T2.
# custom:
#   id: ACCT-TF-002
#   severity: HIGH
#   input:
#     selector:
#       - type: terraform-raw
package user.accounts_api.rds_backup_retention

import rego.v1

resources(type) := [block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type == type
]

deny contains res if {
	some db in resources("aws_db_instance")
	not retained(db)
	res := result.new("backup_retention_period must be set to 7 or more; 0 disables backups and point-in-time recovery.", db)
}

retained(db) if db.attributes.backup_retention_period.value >= 7
