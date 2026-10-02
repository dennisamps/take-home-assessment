# METADATA
# title: PostgreSQL must not be reachable from the internet
# description: Prevents the supplied defect of the database security group admitting PostgreSQL 5432 from 0.0.0.0/0. A security group ingress rule may not open port 5432 to 0.0.0.0/0 or ::/0, whether it names the port, a range containing it, or all protocols. Public ingress on other ports, such as HTTPS 443 on the internet-facing ALB, is not affected. Traces to threat-model.md T2.
# custom:
#   id: ACCT-TF-001
#   severity: CRITICAL
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - provider: aws
#             service: ec2
package user.accounts_api.no_public_postgres_ingress

import rego.v1

postgres_port := 5432

public_cidrs := {"0.0.0.0/0", "::/0"}

deny contains res if {
	some sg in input.aws.ec2.securitygroups
	some rule in sg.ingressrules
	exposes_postgres(rule)
	some cidr in rule.cidrs
	cidr.value in public_cidrs
	res := result.new(
		sprintf("Security group ingress exposes PostgreSQL %d to %s; allow only the security group of the workload that needs the database.", [postgres_port, cidr.value]),
		cidr,
	)
}

# The rule names 5432 or a TCP port range that contains it.
exposes_postgres(rule) if {
	rule.protocol.value in {"tcp", "6"}
	rule.fromport.value <= postgres_port
	rule.toport.value >= postgres_port
}

# The rule allows all protocols, and therefore every port.
exposes_postgres(rule) if rule.protocol.value in {"-1", "all"}
