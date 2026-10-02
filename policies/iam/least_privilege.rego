# METADATA
# title: IAM policy documents must be least privilege
# description: Prevents the supplied pod identity policy, which allowed everything except two actions (NotAction) on every resource. An Allow statement may not use NotAction, a wildcard action, or Resource "*". Traces to threat-model.md T2.
# custom:
#   id: ACCT-IAM-001
#   severity: CRITICAL
#   input:
#     selector:
#       - type: json
package user.accounts_api.iam_least_privilege

import rego.v1

statements := input.Statement if is_array(input.Statement)

statements := [input.Statement] if is_object(input.Statement)

as_list(value) := value if is_array(value)

as_list(value) := [value] if is_string(value)

allows contains statement if {
	some statement in statements
	statement.Effect == "Allow"
}

deny contains res if {
	some statement in allows
	statement.NotAction
	res := result.new("Allow with NotAction grants every action except those listed; list the allowed actions instead.", {})
}

deny contains res if {
	some statement in allows
	some action in as_list(statement.Action)
	endswith(action, "*")
	res := result.new(sprintf("Wildcard action %q is not allowed; name each action.", [action]), {})
}

deny contains res if {
	some statement in allows
	some resource in as_list(statement.Resource)
	resource == "*"
	res := result.new("Resource \"*\" is not allowed; name the specific resource ARNs.", {})
}
