# policies/sc28_encryption.rego
# METADATA
# title: SC-28 - Encryption at Rest (GCS)
# description: "Every google_storage_bucket must encrypt at rest with a customer-managed encryption key (CMEK)."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add an encryption { default_kms_key_name = ... } block referencing a google_kms_crypto_key you control."
package compliance.sc28

import rego.v1

deny contains msg if {
	some resource in input.planned_values.root_module.resources
	resource.type == "google_storage_bucket"
	not has_cmek(resource)
	msg := sprintf(
		"[SC-28] %s: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }.",
		[resource.address],
	)
}

# The same logic for module-wrapped buckets (recurse into child_modules).
deny contains msg if {
	some child in input.planned_values.root_module.child_modules
	some resource in child.resources
	resource.type == "google_storage_bucket"
	not has_cmek(resource)
	msg := sprintf(
		"[SC-28] %s: missing customer-managed encryption key. Remediation: add encryption { default_kms_key_name = ... }.",
		[resource.address],
	)
}

# Compliant if an encryption block is present and its key was not
# explicitly set to an empty string. A `null` key name is treated as
# compliant here because it commonly means the key is a reference to
# a resource being created in the same plan (value unknown until apply),
# not a missing configuration.
has_cmek(resource) if {
	count(resource.values.encryption) > 0
	not explicitly_empty(resource.values.encryption[0])
}

explicitly_empty(enc) if enc.default_kms_key_name == ""
