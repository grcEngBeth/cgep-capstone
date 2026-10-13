# policies/cc6_7_s3_tls.rego
# METADATA
# title: CC6.7 - S3 buckets deny non-TLS requests (GAP-03)
# description: "Every aws_s3_bucket needs a bucket policy with a Deny statement on aws:SecureTransport = false."
# custom:
#   control_id: CC6.7
#   framework: soc2-tsc
#   severity: high
#   remediation: "Add an aws_s3_bucket_policy whose policy document denies s3:* when aws:SecureTransport is false."
package compliance.cc6_7_s3_tls

import rego.v1

deny contains msg if {
	some bucket in bucket_addrs
	not tls_enforced(bucket)
	msg := sprintf(
		"[SOC2 CC6.7] %s: no bucket policy denies non-TLS requests. Remediation: add aws_s3_bucket_policy with a Deny on aws:SecureTransport = false.",
		[bucket],
	)
}

bucket_addrs contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

tls_enforced(bucket_addr) if {
	some p in input.configuration.root_module.resources
	p.type == "aws_s3_bucket_policy"
	some ref in p.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some pref in p.expressions.policy.references
	doc := policy_doc_for(pref)
	denies_insecure(doc)
}

policy_doc_for(pref) := d if {
	some d in input.configuration.root_module.resources
	d.mode == "data"
	d.type == "aws_iam_policy_document"
	addr := sprintf("data.aws_iam_policy_document.%s", [d.name])
	pref in {addr, sprintf("%s.json", [addr])}
}

denies_insecure(doc) if {
	some s in doc.expressions.statement
	s.effect.constant_value == "Deny"
	some c in s.condition
	c.variable.constant_value == "aws:SecureTransport"
	"false" in c.values.constant_value
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
