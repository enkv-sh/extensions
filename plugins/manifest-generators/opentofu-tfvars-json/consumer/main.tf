terraform {
  required_version = "= 1.13.2"
}

variable "enkv" {
  description = "Public enkv OpenTofu reference manifest."
  nullable    = false

  type = object({
    schema             = string
    format_contract_id = string
    config_contract_id = string
    observation = object({
      domain_id        = string
      head_revision_id = string
      snapshot_id      = string
    })
    target_recipient_id = string
    selection = object({
      target_mode = string
      entry_mode  = string
    })
    service_filter = string
    plain = map(object({
      entry_incarnation_id = string
      encoding             = string
      value                = string
    }))
    secrets = map(object({
      entry_incarnation_id = string
      destinations = list(object({
        destination_id         = string
        binding_incarnation_id = string
        entry_incarnation_id   = string
        service_contract_id    = string
        consumer_locator       = string
        target_contract_id     = string
        canonical_target       = string
        target_data_base64     = string
        payload_encoding       = string
        consumer_policy = object({
          contract_id = string
          data_base64 = string
          digest      = string
        })
      }))
    }))
    excluded_entries = list(object({
      name                 = string
      entry_incarnation_id = string
      reason               = string
    }))
    evidence_limit = string
  })

  validation {
    condition = (
      var.enkv.schema == "ENKV/OPENTOFU-TFVARS-MANIFEST/v2" &&
      var.enkv.format_contract_id == "ENKV/OPENTOFU-TFVARS-MANIFEST/v2" &&
      var.enkv.config_contract_id == "ENKV/OPENTOFU-TFVARS-CONFIG/v1"
    )
    error_message = "Expected an enkv OpenTofu reference manifest."
  }
}

locals {
  # This named field has a known UTF-8 text meaning in this example.
  service_url = base64decode(var.enkv.plain["service_url"].value)

  # Preserve arbitrary bytes as the original padded Base64 string.
  binary_base64 = var.enkv.plain["binary"].value

  api_token_destinations = {
    for destination in var.enkv.secrets["api_token"].destinations :
    destination.destination_id => destination
  }
  api_token_reference = local.api_token_destinations["primary"]
}

output "service_url" {
  value = local.service_url
}

output "binary_base64" {
  value = local.binary_base64
}

output "api_token_reference" {
  value = local.api_token_reference
}
