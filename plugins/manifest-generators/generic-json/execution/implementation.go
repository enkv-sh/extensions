// Package execution binds the manifest plugin's native startup declaration.
package execution

import (
	plugin "enkv.sh/plugins/manifest-generators/generic-json"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/native"
)

// NewImplementation checks the embedded descriptor before author callbacks run.
func NewImplementation(descriptor []byte) (native.Implementation, error) {
	return native.Bind(descriptor, plugin.ConfigContractID, plugin.FormatContractID, manifest.Implementation{ValidateFormatSettings: plugin.ValidateFormatSettings, Render: plugin.Render})
}
