// +build go1.7

package providertests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func ExerciseProviderTestScenarios(t *testing.T, scenarios []ProviderTestScenario) {
	for _, scenario := range scenarios {
		t.Run(scenario.ScenarioName, func(t *testing.T) {
			_, err := scenario.ServiceProvider.RetrieveAssertionInfo(scenario.Response)
			require.NoError(t, err)
		})
	}
}
