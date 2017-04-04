// +build go1.7

package providertests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func ExerciseProviderTestScenarios(t *testing.T, scenarios []ProviderTestScenario) {
	for _, scenario := range scenarios {
		t.Run(scenario.ScenarioName, func(t *testing.T) {
			assertionInfo, err := scenario.ServiceProvider.RetrieveAssertionInfo(scenario.Response)
			if scenario.CheckError != nil {
				scenario.CheckError(t, err)
			} else {
				require.NoError(t, err)
			}

			if err == nil {
				if scenario.CheckWarningInfo != nil {
					scenario.CheckWarningInfo(t, assertionInfo.WarningInfo)
				} else {
					require.False(t, assertionInfo.WarningInfo.InvalidTime)
					require.False(t, assertionInfo.WarningInfo.NotInAudience)
				}
			}
		})
	}
}
