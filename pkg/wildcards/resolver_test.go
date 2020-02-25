package wildcards

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRotateRoundRobin(t *testing.T) {
	index := int32(0)
	indexList := []string{"a", "b", "c", "d", "e"}

	for i := 0; i < len(indexList)+2; i++ {
		newIndex := atomic.LoadInt32(&index)

		if newIndex >= int32(len(indexList)) {
			require.Failf(t, "got invalid index", "Could not get index newIndex=%d: i=%d", newIndex, i)
		}

		if newIndex == int32(len(indexList)-1) {
			atomic.StoreInt32(&index, 0)
		}
		atomic.AddInt32(&index, 1)
	}
}
