package startup

import "github.com/cjlapao/common-go/execution_context"

var providers = execution_context.Get().Services

func Init() {
	// Add your initialization section here
}
