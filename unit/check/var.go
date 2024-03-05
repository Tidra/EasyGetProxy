package check

import "time"

const (
	retryInterval = time.Second * 1
	maxRetryGet   = 3
	downloadSize  = 100
)
