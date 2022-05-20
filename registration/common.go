package registration

import "sync"

var authorizeLock *sync.Mutex

func init() {
	authorizeLock = new(sync.Mutex)
}
