package platformsamlauth

import "sync"

type authorizationStartMaterial struct {
	guard     sync.Mutex
	handle    []byte
	destroyed bool
}

func newAuthorizationStartMaterial(handle []byte) *authorizationStartMaterial {
	return &authorizationStartMaterial{handle: handle}
}

func (material *authorizationStartMaterial) copy() []byte {
	if material == nil {
		return nil
	}
	material.guard.Lock()
	defer material.guard.Unlock()
	if material.destroyed {
		return nil
	}
	return append([]byte(nil), material.handle...)
}

func (material *authorizationStartMaterial) consume() ([]byte, bool) {
	if material == nil {
		return nil, false
	}
	material.guard.Lock()
	defer material.guard.Unlock()
	if material.destroyed || len(material.handle) == 0 {
		return nil, false
	}
	handle := material.handle
	material.handle = nil
	material.destroyed = true
	return handle, true
}

func (material *authorizationStartMaterial) present() bool {
	if material == nil {
		return false
	}
	material.guard.Lock()
	defer material.guard.Unlock()
	return !material.destroyed && len(material.handle) != 0
}

// ConsumeBrowserHandle transfers the one browser-handle owner exactly once.
// Every value copy shares the same owner, so concurrent transports cannot
// emit duplicate transaction cookies.
func (start *AuthorizationStart) ConsumeBrowserHandle() ([]byte, bool) {
	if start == nil || start.material == nil {
		return nil, false
	}
	return start.material.consume()
}

// Destroy clears the browser-handle owner shared by every value copy. It is
// safe to call concurrently and more than once.
func (start *AuthorizationStart) Destroy() {
	if start == nil || start.material == nil {
		return
	}
	material := start.material
	material.guard.Lock()
	if !material.destroyed {
		clear(material.handle)
		material.handle = nil
		material.destroyed = true
	}
	material.guard.Unlock()
}
