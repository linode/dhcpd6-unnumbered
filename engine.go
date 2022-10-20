package main

import (
	"fmt"
	"regexp"
	"sync"

	ll "github.com/sirupsen/logrus"
)

// Engine is the main object collecting all running taps
type Engine struct {
	tap   map[int]*Listener
	lock  sync.RWMutex
	Flags *ListenerOptions
}

// NewEngine just setups up a empty new engine
func NewEngine(regex string) (*Engine, error) {
	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, fmt.Errorf("unable to parse interface regex %s: %w", regex, err)
	}

	ll.Infof("Handling Interfaces matching '%s'", r.String())

	return &Engine{
		tap:  make(map[int]*Listener),
		lock: sync.RWMutex{},
		Flags: &ListenerOptions{
			regex: r,
		},
	}, nil
}

// Qualifies checks if interface qulalifies, aka matches the regex for taps to be handled
func (e *Engine) Qualifies(ifName string) bool {
	return e.Flags.regex.Match([]byte(ifName))
}

// Add adds a new Interface to be handled by the engine
func (e *Engine) Add(ifIdx int) {
	t, err := NewListener(ifIdx, e.Flags)
	if err != nil {
		ll.WithFields(ll.Fields{"InterfaceID": ifIdx}).Errorf("failed adding ifIndex %d: %s", ifIdx, err)
		return
	}

	ll.WithFields(ll.Fields{"Interface": t.ifi.Name}).Infof("adding %s", t.ifi.Name)

	// need to lock/handle concurrency due to the cleanup inside the go routine
	// eventually we could add some more logic to deal with on the fly route-changes by hooking into the routes channel
	e.lock.Lock()
	//assigning a copy to the map so I don't have to deal with concurrency while working with the tap itself
	e.tap[ifIdx] = t
	e.lock.Unlock()

	go func() {
		if err := t.Listen(); err != nil {
			ll.WithFields(ll.Fields{"Interface": t.ifi.Name}).Errorf("%s failed with %s", t.ifi.Name, err)
		}
		// cleanup after closing up
		e.lock.Lock()
		delete(e.tap, ifIdx)
		e.lock.Unlock()
	}()
}

// Get returns a lookedup Tap interface thread safe
func (e *Engine) Get(ifIdx int) *Listener {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.tap[ifIdx]
}

// Exists verifies (thread safe) if tap  is already handled or not
func (e *Engine) Exists(ifIdx int) bool {
	e.lock.RLock()
	_, exists := e.tap[ifIdx]
	e.lock.RUnlock()
	return exists
}

// Close stops handling a Tap interfaces and drops it from the map - thread safe
func (e *Engine) Close(ifIdx int) {
	e.lock.RLock()
	tap := e.tap[ifIdx]
	e.lock.RUnlock()
	ifName := tap.ifi.Name
	ll.WithFields(ll.Fields{"Interface": ifName}).Infof("removing %s", ifName)
	tap.Close()
}
