package main

import (
	"context"
	"fmt"
	"net"
)

// Tap is the interface object
type Tap struct {
	l     *Listener
	Ifi   *net.Interface
	ctx   context.Context
	Close context.CancelFunc
}

// NewTap finds, verifies and gets all aparms for a new Tap and returns the object
func NewTap(idx int) (*Tap, error) {

	ifi, err := net.InterfaceByIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("unable to get interface: %v", err)
	}

	l, err := NewListener(ifi)
	if err != nil {
		return nil, fmt.Errorf("unable to create Listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Tap{
		l:     l,
		ctx:   ctx,
		Close: cancel,
		Ifi:   ifi,
	}, nil
}

// Listen starts listening for RouterSolicits on this tap and sends periodic RAs
func (t Tap) Listen() error {
	return t.l.Listen6()
}
