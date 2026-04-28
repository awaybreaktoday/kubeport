package main

import (
	"fmt"
	"os"
	"sync"
)

// cleanup is a LIFO stack of shutdown hooks. Each hook is run exactly once.
type cleanup struct {
	mu    sync.Mutex
	done  bool
	steps []cleanupStep
}

type cleanupStep struct {
	name string
	fn   func() error
}

func newCleanup() *cleanup { return &cleanup{} }

func (c *cleanup) push(name string, fn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps = append(c.steps, cleanupStep{name: name, fn: fn})
}

func (c *cleanup) run() {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	steps := c.steps
	c.mu.Unlock()

	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if err := step.fn(); err != nil {
			fmt.Fprintf(os.Stderr, "[kubeport] cleanup: %s: %v\n", step.name, err)
		}
	}
}
