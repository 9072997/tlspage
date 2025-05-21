package main

import (
	"os"
	"os/signal"
)

var ProcessShutdownHandlers []func()

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		<-c
		for _, handler := range ProcessShutdownHandlers {
			handler()
		}
		os.Exit(0)
	}()
}
