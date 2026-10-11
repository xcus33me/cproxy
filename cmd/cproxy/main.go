package main

import (
	"cproxy/internal/app"
	"os"
)

func main() { os.Exit(app.Run(os.Args[1:])) }
