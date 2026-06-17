package main

import (
	"Scan/internal/ui"

	"github.com/ying32/govcl/vcl"
)

func main() {
	vcl.Application.Initialize()
	vcl.Application.SetMainFormOnTaskBar(true)
	vcl.Application.CreateForm(&ui.MainForm)
	vcl.Application.Run()
}
