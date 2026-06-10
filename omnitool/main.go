package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Création de l'application
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "OmniTool",
		Width:     1200,
		Height:    800,
		Frameless: true, // LA MAGIE EST ICI : Fait disparaître la bordure Windows !
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 5, G: 5, B: 6, A: 255},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
