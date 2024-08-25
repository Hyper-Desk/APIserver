package main

import (
	_ "hyperdesk/docs"
	"hyperdesk/routes"
)

func main() {
	routes.Run(":8080")
}
