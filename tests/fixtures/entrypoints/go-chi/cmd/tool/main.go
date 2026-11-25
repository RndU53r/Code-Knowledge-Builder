package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tool",
	Short: "demo",
	Run:   runTool,
}

func runTool(cmd *cobra.Command, args []string) {
	fmt.Println(os.Args)
}

func main() { rootCmd.Execute() }
