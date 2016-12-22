package main

import (
	"fmt"
)

type Worker struct {

}

type Scanner struct {
	NumWorkers uint
	Workers *Worker
}

func NewScanner(nworkers uint) *Scanner {
	return &Scanner {
		NumWorkers: nworkers
	}
}

func main() {
	for i := 1 ; i <= 10; i++ {
		fmt.Println(i)
	}
	fmt.Println("Hello, World!")
	s := new(Scanner)
}
