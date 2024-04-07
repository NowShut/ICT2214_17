/*
Package heffalump attempts to encapsulate the original work by carlmjohnson on heffalump
https://github.com/carlmjohnson/heffalump
*/
package heffalump

import (
	"bufio"
	// "io"
	"sync"

	"github.com/yunginnanet/HellPot/internal/config"
)

var log = config.GetLogger()

// DefaultHeffalump represents a Heffalump type
var DefaultHeffalump *Heffalump

// Heffalump represents our buffer pool and markov map from Heffalump
type Heffalump struct {
	pool     *sync.Pool
	buffsize int
	mm       MarkovMap
}

// NewHeffalump instantiates a new Heffalump for markov generation and buffer/io operations
func NewHeffalump(mm MarkovMap, buffsize int) *Heffalump {
	return &Heffalump{
		pool: &sync.Pool{New: func() interface{} {
			b := make([]byte, buffsize)
			return b
		}},
		buffsize: buffsize,
		mm:       mm,
	}
}

// WriteHell writes markov chain heffalump hell to the provided io.Writer
func (h *Heffalump) WriteHell(bw *bufio.Writer) (int64, error) {
	var n int64
	var err error

	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("caller", r).Msg("panic recovered!")
		}
	}()

	buf := h.pool.Get().([]byte)
	defer h.pool.Put(buf)

	if _, err = bw.WriteString("<!DOCTYPE html>"); err != nil {
		return n, err
	}
	// bw.WriteString("<p>Hello World</p>\n</html>")

	bw.WriteString(`
	<html>
	<head>
		<title>Login Page</title>
		<style>
			body {
				font-family: Arial, sans-serif;
				margin: 0;
				padding: 0;
				background-color: #f1f1f1;
			}
			.login-container {
				width: 300px;
				margin: 100px auto;
				padding: 20px;
				background-color: #fff;
				border-radius: 5px;
				box-shadow: 0 2px 4px rgba(0,0,0,0.1);
			}
			input[type="text"],
			input[type="password"],
			input[type="submit"] {
				width: 100%;
				padding: 10px;
				margin-bottom: 10px;
				box-sizing: border-box;
				border: 1px solid #ccc;
				border-radius: 4px;
			}
			input[type="submit"] {
				background-color: #4CAF50;
				color: white;
				border: none;
				cursor: pointer;
			}
			input[type="submit"]:hover {
				background-color: #45a049;
			}
		</style>
	</head>
	<body>
		<div class="login-container">
			<h2>Login</h2>
			<form action="/login" method="post">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required><br>
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required><br>
				<input type="submit" value="Login">
			</form>
		</div>
	</body>
	</html>
	`)

	return n, nil
}

// if _, err = bw.WriteString("<p>Hello World</p>\n</html>"); err != nil {
// 	return n, nil
// }

// if n, err = io.CopyBuffer(bw, h.mm, buf); err != nil {
// 	return n, nil
// }
