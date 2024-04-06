package http

import (
	"fmt"
	"net/http"

	// "net/http"
	"runtime"
	"strings"
	"time"

	// "time"

	"github.com/fasthttp/router"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"

	// "github.com/yunginnanet/HellPot/heffalump"
	"github.com/yunginnanet/HellPot/internal/config"
)

var log *zerolog.Logger

func getRealRemote(ctx *fasthttp.RequestCtx) string {
	xrealip := string(ctx.Request.Header.Peek(config.HeaderName))
	if len(xrealip) > 0 {
		return xrealip
	}
	return ctx.RemoteIP().String()

}

func hellPot(ctx *fasthttp.RequestCtx) {
	path, pok := ctx.UserValue("path").(string)
	if len(path) < 1 || !pok {
		path = "/"
	}

	remoteAddr := getRealRemote(ctx)
	if string(ctx.RequestURI()) == "/wp-login" {
		slog := log.With().
			Str("USERAGENT", string(ctx.UserAgent())).
			Str("REMOTE_ADDR", remoteAddr).
			Interface("URL", string(ctx.RequestURI())).
			Str("METHOD", string(ctx.Method()[:])).
			Str("USERNAME", string(ctx.Request.PostArgs().Peek("username"))).
			Str("PASSWORD", string(ctx.Request.PostArgs().Peek("password"))).Logger()
		slog.Info().Msg("NEW")
	}
	if string(ctx.RequestURI()) == "/forum.php" {
		slog := log.With().
			Str("USERAGENT", string(ctx.UserAgent())).
			Str("REMOTE_ADDR", remoteAddr).
			Interface("URL", string(ctx.RequestURI())).
			Str("METHOD", string(ctx.Method()[:])).
			Str("TITLE", string(ctx.Request.PostArgs().Peek("postTitle"))).
			Str("CONTENT", string(ctx.Request.PostArgs().Peek("postContent"))).Logger()
		slog.Info().Msg("NEW")
	} else {
		slog := log.With().
			Str("USERAGENT", string(ctx.UserAgent())).
			Str("REMOTE_ADDR", remoteAddr).
			Interface("URL", string(ctx.RequestURI())).
			Str("METHOD", string(ctx.Method()[:])).Logger()
		slog.Info().Msg("NEW")
		for _, denied := range config.UseragentBlacklistMatchers {
			if strings.Contains(string(ctx.UserAgent()), denied) {
				slog.Trace().Msg("Ignoring useragent")
				ctx.Error("Not founds", http.StatusNotFound)
				return
			}
		}

		if config.Trace {
			slog = slog.With().Str("caller", path).Logger()
		}

		slog.Info().Msg("NEW")

	}

	// Get Request url and remove any get parameters that are appended.
	reqUrlString := string(ctx.RequestURI())
	ctx.SetContentType("text/html")

	//TODO The form method for the below 2 html forms.
	if reqUrlString == "/wp-login" {
		ctx.SetBodyString(`
	<!DOCTYPE html>
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
        .navbar {
            background-color: #333;
            overflow: hidden;
        }
        .navbar a {
            float: left;
            display: block;
            color: white;
            text-align: center;
            padding: 14px 20px;
            text-decoration: none;
        }
        .navbar a:hover {
            background-color: #ddd;
            color: black;
        }
        .content {
            padding: 20px;
        }
        .login-container {
            width: 300px;
            margin: 50px auto;
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
    <div class="navbar">
        <a href="/wp-login.php">Home</a>
        <a href="/forum.php">Forum</a>
    </div>
    <div class="content">
        <div class="login-container">
            <h2>Login</h2>
            <form action="/wp-login" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br>
                <input type="submit" value="Login">
            </form>
        </div>
    </div>
</body>
</html>
	`)
	}
	if reqUrlString == "/forum.php" {
		ctx.SetBodyString(
			`
		<!DOCTYPE html>
<html>
<head>
    <title>Simple Forum</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f1f1f1;
        }
        .navbar {
            background-color: #333;
            overflow: hidden;
        }
        .navbar a {
            float: left;
            display: block;
            color: white;
            text-align: center;
            padding: 14px 20px;
            text-decoration: none;
        }
        .navbar a:hover {
            background-color: #ddd;
            color: black;
        }
        .content {
            padding: 20px;
        }
        .post {
            background-color: #fff;
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .post-title {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .post-content {
            font-size: 16px;
        }
        .post-footer {
            font-size: 14px;
            color: #666;
            margin-top: 10px;
        }
        .form-container {
            background-color: #fff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        input[type="text"],
        textarea,
        input[type="submit"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        textarea {
            height: 100px;
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
    <div class="navbar">
        <a href="/wp-login">Home</a>
        <a href="/forum.php">Forum</a>
    </div>
    <div class="content">
	<div style="color: red;">You need to be logged in to post.</div>
        <div class="form-container">
            <h2>Create a New Post</h2>
            <form action="/forum.php" method="POST">
                <label for="postTitle">Title:</label>
                <input type="text" id="postTitle" name="postTitle" required><br>
                <label for="postContent">Content:</label>
                <textarea id="postContent" name="postContent" required></textarea><br>
                <input type="submit" value="Submit">
            </form>
        </div>
        <div class="post">
            <div class="post-title">First Post</div>
            <div class="post-content">
                This is the content of the first post in the forum. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla euismod justo nec orci blandit, at venenatis justo volutpat.
            </div>
            <div class="post-footer">
                Posted by John Doe on 2022-04-06
            </div>
        </div>
        <div class="post">
            <div class="post-title">Second Post</div>
            <div class="post-content">
                This is the content of the second post in the forum. Sed quis leo ullamcorper, fringilla metus vel, finibus justo. Integer condimentum vestibulum sem, vel volutpat libero ultricies nec.
            </div>
            <div class="post-footer">
                Posted by Jane Smith on 2022-04-07
            </div>
        </div>
    </div>
</body>
</html>
		`)
	}
}

func getSrv(r *router.Router) fasthttp.Server {
	if !config.RestrictConcurrency {
		config.MaxWorkers = fasthttp.DefaultConcurrency
	}

	log = config.GetLogger()

	return fasthttp.Server{
		// User defined server name
		// Likely not useful if behind a reverse proxy without additional configuration of the proxy server.
		Name: config.FakeServerName,

		/*
			from fasthttp docs: "By default request read timeout is unlimited."
			My thinking here is avoiding some sort of weird oversized GET query just in case.
		*/
		ReadTimeout:        5 * time.Second,
		MaxRequestBodySize: 1 * 1024 * 1024,

		// Help curb abuse of HellPot (we've always needed this badly)
		MaxConnsPerIP:      10,
		MaxRequestsPerConn: 2,
		Concurrency:        config.MaxWorkers,

		// only accept GET requests
		// TODO This already set to false but not working
		GetOnly: false,

		// we don't care if a request ends up being handled by a different handler (in fact it probably will)
		KeepHijackedConns: true,

		CloseOnShutdown: true,

		// No need to keepalive, our response is a sort of keep-alive ;)
		DisableKeepalive: true,

		Handler: r.Handler,
		Logger:  log,
	}
}

// Serve starts our HTTP server and request router
func Serve() error {
	log = config.GetLogger()
	l := config.HTTPBind + ":" + config.HTTPPort

	r := router.New()

	if config.MakeRobots && !config.CatchAll {
		r.GET("/robots.txt", robotsTXT)
	}

	if !config.CatchAll {
		for _, p := range config.Paths {
			log.Trace().Str("caller", "router").Msgf("Add route: %s", p)
			r.GET(fmt.Sprintf("/%s", p), hellPot)
			r.POST(fmt.Sprintf("/%s", p), hellPot)
		}
	} else {
		log.Trace().Msg("Catch-All mode enabled...")
		r.GET("/{path:*}", hellPot)
	}

	srv := getSrv(r)

	//goland:noinspection GoBoolExpressions
	if !config.UseUnixSocket || runtime.GOOS == "windows" {
		log.Info().Str("caller", l).Msg("Listening and serving HTTP Pies...")
		return srv.ListenAndServe(l)
	}

	if len(config.UnixSocketPath) < 1 {
		log.Fatal().Msg("unix_socket_path configuration directive appears to be empty")
	}

	log.Info().Str("caller", config.UnixSocketPath).Msg("Listening and serving HTTP...")
	return listenOnUnixSocket(config.UnixSocketPath, r)
}
