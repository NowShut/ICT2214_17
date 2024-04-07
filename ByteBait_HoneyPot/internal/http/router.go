package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"sync"

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
func predictAttackType(logEntry map[string]string) string {
	// Convert logEntry map to JSON
	jsonBytes, err := json.Marshal(logEntry)
	if err != nil {
		log.Error().Str("error", err.Error()).Msg("Error marshalling logEntry to JSON")
		return "Error in prediction"
	}

	// Execute the Python script, passing the JSON string via stdin
	cmd := exec.Command("python", "../../predict.py")
	cmd.Stdin = bytes.NewReader(jsonBytes) // Pass JSON as stdin
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Str("error", err.Error()).Msg("Error executing predictAttackType")
		return "Error in prediction"
	}

	// Assuming the output from your Python script is the prediction result
	return string(output)
}
func dashboardHandler(ctx *fasthttp.RequestCtx) {
	dashboardHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .log { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }
        .log-key { font-weight: bold; }
    </style>
</head>
<body>
    <h2>Dashboard</h2>
    <div id="logContainer"></div>

	<script>
	let lastTimestamp = 0;
	
	function fetchLogs() {
		fetch("/logs/updates?lastTimestamp=" + lastTimestamp)
			.then(response => response.json())
			.then(data => {
				const container = document.getElementById("logContainer");
				data.forEach(log => {
					const logDiv = document.createElement("div");
					logDiv.classList.add("log");
	
					Object.keys(log).forEach(key => {
						if (key !== "timestamp") {
							const p = document.createElement("p");
							const keySpan = document.createElement("span");
							keySpan.textContent = key + ": ";
							keySpan.style.fontWeight = "bold";
							p.appendChild(keySpan);
	
							// Create a text node for safe text rendering
							const valueText = document.createTextNode(log[key]);
							p.appendChild(valueText);
	
							logDiv.appendChild(p);
						}
					});
	
					container.appendChild(logDiv);
	
					// Update lastTimestamp with the latest log's timestamp
					if (log.timestamp > lastTimestamp) {
						lastTimestamp = log.timestamp;
					}
				});
			})
			.catch(err => console.error("Failed to fetch logs:", err));
	
		// Fetch new logs every 5 seconds
		setTimeout(fetchLogs, 5000);
	}
	
	// Initial fetch
	fetchLogs();
	</script>
	

</body>
</html>`

	ctx.SetContentType("text/html")
	ctx.SetBodyString(dashboardHTML)
}

var (
	logs     []map[string]interface{}
	logMutex sync.Mutex
)

func appendLog(logEntry map[string]interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// Adding a timestamp to each log entry
	logEntry["timestamp"] = time.Now().Unix()
	logs = append(logs, logEntry)
}

func logsUpdateHandler(ctx *fasthttp.RequestCtx) {
	// Extracting the last timestamp received by the client
	lastTimestampParam := string(ctx.QueryArgs().Peek("lastTimestamp"))
	lastTimestamp, _ := strconv.ParseInt(lastTimestampParam, 10, 64)

	var newLogs []map[string]interface{}

	logMutex.Lock()
	for _, logEntry := range logs {
		if logEntryTimestamp, ok := logEntry["timestamp"].(int64); ok && logEntryTimestamp > lastTimestamp {
			newLogs = append(newLogs, logEntry)
		}
	}
	logMutex.Unlock()

	updatedLogs, _ := json.Marshal(newLogs)

	ctx.SetContentType("application/json")
	ctx.SetBody(updatedLogs)
}

func hellPot(ctx *fasthttp.RequestCtx) {
	path, pok := ctx.UserValue("path").(string)
	if len(path) < 1 || !pok {
		path = "/"
	}

	remoteAddr := getRealRemote(ctx)
	userAgent := string(ctx.UserAgent())
	uri := string(ctx.RequestURI())
	method := string(ctx.Method())
	log.Info().
		Str("USERAGENT", userAgent).
		Str("REMOTE_ADDR", remoteAddr).
		Str("URL", uri).
		Str("METHOD", method).
		Msg("Request received")

	// Construct log entry as a map to hold necessary information
	logEntryMap := map[string]string{
		"REMOTE_ADDR": remoteAddr,
		"USERAGENT":   userAgent,
	}
	// This map is for dashboard logging
	logEntryForDashboard := map[string]interface{}{
		"REMOTE_ADDR": remoteAddr,
		"USERAGENT":   userAgent,
		"URL":         uri,
		"METHOD":      method,
	}

	// Dynamically add fields based on the request URI
	switch string(ctx.RequestURI()) {
	case "/wp-login":
		logEntryMap["USERNAME"] = string(ctx.Request.PostArgs().Peek("username"))
		logEntryMap["PASSWORD"] = string(ctx.Request.PostArgs().Peek("password"))
		// Add the same fields for dashboard logging
		logEntryForDashboard["USERNAME"] = logEntryMap["USERNAME"]
		logEntryForDashboard["PASSWORD"] = logEntryMap["PASSWORD"]
	case "/forum.php":
		logEntryMap["TITLE"] = string(ctx.Request.PostArgs().Peek("postTitle"))
		logEntryMap["CONTENT"] = string(ctx.Request.PostArgs().Peek("postContent"))
		// Add the same fields for dashboard logging
		logEntryForDashboard["TITLE"] = logEntryMap["TITLE"]
		logEntryForDashboard["CONTENT"] = logEntryMap["CONTENT"]
	default:
		logEntryMap["URL"] = string(ctx.RequestURI()) // General case for other URLs
	}

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

	// Prediction Logic (assuming you have a function that handles this)
	prediction := predictAttackType(logEntryMap)
	log.Info().Msgf("Predicted Attack Type: %s", prediction)

	// Append log entry for dashboard
	logEntryForDashboard["Prediction"] = prediction
	appendLog(logEntryForDashboard)

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
	// Updated to ensure every request is handled by hellPot, thereby logging all attempts
	r.ANY("/{path:*}", hellPot) // Using r.ANY to catch all HTTP methods
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
	r.GET("/dashboard", dashboardHandler)     // Endpoint for serving dashboard HTML
	r.GET("/logs/updates", logsUpdateHandler) // Endpoint for serving log updates

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
