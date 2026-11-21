<p align="center">
  <img src="logburr.jpg" alt="logburr" width="720">
</p>

# Logburr

Logs go brrr. Logburr sits in front of the pile and lets you read it.

Point it at a directory of directory-fuzz output. It serves a filterable table on localhost: status, size, words, payload, and the curl for that one row. Repeated responses collapse into buckets. One row can be copied, edited, sent through Burp, or run directly when Burp is not up. The response comes back in the page, highlighted, and you can save it next to the log that produced it.

The page is one Python file. There is no build step and no third-party package.

## Install

Python 3.10 or newer. [curl](https://curl.se/) on `PATH` if you want the Run button. Nothing to install from PyPI.

```bash
git clone https://github.com/glask1d/logburr.git
cd logburr
python3 logburr.py ~/scans/api
```

Open http://127.0.0.1:8877. `requirements.txt` is empty on purpose. `pip install -r requirements.txt` succeeds and installs nothing.

```bash
python3 logburr.py ~/scans/api --check   # parse and print a summary, then exit
python3 logburr.py ~/scans/api -p 9000   # another port
```

The directory argument defaults to the folder that contains `logburr.py`. Pass the folder where the logs actually are. Refresh in the page rescans that folder, so a new report shows up without a restart. Dotfiles are skipped. So are `.py`, `.pyc`, and `.pyo`, which keeps the program from listing itself. Subdirectories are not scanned. Each file is read up to 20 MB.

The sidebar has an import box. Paste a file path or a folder path and press Import. Logburr reads it in place and leaves the file where it is. A folder import follows the same rules as the folder you started in: one level, no dotfiles, no Python files. Refresh picks up new files in an imported folder. The × next to a path drops that import. Saved responses still go in `responses/` under the folder Logburr was started in.

```bash
python3 logburr.py ~/scans/api -i ~/scans/vhosts/gobuster.log
python3 logburr.py ~/scans/api -i ~/scans/vhosts -i ~/other/one.md
```

`-i` can be repeated. The page can add more paths after startup. Those extra paths last until you remove them or stop the process.

Leave the bind address at `127.0.0.1`. `-b 0.0.0.0` would expose Run and Save to anything that can reach the port.

## What it reads

| Tool | What Logburr looks for |
| --- | --- |
| ffuf | A markdown report (`-of md`). The command is the backticked line. `&#34;` is turned back into a quote. `FUZZ` in the URL, in `-H` headers, and in a `-d` body is filled per row. |
| feroxbuster | A `Configuration` block (`target_url`, `wordlist`) plus hit lines: status, method, lines, words, bytes, URL, optional redirect. |
| gobuster | A `Url:` line and `Found:` / `(Status: NNN)` lines, with optional size and redirect. |
| dirsearch | Lines shaped like `200  1234B  /path -> /other`. `KB`, `MB`, and `GB` are scaled. |
| anything else | No hits. The page shows the first 80 lines so you can see why. |

ffuf stores `os.Args` after the shell has already eaten quotes. A body written as `-d "{"url":"http://FUZZ"}"` is saved without the inner quotes, and the copied curl will match that. Use `-d '{"url":"http://FUZZ"}'` if you want the quotes in the report.

## The table

The file with the most hits opens first. The sidebar is every other log in the directory.

- Search matches status, method, path, payload, URL, redirect, content type, and the raw line. `/` focuses the box.
- Status classes are toggles. Turn 404s off without hiding 200s.
- **Hide groups of N** (default 5) drops any response signature that shows up at least N times. A signature is status, size, word count, line count, and content type.
- Buckets sit above the table. A bucket shows the count, a short size line, and up to three sample values. Click a sample to search that value and isolate the bucket. Click the bucket itself to isolate the whole group. Click the unique chip for the rows that appear once.
- A payload column appears when a row has a body that is not already the path. It stays narrow.
- Click a row, or press Enter, for labeled fields: curl, payload, url, fuzz, redirect, position, status, size, words, lines, type, time, hash. Empty fields are skipped.
- Sort starts at rarest signature first.

### Keys

| Key | Action |
| --- | --- |
| `/` | Search |
| `j` `k` or arrows | Move the selection |
| Enter | Open or close the raw fields |
| `c` or `y` | Copy the URL |
| `x` | Copy curl |
| `b` | Send to Burp |
| `r` | Run directly |
| `h` | Toggle hide-repeats |
| Escape | Clear the isolate filter and close the open row |

`c`, `y`, `x`, `b`, and `r` do nothing when Ctrl, Meta, or Alt is held, and they do nothing while text is selected. Ctrl+C still copies what you highlighted. Typing in the search box, the editor, or the save-name field does not trigger these keys.

## One request

Select a row.

**Copy cURL** (`x`) copies a one-line curl. HTTPS gets `-k`. GET omits `-X`. Other methods get `-X`, one `-H` per header, and `-d` when there is a body. Headers that contained `FUZZ` are filled with that row's value.

**Send to Burp** (`b`) checks that something is listening on `127.0.0.1:8080`, then sends the same request through that proxy with TLS verification off. Host, Content-Length, Connection, and Transfer-Encoding are left for Burp to set. If Burp still has the request after a few seconds, the toast says it is waiting in Intercept. The forward itself is allowed 180 seconds, so an intercept-on proxy is not aborted early. Nothing is listening, and you get that message instead of a hang.

**Run** (`r`) is the same request with Burp out of the path. Logburr calls `curl` as a fixed argument list, never through a shell:

```text
curl -skS --noproxy * -D - --max-time 30 -X METHOD URL
```

`--noproxy *` keeps the request off a local proxy. `-D -` prints the response headers in front of the body. Redirects are not followed. The wait is 30 seconds. Output longer than 500 KB is cut. The box under the table shows the status line, header names, and a pretty-printed JSON body when the body is JSON. HTML tags are marked too. **Hide response** collapses the box and leaves the bar.

**Edit** opens the request as text before Run, Burp, or Copy cURL:

```text
POST https://host/path
Content-Type: application/json

{"url":"http://127.0.0.1"}
```

The first line is the method and an `http` or `https` URL. Headers follow. A blank line starts the body. Untick Edit and the text is thrown away. The next tick loads the row from the log again. Changing rows while Edit is ticked loads that row's original request.

**Save** writes the text you are looking at, including the pretty-printed JSON, to `responses/` inside the log directory. The name is filled from the payload. It has to be a plain filename such as `ip6-localhost.http`. Allowed suffixes are `.txt`, `.json`, `.http`, `.log`, `.md`, and `.html`. Anything else gets `.txt`. Names with a path, a leading dot, or a symlink are refused. The file has to stay inside `responses/`. The cap is 2 MB. The folder is created on the first save.

## Safety

- The default listen address is loopback.
- Run and Burp only accept `http` and `https` URLs, and they drop header lines that contain a carriage return or a newline.
- Run does not invoke a shell. The curl string in the page is for the clipboard. The process builds its own argv.
- Save cannot leave the log directory.
- Copy, Run, and Burp happen when you press the button. Opening the page does not send traffic to the hosts in the logs.

Do not commit the logs or `responses/`. Those are the engagement. `.gitignore` already ignores `responses/` and bytecode.

## Layout

```text
logburr.py         the server and the page
logburr.jpg        the logo
requirements.txt   empty
README.md
.gitignore
```

Logburr is released under the MIT license. See `LICENSE`.
