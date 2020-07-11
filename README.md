# WAYUU

WAYUU is a blazing fast, lightweight web server and a microframework for building web applications and services.

# Usage
There are two ways of using WAYUU: standalone and embedded configuration. 

Standalone usage allows WAYUU to serve static content. If you are interested in building applications that use the REST API support that is native in WAYUU, you should embed WAYUU in your application.

## Standalone usage

Simply compile the binary and execute it. As standard, you can get a list of CLI options using the `-h` flag.

```
$ ./wayuu -h
USAGE: wayuu [-d] [-b ip_addr] [-p port] [-r root] [-f]
Options:
-d         : Enabled DEBUG mode
-b ip_addr : Bind to IP address. Default: "0.0.0.0"
-p port    : Bind to TCP port. Default: 4443
-r root    : Use root as the root folder for WAYUU. Default: /etc/wayuu
-f         : HTTP mode
```

## Embedded usage

Include the header file `wayuu.h` in your project. 

The WAYUU `Makefile` includes a `lib` target that compiles WAYUU as a static library. 

## Routing

WAYUU implements a very simple routing framework that supports most use cases in a RESTful API implementation. For more details you can refer to the implementation in `router.h` and `router.c`.

A Route is defined by 3 elements:
1. **The URL specification of the route**, in the form `METHOD:PATH`, where `METHOD` is an HTTP Method. Currently the API supports: `GET`, `POST`, `DELETE`. `PATH` is the fragment of the URL that will be matched. WAYUU serves all Router requests from the `/api` endpoint. For instance, the URL specification `GET:/users` will match the HTTP request `GET /api/users`.

2. **The Request Handler**, which is an implementation of the pointer to function `void (*request_handler)(api_request *req)`. This is where the request is properly handled and the response generated and returned. The structure `api_request` is specified in `http_utils.h`. It contains the context of the HTTP request. Implementations can use the utility functions in `http_utils.h` to return standard answers.

3. **The Request Filter**, an optional mechanism that can be used to implement features such as enpoint authentication, security and logging functionality. The request filter is an implementation of the function pointer `bool (*request_filter)(api_request *req)` as specified in `router.h`. If provided, the Router will execute the filter function *before* the request handler. If the filter function returns `true`, the request handler is executed. Otherwise, the request handler is not executed. The filter function must implement appropriate return in case of exception. 

The Route can be added to the Router using the function `void router_add_route(char *matcher, request_handler handler, request_filter filter)`;

# Configuration

By default, WAYUU looks for it's configuration in under `/etc/wayuu`, but you can modify it by passing the root folder with the `-r` CLI option.

The SSL certificates must be placed under the `ssl` folder. By default: `/etc/wayuu/ssl`. WAYUU looks for a `cert.pem` and a `key.pem` file.

# Building

WAYUU uses standard Linux GNU extensions as well as OpenSSL and libcrypto. You can use build WAYUU easily with GCC and Make. 

- `make`: Builds the `wayuu` binary.
- `make test`: Executes the unit tests. 


# Supported platforms

Tested on Ubuntu 18.04+, as well as Debian, and Fedora. 

It should be relatively easy to port WAYUU it to other distribution or Operating Systems, given that WAYUU only uses a minimal set of standard dependencies.