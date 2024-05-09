# lua-oauth2c

[![test](https://github.com/mah0x211/lua-oauth2c/actions/workflows/test.yml/badge.svg)](https://github.com/mah0x211/lua-oauth2c/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/mah0x211/lua-oauth2c/branch/master/graph/badge.svg)](https://codecov.io/gh/mah0x211/lua-oauth2c)

OAuth2 client library for lua.

## Installation

```
luarocks install oauth2c
```

***

## o = oauth2c( params )

creating an instance of the oauth2c object.

**Parameters**

- `params:table`: a table that contains the following fields:
    - `client_id:string`: client id.
    - `client_secret:string`: client secret.
    - `authz_uri:string`: authorization uri.
    - `token_uri:string`: token uri.
    - `redirect_uri:string`: redirect uri.

**Returns**

- `o:oauth2c`: an instance of the oauth2c object.

**Usage**

```lua
local oauth2c = require('oauth2c')
local o = oauth2c.new({
    client_id = 'your-client-id',
    client_secret = 'your-client-secret',
    authz_uri = 'https://example.com/authorize',
    token_uri = 'https://example.com/token',
    redirect_uri = 'https://example.com/callback',
})
```


## ok, err = oauth2c:set_tokens( tokens )

set the access token and related information to the oauth2c object.

**Parameters**

- `tokens:table`: a table that contains the following fields:
    - `access_token:string`: access token. (required)
    - `token_type:string`: token type. (required)
    - `expires_in:integer`: the lifetime in seconds of the access token. (optional)
    - `refresh_token:string`: refresh token. (optional)
    - `scope:string`: the scope of the access token. (optional)

**Returns**

- `ok:boolean`: `true` if successful, otherwise `false`.
- `err:any`: an error message.

**NOTE**

the token information is automatically updated when the `oauth2c:verify_access_token_response()` method is successfully called, and response contains the access token.


## tokens = oauth2c:get_tokens()

get the access token and related information from the oauth2c object.  
if the access token is not set, it returns `nil`.

**Returns**

- `tokens:table`: a table that contains the following fields:
    - `access_token:string`: access token.
    - `token_type:string`: token type.
    - `expires_in:integer`: the lifetime in seconds of the access token.
    - `refresh_token:string`: refresh token.
    - `scope:string`: the scope of the access token.


## header = oauth2c:create_authorization_header()

create an value of authorization header that contains the access token.

**Returns**

- `header:string?`: a value of the authorization header, or `nil` if both the access token and the token type are not set.

**Usage**

```lua
print(o:create_authorization_header()) -- "Bearer xxxxxxxx"
```


## req = oauth2c:create_authorization_request( [scope [, state]] )

create an authorization request object.

**Parameters**

- `scope:string`: the scope of the access request.
- `state:string`: a random string that used to protect against cross-site request forgery.

**Returns**

- `req:oauth2c.request`: a [request object](#oauth2crequest) that contains the following fields:
    - `uri:string`: the authorization uri.
    - `params:table`: a table that contains the following fields:
        - `response_type:string`: the response type. (it is always `code`)
        - `client_id:string`: client id.
        - `redirect_uri:string`: redirect uri.
        - `scope:string`: the scope of the access request that specified by the `scope` argument.
        - `state:string`: a random string that same as the `state` field of the parent object.

**Usage**

```lua
local dump = require('dump')
local req = o:create_authorization_request('read write', '1ME5p04YcJOVM6hO')
print('Authorization Request:', dump(req))
-- Authorization Request: {
--     _NAME = "oauth2c.request",
--     _PACKAGE = "oauth2c.request",
--     _STRING = "oauth2c.request: 0x600001b4bc00",
--     params = {
--         client_id = "your-client-id",
--         redirect_uri = "https://example.com/callback",
--         response_type = "code",
--         scope = "read write",
--         state = "1ME5p04YcJOVM6hO"
--     },
--     uri = "https://example.com/authorize"
-- }
```


## res, err = oauth2c:verify_authorization_response_query( query [, state] )

verify the authorization response.  
please refer to the following document for the authorization response.

- https://tools.ietf.org/html/rfc6749#section-4.1.2

**Parameters**

- `query:string|table`: a query string or a table that contains the following fields:
    - `code:string`: the authorization code.
    - `state:string`: a random string that compared with the specified `state` argument.
- `state:string`: a random string that same as the `state` field of the request object that created by the `oauth2c:create_authorization_request()` method.

**Returns**

- `res:table`: a table that same as the `query` argument, or a table of the parsed query string.

**NOTE**

if the `error` field is not found in the response, update the `code` field of oauth2c object with the `code` field of the response.

**Usage**

```lua
local dump = require('dump')
local res, err = o:verify_authorization_response_query(resp.query, state)
if not res then
    print('Authorization Response Verification Failed:', err)
    return
elseif res.error then
    print('Authorization Response Error:', dump(res))
    return
end
print('Authorization Response:', dump(res))
-- Authorization Response: {
--     code = "auth-code",
--     state = "qyFNoWGp8wTcdS5L"
-- }
```


## req, err = oauth2c:create_access_token_request()

create an access token request object.

**Returns**

- `req:oauth2c.request`: a request object that contains the following fields:
    - `uri:string`: the token uri.
    - `params:table`: a table that contains the following fields:
        - `grant_type:string`: the grant type. (it is always `authorization_code`)
        - `code:string`: the authorization code that obtained by the `oauth2c:verify_authorization_response_query()` method.
        - `redirect_uri:string`: redirect uri.
        - `client_id:string`: client id.
        - `client_secret:string`: client secret.
- `err:any`: an error message.

**Usage**

```lua
local req, err = o:create_access_token_request()
if err then
    print(err)
    return
end
print('Access Token Request:', dump(req))
-- Access Token Request: {
--     _NAME = "oauth2c.request",
--     _PACKAGE = "oauth2c.request",
--     _STRING = "oauth2c.request: 0x60000215f740",
--     params = {
--         client_id = "your-client-id",
--         client_secret = "your-client-secret",
--         code = "auth-code",
--         grant_type = "authorization_code",
--         redirect_uri = "https://example.com/callback"
--     },
--     uri = "https://example.com/token"
-- }
```


## res, err = oauth2c:verify_access_token_response( resp )

verify the access token response.

**Parameters**

- `resp:string|table`: a JSON string or a table that contains the following fields:
    - `access_token:string`: access token. (required)
    - `token_type:string`: token type. (required)
    - `expires_in:integer`: the lifetime in seconds of the access token. (optional)
    - `refresh_token:string`: refresh token. (optional)
    - `scope:string`: the scope of the access token. (optional)

**Returns**

- `res:table`: a table that same as the `resp` argument, or a table of the parsed JSON string.
- `err:any`: an error message.

**NOTE**

if the `error` field is not found in the response, update the access token information of the oauth2c object with the response.

**Usage**

```lua
local dump = require('dump')
local res, err = o:verify_access_token_response(resp)
if err then
    print(err)
    return
end
print('Access Token Response:', dump(res))
-- Access Token Response: {
--     access_token = "xxxxx",
--     token_type = "Bearer",
--     expires_in = 3600,
--     refresh_token = "yyyyy",
--     scope = "read write",
-- }
```


## oauth2c.request

the `oauth2c.request` object that created by the `oauth2c:create_authorization_request()` method or the `oauth2c:create_access_token_request()` method.

the object has the following fields.

- `uri:string`: the endpoint uri.
- `params:table`: a table that contains the parameters of the request.

And the following methods are available.


## uri = request:encode_uri()

encode the request object to the uri string.

**Returns**

- `uri:string`: the uri string.

**Usage**

```lua
local req = o:create_authorization_request('read write', '1ME5p04YcJOVM6hO')
print(req:encode_uri())
-- "https://example.com/authorize?client_id=your-client-id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code&scope=read+write&state=1ME5p04YcJOVM6hO"
```


## params = request:encode_params()

encode the `params` field of the request object to the string in `application/x-www-form-urlencoded` format.

**Returns**

- `params:string`: the encoded string in `application/x-www-form-urlencoded` format.

**Usage**

```lua
local req = o:create_authorization_request('read write', '1ME5p04YcJOVM6hO')
print(req:encode_params())
-- "client_id=your-client-id&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code&scope=read+write&state=1ME5p04YcJOVM6hO"
```

## params, err = req:encode_params_json()

encode the `params` field of the request object to the JSON string.

**Returns**

- `params:string`: the JSON string.
- `err:any`: an error message.

**Usage**

```lua
local req = o:create_access_token_request()
local params, err = req:encode_params_json()
if err then
    print(err)
    return
end
print(params)
-- {"client_id":"your-client-id","client_secret":"your-client-secret","code":"auth-code","grant_type":"authorization_code","redirect_uri":"https://example.com/callback"}
```


## License

MIT License
