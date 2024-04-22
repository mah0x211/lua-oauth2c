--
-- Copyright (C) 2024-present Masatoshi Fukunaga
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
local is_str = require('lauxhlib.is').str
local is_table = require('lauxhlib.is').table
local is_uint = require('lauxhlib.is').uint
local errorf = require('error').format
local decode_json = require('yyjson').decode
local new_request = require('oauth2c.request')

--
-- http://tools.ietf.org/html/rfc6749#section-4.1.3
-- 4.1.3.  Access Token Request
--
--  The client makes a request to the token endpoint by sending the
--  following parameters using the "application/x-www-form-urlencoded"
--  format per Appendix B with a character encoding of UTF-8 in the HTTP
--  request entity-body:
--
--  grant_type
--        REQUIRED.  Value MUST be set to "authorization_code".
--
--  code
--        REQUIRED.  The authorization code received from the
--        authorization server.
--
--  redirect_uri
--        REQUIRED, if the "redirect_uri" parameter was included in the
--        authorization request as described in Section 4.1.1, and their
--        values MUST be identical.
--
--  client_id
--        REQUIRED, if the client is not authenticating with the
--        authorization server as described in Section 3.2.1.
--
--  If the client type is confidential or the client was issued client
--  credentials (or assigned other authentication requirements), the
--  client MUST authenticate with the authorization server as described
--  in Section 3.2.1.
--
--  For example, the client makes the following HTTP request using TLS
--  (with extra line breaks for display purposes only):
--
--    POST /token HTTP/1.1
--    Host: server.example.com
--    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
--    Content-Type: application/x-www-form-urlencoded
--
--    grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
--    &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
--
--  The authorization server MUST:
--
--  o  require client authentication for confidential clients or for any
--     client that was issued client credentials (or with other
--     authentication requirements),
--
--  o  authenticate the client if client authentication is included,
--
--  o  ensure that the authorization code was issued to the authenticated
--     confidential client, or if the client is public, ensure that the
--     code was issued to "client_id" in the request,
--
--  o  verify that the authorization code is valid, and
--
--  o  ensure that the "redirect_uri" parameter is present if the
--     "redirect_uri" parameter was included in the initial authorization
--     request as described in Section 4.1.1, and if included ensure that
--     their values are identical.
--
--- @class oauth2c.access_token.request.params : oauth2c.request.params
--- @field grant_type string @ REQUIRED. Value MUST be set to "authorization_code".
--- @field code string @ REQUIRED. The authorization code received from the authorization server.
--- @field redirect_uri string @ REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.
--- @field client_id string @ REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.
--- @field client_secret string @ REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.

--- @class oauth2c.access_token.request : oauth2c.request
--- @field uri string @ token endpoint URI
--- @field params oauth2c.access_token.request.params

--- create_request
--- @param uri string @ token endpoint URI
--- @param code string @ The authorization code received from the authorization server.
--- @param redirect_uri string @ REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.
--- @param client_id string @ REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.
--- @param client_secret string @ REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.
--- @return oauth2c.access_token.request req
local function create_request(uri, code, redirect_uri, client_id, client_secret)
    assert(is_str(uri), 'uri must be string')
    assert(is_str(code), 'code must be string')
    assert(is_str(redirect_uri), 'redirect_uri must be string')
    assert(is_str(client_id), 'client_id must be string')
    assert(is_str(client_secret), 'client_secret must be string')

    return new_request(uri, {
        grant_type = 'authorization_code',
        code = code,
        redirect_uri = redirect_uri,
        client_id = client_id,
        client_secret = client_secret,
    })
end

--
-- http://tools.ietf.org/html/rfc6749#section-4.1.4
-- 4.1.4.  Access Token Response
--
--   If the access token request is valid and authorized, the
--   authorization server issues an access token and optional refresh
--   token as described in Section 5.1.  If the request client
--   authentication failed or is invalid, the authorization server returns
--   an error response as described in Section 5.2.
--
--
-- http://tools.ietf.org/html/rfc6749#section-5.1
-- 5.1.  Successful Response
--
--   The authorization server issues an access token and optional refresh
--   token, and constructs the response by adding the following parameters
--   to the entity-body of the HTTP response with a 200 (OK) status code:
--
--   access_token
--         REQUIRED.  The access token issued by the authorization server.
--
--   token_type
--         REQUIRED.  The type of the token issued as described in
--         Section 7.1.  Value is case insensitive.
--
--   expires_in
--         RECOMMENDED.  The lifetime in seconds of the access token.  For
--         example, the value "3600" denotes that the access token will
--         expire in one hour from the time the response was generated.
--         If omitted, the authorization server SHOULD provide the
--         expiration time via other means or document the default value.
--
--   refresh_token
--         OPTIONAL.  The refresh token, which can be used to obtain new
--         access tokens using the same authorization grant as described
--         in Section 6.
--
--   scope
--         OPTIONAL, if identical to the scope requested by the client;
--         otherwise, REQUIRED.  The scope of the access token as
--         described by Section 3.3.
--
--   The parameters are included in the entity-body of the HTTP response
--   using the "application/json" media type as defined by [RFC4627].  The
--   parameters are serialized into a JavaScript Object Notation (JSON)
--   structure by adding each parameter at the highest structure level.
--   Parameter names and string values are included as JSON strings.
--   Numerical values are included as JSON numbers.  The order of
--   parameters does not matter and can vary.
--
--   The authorization server MUST include the HTTP "Cache-Control"
--   response header field [RFC2616] with a value of "no-store" in any
--   response containing tokens, credentials, or other sensitive
--   information, as well as the "Pragma" response header field [RFC2616]
--   with a value of "no-cache".
--
--   For example:
--
--     HTTP/1.1 200 OK
--     Content-Type: application/json;charset=UTF-8
--     Cache-Control: no-store
--     Pragma: no-cache
--
--     {
--       "access_token":"2YotnFZFEjr1zCsicMWpAA",
--       "token_type":"example",
--       "expires_in":3600,
--       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
--       "example_parameter":"example_value"
--     }
--
--   The client MUST ignore unrecognized value names in the response.  The
--   sizes of tokens and other values received from the authorization
--   server are left undefined.  The client should avoid making
--   assumptions about value sizes.  The authorization server SHOULD
--   document the size of any value it issues.
--

--- @class oauth2c.access_token.response
--- @field access_token string @ REQUIRED. The access token issued by the authorization server.
--- @field token_type string @ REQUIRED. The type of the token issued as described in Section 7.1. Value is case insensitive.
--- @field expires_in number @ RECOMMENDED. The lifetime in seconds of the access token.
--- @field refresh_token string @ OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in Section 6.
--- @field scope string @ OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope of the access token as described by Section 3.3.

--- verify_response
--- @param response table|string
--- @return oauth2c.access_token.response|oauth2c.error_response? res
--- @return any err
local function verify_response(response)
    local res
    if not is_str(response) then
        assert(is_table(response), 'response must be table or string')
        res = response --- @type table
    else
        local json, err = decode_json(response)
        if not json then
            return nil, errorf('failed to decode response as JSON: %s', err)
        end
        res = json --- @type table
    end

    if res.error then
        return res
    elseif res.access_token == nil then
        return nil, errorf('no access_token field in response')
    elseif not is_str(res.access_token) then
        return nil, errorf('access_token field in response is not string')
    elseif res.token_type == nil then
        return nil, errorf('no token_type field in response')
    elseif not is_str(res.token_type) then
        return nil, errorf('token_type field in response is not string')
    elseif res.expires_in ~= nil and not is_uint(res.expires_in) then
        return nil,
               errorf('expires_in field in response is not unsigned integer')
    elseif res.refresh_token ~= nil and not is_str(res.refresh_token) then
        return nil, errorf('refresh_token field in response is not string')
    elseif res.scope ~= nil and not is_str(res.scope) then
        return nil, errorf('scope field in response is not string')
    end
    return res
end

return {
    request = create_request,
    response = verify_response,
}
