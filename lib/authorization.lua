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
local find = string.find
local pairs = pairs
local is_str = require('lauxhlib.is').str
local is_table = require('lauxhlib.is').table
local parse_uri = require('url').parse
local errorf = require('error').format
local new_request = require('oauth2c.request')

--
-- https://tools.ietf.org/html/rfc6749#section-4.1.1
-- 4.1.1.  Authorization Request
--
--  The client constructs the request URI by adding the following
--  parameters to the query component of the authorization endpoint URI
--  using the "application/x-www-form-urlencoded" format, per Appendix B:
--
--  response_type
--        REQUIRED.  Value MUST be set to "code".
--
--  client_id
--        REQUIRED.  The client identifier as described in Section 2.2.
--
--  redirect_uri
--        OPTIONAL.  As described in Section 3.1.2.
--
--  scope
--        OPTIONAL.  The scope of the access request as described by
--        Section 3.3.
--
--  state
--        RECOMMENDED.  An opaque value used by the client to maintain
--        state between the request and callback.  The authorization
--        server includes this value when redirecting the user-agent back
--        to the client.  The parameter SHOULD be used for preventing
--        cross-site request forgery as described in Section 10.12.
--
--  The client directs the resource owner to the constructed URI using an
--  HTTP redirection response, or by other means available to it via the
--  user-agent.
--
--  For example, the client directs the user-agent to make the following
--  HTTP request using TLS (with extra line breaks for display purposes
--  only):
--
--   GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
--       &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
--   Host: server.example.com
--
--  The authorization server validates the request to ensure that all
--  required parameters are present and valid.  If the request is valid,
--  the authorization server authenticates the resource owner and obtains
--  an authorization decision (by asking the resource owner or by
--  establishing approval via other means).
--
--  When a decision is established, the authorization server directs the
--  user-agent to the provided client redirection URI using an HTTP
--  redirection response, or by other means available to it via the
--  user-agent.
--
--- @class oauth2c.authorization.request.params : oauth2c.request.params
--- @field response_type string @ REQUIRED. Value MUST be set to "code".
--- @field client_id string @ REQUIRED. The client identifier as described in Section 2.2
--- @field redirect_uri string @ OPTIONAL. As described in Section 3.1.2.
--- @field scope string @ OPTIONAL. The scope of the access request as described by Section 3.3.
--- @field state string @ RECOMMENDED. An opaque value used by the client to maintain state between the request and callback.

--- @class oauth2c.authorization.request : oauth2c.request
--- @field state string @ state parameter

--- create_request
--- @param uri string @ authorization endpoint URI
--- @param client_id string @ The client identifier as described in Section 2.2
--- @param redirect_uri string? @ OPTIONAL. As described in Section 3.1.2.
--- @param scope? string @ OPTIONAL. The scope of the access request as described by Section 3.3.
--- @param state? string @ RECOMMENDED. An opaque value used by the client to maintain state between the request and callback.
--- @return oauth2c.authorization.request req
local function create_request(uri, client_id, redirect_uri, scope, state)
    assert(is_str(uri), 'uri must be string')
    assert(is_str(client_id), 'client_id must be string')
    assert(redirect_uri == nil or is_str(redirect_uri),
           'redirect_uri must be string or nil')
    assert(scope == nil or is_str(scope), 'scope must be string or nil')
    assert(state == nil or is_str(state), 'state must be string or nil')

    return new_request(uri, {
        response_type = 'code',
        client_id = client_id,
        redirect_uri = redirect_uri,
        scope = scope,
        state = state,
    })
end

--
-- https://tools.ietf.org/html/rfc6749#section-4.1.2
-- 4.1.2.  Authorization Response
--
--  If the resource owner grants the access request, the authorization
--  server issues an authorization code and delivers it to the client by
--  adding the following parameters to the query component of the
--  redirection URI using the "application/x-www-form-urlencoded" format,
--  per Appendix B:
--
--  code
--        REQUIRED.  The authorization code generated by the
--        authorization server.  The authorization code MUST expire
--        shortly after it is issued to mitigate the risk of leaks.  A
--        maximum authorization code lifetime of 10 minutes is
--        RECOMMENDED.  The client MUST NOT use the authorization code
--        more than once.  If an authorization code is used more than
--        once, the authorization server MUST deny the request and SHOULD
--        revoke (when possible) all tokens previously issued based on
--        that authorization code.  The authorization code is bound to
--        the client identifier and redirection URI.
--
--  state
--        REQUIRED if the "state" parameter was present in the client
--        authorization request.  The exact value received from the
--        client.
--
--  For example, the authorization server redirects the user-agent by
--  sending the following HTTP response:
--
--    HTTP/1.1 302 Found
--    Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
--                &state=xyz
--
--  The client MUST ignore unrecognized response parameters.  The
--  authorization code string size is left undefined by this
--  specification.  The client should avoid making assumptions about code
--  value sizes.  The authorization server SHOULD document the size of
--  any value it issues.
--
--- @class oauth2c.authorization.response
--- @field code string @ REQUIRED. The authorization code generated by the authorization server.
--- @field state string @ REQUIRED if the "state" parameter was present in the client authorization request. The exact value received from the client.

--- verify_response
--- @param query table|string
--- @param state? string
--- @return oauth2c.authorization.response|oauth2c.error_response? res
--- @return any err
local function verify_response(query, state)
    assert(state == nil or is_str(state), 'state must be string or nil')

    local res
    if not is_str(query) then
        assert(is_table(query), 'query must be table or string')
        res = query --- @type table
    else
        local uri, pos, errc = parse_uri(query, true)
        if errc then
            return nil, errorf(
                       'found illegal character sequence %q at position %d in query',
                       errc, pos)
        end

        res = uri.query_params or {}
        for k, v in pairs(res) do
            -- use only last value
            res[k] = v[#v]
        end
    end

    if res.error then
        return res
    elseif res.code == nil then
        return nil, errorf('no code parameter in query')
    elseif not is_str(res.code) then
        return nil, errorf('code parameter in query is not string')
    elseif find(res.code, '^%s*$') then
        return nil, errorf('code parameter in query is empty string')
    elseif res.state ~= nil and not is_str(res.state) then
        return nil, errorf('state parameter in query is not string')
    elseif res.state ~= state then
        return nil, errorf('state mismatch')
    end
    return res
end

return {
    request = create_request,
    response = verify_response,
}
