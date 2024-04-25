require('luacov')
local testcase = require('testcase')
local assert = require('assert')
local oauth2c = require('oauth2c')

function testcase.new()
    -- test that create a new instance
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })
    assert.re_match(o, '^oauth2c: ')

    -- test that throws an error if params is not a table
    local err = assert.throws(oauth2c, true)
    assert.match(err, 'params must be table')

    -- test that throws an error if client_id is missing
    err = assert.throws(oauth2c, {
        -- client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })
    assert.match(err, 'params.client_id is required')

    -- test that throws an error if field is not a string
    for _, k in ipairs({
        'client_id',
        'client_secret',
        'authz_uri',
        'token_uri',
        'redirect_uri',
    }) do
        local params = {
            client_id = 'my_client_id',
            client_secret = 'my_client_secret',
            authz_uri = 'https://example.com/oauth2/authorize',
            token_uri = 'https://example.com/oauth2/token',
            redirect_uri = 'http://example.com/authz/',
            [k] = true,
        }
        err = assert.throws(oauth2c, params)
        assert.match(err, 'params.' .. k .. ' must be string')
    end
end

function testcase.set_tokens_get_tokens()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that set tokens
    o:set_tokens({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })

    -- test that get tokens
    assert.equal(o:get_tokens(), {
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })

    -- test that throws an error if access_token is missing
    local err = assert.throws(o.set_tokens, o, {
        -- access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.match(err, 'access_token is required')

    -- test that throws an error if access_token is not a string
    err = assert.throws(o.set_tokens, o, {
        access_token = {
            '1234',
        },
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.match(err, 'access_token must be string')

    -- test that throws an error if token_type is missing
    err = assert.throws(o.set_tokens, o, {
        access_token = '1234',
        -- token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.match(err, 'token_type is required')

    -- test that throws an error if token_type is not a string
    err = assert.throws(o.set_tokens, o, {
        access_token = '1234',
        token_type = {
            'bearer',
        },
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.match(err, 'token_type must be string')

    -- test that throws an error if expires_in is not uint
    err = assert.throws(o.set_tokens, o, {
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3.600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.match(err, 'expires_in must be unsigned integer')

    -- test that throws an error if refresh_token is not a string
    err = assert.throws(o.set_tokens, o, {
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = {
            '5678',
        },
        scope = 'read write',
    })
    assert.match(err, 'refresh_token must be string')

    -- test that throws an error if scope is not a string
    err = assert.throws(o.set_tokens, o, {
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = {
            'read write',
        },
    })
    assert.match(err, 'scope must be string')
end

function testcase.create_authorization_header()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that return empty string if no access token set yet
    assert.equal(o:create_authorization_header(), '')

    -- test that create authorization header
    o:set_tokens({
        access_token = '1234',
        token_type = 'bearer',
    })
    assert.equal(o:create_authorization_header(), 'bearer 1234')
end

function testcase.create_authorization_request()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that create authorization request
    local req = o:create_authorization_request()
    assert.re_match(req, '^oauth2c.request: ')
    assert.contains(req, {
        uri = 'https://example.com/oauth2/authorize',
        state = req.state,
        params = {
            client_id = 'my_client_id',
            response_type = 'code',
            redirect_uri = 'http://example.com/authz/',
            state = req.state,
        },
    })

    -- test that create authorization request without redirect_uri
    o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
    })
    req = o:create_authorization_request()
    assert.re_match(req, '^oauth2c.request: ')
    assert.contains(req, {
        uri = 'https://example.com/oauth2/authorize',
        state = req.state,
        params = {
            client_id = 'my_client_id',
            response_type = 'code',
            state = req.state,
        },
    })

    -- test that create authorization request with scope
    req = o:create_authorization_request('read write')
    assert.contains(req, {
        uri = 'https://example.com/oauth2/authorize',
        state = req.state,
        params = {
            client_id = 'my_client_id',
            response_type = 'code',
            state = req.state,
            scope = 'read write',
        },
    })

    -- test that throws an error if scope is not a string
    local err = assert.throws(o.create_authorization_request, o, true)
    assert.match(err, 'scope must be string or nil')
end

function testcase.verify_authorization_response_query()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })
    local req = o:create_authorization_request()

    -- test that verify authorization response query table
    local res, err = o:verify_authorization_response_query(req.state, {
        code = '1234',
        state = req.state,
    })
    assert.is_nil(err)
    assert.equal(res, {
        code = '1234',
        state = req.state,
    })

    -- test that verify authorization response query string
    res, err = o:verify_authorization_response_query(req.state,
                                                     '/authz/?code=1234&state=' ..
                                                         req.state)
    assert.is_nil(err)
    assert.equal(res, {
        code = '1234',
        state = req.state,
    })

    -- test that throws an error if state is not string
    err = assert.throws(o.verify_authorization_response_query, o, true,
                        '/authz/?code=1234')
    assert.match(err, 'state must be string')

    -- test that throws an error if query is not a string or table
    err = assert.throws(o.verify_authorization_response_query, o, req.state,
                        true)
    assert.match(err, 'query must be table or string')

    -- test that return error if query string cannot be parsed
    res, err = o:verify_authorization_response_query(req.state,
                                                     '/authz/ ?code=1234')
    assert.is_nil(res)
    assert.match(err, 'illegal character sequence')

    -- test that return error if error parameter is present
    res, err = o:verify_authorization_response_query(req.state, {
        error = 'invalid_request',
    })
    assert.is_nil(err)
    assert.equal(res, {
        error = 'invalid_request',
    })

    -- test that return error if no state parameter in query
    res, err = o:verify_authorization_response_query(req.state, {
        code = '1234',
    })
    assert.is_nil(res)
    assert.match(err, 'no state parameter in query')

    -- test that return error if state parameter in query is not string
    res, err = o:verify_authorization_response_query(req.state, {
        code = '1234',
        state = 1234,
    })
    assert.is_nil(res)
    assert.match(err, 'state parameter in query is not string')

    -- test that return error if state parameters is not equal to state
    res, err = o:verify_authorization_response_query(req.state, {
        code = '1234',
        state = '5678',
    })
    assert.is_nil(res)
    assert.match(err, 'state mismatch')

    -- test that return error if no code parameter in query
    res, err = o:verify_authorization_response_query(req.state, {
        state = req.state,
    })
    assert.is_nil(res)
    assert.match(err, 'no code parameter in query')

    -- test that return error if code parameter in query is not string
    res, err = o:verify_authorization_response_query(req.state, {
        code = 1234,
        state = req.state,
    })
    assert.is_nil(res)
    assert.match(err, 'code parameter in query is not string')

    -- test that return error if code parameter in query is empty string
    res, err = o:verify_authorization_response_query(req.state, {
        code = '',
        state = req.state,
    })
    assert.is_nil(res)
    assert.match(err, 'code parameter in query is empty string')
end

function testcase.create_access_token_request()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that return error if no code parameter received
    local req, err = o:create_access_token_request()
    assert.match(err, 'must call verify_authorization_response_query')
    assert.is_nil(req)

    -- test that create access token request after verify authorization response
    assert(o:verify_authorization_response_query('foobar', {
        code = '1234',
        state = 'foobar',
    }))
    req, err = o:create_access_token_request()
    assert.is_nil(err)
    assert.re_match(req, '^oauth2c.request: ')
    assert.contains(req, {
        uri = 'https://example.com/oauth2/token',
        params = {
            grant_type = 'authorization_code',
            code = '1234',
            redirect_uri = 'http://example.com/authz/',
            client_id = 'my_client_id',
            client_secret = 'my_client_secret',
        },
    })
end

function testcase.verify_access_token_response()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that verify access token response table
    local res, err = o:verify_access_token_response({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(err)
    assert.equal(res, {
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.equal(o:get_tokens(), res)

    -- test that verify access token response JSON string
    res, err = o:verify_access_token_response([[{
        "access_token": "5678",
        "token_type": "bearer",
        "expires_in": 86400,
        "refresh_token": "8901",
        "scope": "get post"
    }]])
    assert.is_nil(err)
    assert.equal(res, {
        access_token = '5678',
        token_type = 'bearer',
        expires_in = 86400,
        refresh_token = '8901',
        scope = 'get post',
    })
    assert.equal(o:get_tokens(), res)

    -- test that return response even error field is present
    res, err = o:verify_access_token_response({
        error = 'invalid_request',
        error_description = 'invalid request',
    })
    assert.is_nil(err)
    assert.equal(res, {
        error = 'invalid_request',
        error_description = 'invalid request',
    })

    -- test that return error if access_token field is missing
    res, err = o:verify_access_token_response({
        -- access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'no access_token field in response')

    -- test that return error if access_token field is not string
    res, err = o:verify_access_token_response({
        access_token = {},
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'access_token field in response is not string')

    -- test that return error if token_type field is missing
    res, err = o:verify_access_token_response({
        access_token = '1234',
        -- token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'no token_type field in response')

    -- test that return error if token_type field is not string
    res, err = o:verify_access_token_response({
        access_token = '1234',
        token_type = {},
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'token_type field in response is not string')

    -- test that return error if expires_in field is not uint
    res, err = o:verify_access_token_response({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3.600,
        refresh_token = '5678',
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'expires_in field in response is not unsigned integer')

    -- test that return error if refresh_token field is not string
    res, err = o:verify_access_token_response({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = {},
        scope = 'read write',
    })
    assert.is_nil(res)
    assert.match(err, 'refresh_token field in response is not string')

    -- test that return error if scope field is not string
    res, err = o:verify_access_token_response({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = {},
    })
    assert.is_nil(res)
    assert.match(err, 'scope field in response is not string')

    -- test that throws an error if response is not a table or string
    err = assert.throws(o.verify_access_token_response, o, true)
    assert.match(err, 'response must be table or string')

    -- test that return error if response string is invalid JSON string
    res, err = o:verify_access_token_response('{"access_token": "1234"')
    assert.is_nil(res)
    assert.match(err, 'failed to decode response as JSON')
end

function testcase.create_refresh_token_request()
    local o = oauth2c({
        client_id = 'my_client_id',
        client_secret = 'my_client_secret',
        authz_uri = 'https://example.com/oauth2/authorize',
        token_uri = 'https://example.com/oauth2/token',
        redirect_uri = 'http://example.com/authz/',
    })

    -- test that return error if no code parameter received
    local req, err = o:create_refresh_token_request()
    assert.match(err, 'must call set_tokens')
    assert.is_nil(req)

    -- test that create refresh token request after set tokens
    o:set_tokens({
        access_token = '1234',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '5678',
        scope = 'read write',
    })
    req, err = o:create_refresh_token_request()
    assert.is_nil(err)
    assert.re_match(req, '^oauth2c.request: ')
    assert.contains(req, {
        uri = 'https://example.com/oauth2/token',
        params = {
            grant_type = 'refresh_token',
            refresh_token = '5678',
            scope = 'read write',
            client_id = 'my_client_id',
            client_secret = 'my_client_secret',
        },
    })

    -- test that create refresh token request after verify access token response
    assert(o:verify_access_token_response({
        access_token = '5678',
        token_type = 'bearer',
        expires_in = 3600,
        refresh_token = '8901',
        scope = 'read write',
    }))
    req, err = o:create_refresh_token_request()
    assert.is_nil(err)
    assert.contains(req, {
        uri = 'https://example.com/oauth2/token',
        params = {
            grant_type = 'refresh_token',
            refresh_token = '8901',
            scope = 'read write',
            client_id = 'my_client_id',
            client_secret = 'my_client_secret',
        },
    })
end
