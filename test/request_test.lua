require('luacov')
local testcase = require('testcase')
local assert = require('assert')
local request = require('oauth2c.request')

function testcase.new()
    -- test that create new request object
    local req = request('https://example.com', {
        hello = 'world',
        foo = 'bar',
    })
    assert.re_match(req, '^oauth2c.request: ')
    assert.contains(req, {
        uri = 'https://example.com',
        params = {
            hello = 'world',
            foo = 'bar',
        },
    })

    -- test that throws an error if uri is not a string
    local err = assert.throws(request, true, {})
    assert.match(err, 'uri must be string')

    -- test that throws an error if params is not a table
    err = assert.throws(request, 'https://example.com', true)
    assert.match(err, 'params must be table')
end

function testcase.encode_uri()
    -- test that encode request
    local req = request('https://example.com', {
        hello = 'hello world',
    })
    local uri = req:encode_uri()
    assert.equal(uri, 'https://example.com?hello=hello+world')
end

function testcase.encode_params()
    -- test that encode request parameters
    local req = request('https://example.com', {
        hello = 'hello world',
    })
    local params = req:encode_params()
    assert.equal(params, 'hello=hello+world')
end

function testcase.encode_params_json()
    -- test that encode request parameters
    local req = request('https://example.com', {
        hello = 'hello world',
    })
    local json, err = req:encode_params_json()
    assert.is_nil(err)
    assert.equal(json, '{"hello":"hello world"}')
end

