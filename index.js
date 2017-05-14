'use strict';

const AWS = require('aws-sdk');
const handlebars = require('handlebars');
const querystring = require('querystring');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// TODO make configurable!
const hmacKeyHexString = 'c808e9f1fd0be55aefe7103e3396bab6'; // crypto.randomBytes(16).toString('hex');
const hmacKey = new Buffer(hmacKeyHexString, 'hex');

exports.lambda = function(event, context, callback) {

  if (event.httpMethod == 'HEAD' && event.path.startsWith('/indieauth/code')) {
    // CASE 0.5: some client check the endpoint by issuing a HEAD request and expecting a "IndieAuth: authorization_endpoint header
    callback(null, {
      statusCode: 200,
      headers: {
        'cache-control': 'no-store',
        'IndieAuth': 'authorization_endpoint'
      }
    });
  } else if (event.httpMethod == 'GET' && event.path.startsWith('/indieauth/code')) {
    // CASE 1: display login page in response to a GET
    // console.log(event);

    if (!event.queryStringParameters.response_type || event.queryStringParameters.response_type == 'id') {
      const template = handlebars.compile(loginPageTemplate);
      const body = template(event.queryStringParameters);
      callback(null, {
        statusCode: 200,
        headers: {
          'content-type': 'text/html',
          'cache-control': 'no-store',
          'IndieAuth': 'authorization_endpoint'
        },
        body : body
      });
    } else {
      console.log(event.queryStringParameters);
      callback(null, {
        statusCode: 501,
        headers: {
          'content-type': 'text/plain',
          'cache-control': 'no-store',
          'IndieAuth': 'authorization_endpoint'
        },
        body : 'Only response_type=id is supported'
      });
    }
  } else if (event.httpMethod == 'POST' && event.path.startsWith('/indieauth/authorize')) {
    console.log(event);
    // CASE 2: receive POST with IAM credentials

    // parse POST
    const postData = querystring.parse(event.body);

    // try sts.assumeRole
    const sts = new AWS.STS({
      apiVersion: '2011-06-15',
      accessKeyId: postData.temporary_aws_api_key_id,
      secretAccessKey: postData.temporary_aws_api_key,
      sessionToken: postData.temporary_aws_session_token
    });
    const params = {
      RoleArn: 'arn:aws:iam::621073008195:role/IndieAuth',
      RoleSessionName: 'IndieAuth_Lambda'
    }
    sts.assumeRole(params).promise()
        .then((data) => {
          // success
          // create JWT
          const payload = {
            redirect_uri: postData.redirect_uri,
            client_uri: postData.client_uri,
            me: postData.me
          }
          const jwtCode = jwt.sign(payload, hmacKey, { expiresIn: 60 }); // 1 minute

          const location = postData.redirect_uri + '?code=' + encodeURIComponent(jwtCode) + '&state=' + postData.state + '&me=' + encodeURIComponent(postData.me);
          callback(null, {
            statusCode: 302,
            headers: {
              Location: location,
              'cache-control': 'no-store',
              'IndieAuth': 'authorization_endpoint'
            },
            body : ''
          });
        })
        .catch((error) => {
          console.log(error);
          callback(null, {
            statusCode: 403
          });
        });

  } else if (event.httpMethod == 'POST' && event.path.startsWith('/indieauth/code')) {
    // CASE 3: receive POST with code

    // parse POST data
    const postData = querystring.parse(event.body);

    // verify JWT
    const options = { algorithms: [ 'HS256' ] };
    jwt.verify(postData.code, hmacKey, options, function(error, payload) {
      if (error) {
        console.log(error);
        callback(null, {
          statusCode: 403
        });
      } else {
        // JWT verified
        // verify data in JWT against POST parameters
        if (postData.redirect_uri == payload.redirect_uri && postData.client_uri == payload.client_uri) {
          // success
          // prepare response body depending on Accept header
          if (event.headers.accept == 'application/x-www-form-urlencoded') {
            callback(null, {
              statusCode: 200,
              headers: {
                'cache-control': 'no-store',
                'IndieAuth': 'authorization_endpoint',
                'content-type': 'application/x-www-form-urlencoded'
              },
              body : querystring.stringify({ me: payload.me })
            });

          } else if (event.headers.accept == 'application/json') {
            callback(null, {
              statusCode: 200,
              headers: {
                'cache-control': 'no-store',
                'IndieAuth': 'authorization_endpoint',
                'content-type': 'application/json'
              },
              body : JSON.stringify({ me: payload.me })
            });
          } else {
            // unknown
            console.log('Unsupported value for HTTP Accept header: ', event.headers);
            callback(null, {
              statusCode: 200,
              headers: {
                'cache-control': 'no-store',
                'IndieAuth': 'authorization_endpoint',
                'content-type': 'application/json'
              },
              body : JSON.stringify({ me: payload.me })
            });
/*            callback(null, {
              statusCode: 406,
              headers: {
                'cache-control': 'no-store',
                'IndieAuth': 'authorization_endpoint'
              },
              body : 'Only "application/x-www-form-urlencoded" and "application/json" are accepted in the Accept-header'
            });*/
          }
        } else {
          console.log({
            postData: postData,
            payload: payload
          });
          callback(null, {
            statusCode: 403,
            headers: {
              'cache-control': 'no-store',
              'IndieAuth': 'authorization_endpoint'
            }
          });
        }
      }
    });
  } else {
    console.log('Something unexpected happened, dumping event and setting status to 500', event);
    callback(null, {
      statusCode: 500
    });
  }
}

const loginPageTemplate = `
<form name="iam_credentials">
  AWS API Key ID: <input type="text" name="aws_api_key_id"><br>
  AWS API Key: <input type="password" name="aws_api_key"><br>
  <input type="submit">
</form>
<form name="indieauth_login" method="POST" action="/indieauth/authorize">
  Me: <input type="text" name="me" value="{{ me }}" readonly="readonly"><br>
  Redirect URI: <input type="text" name="redirect_uri" value="{{ redirect_uri }}" readonly="readonly"><br>
  Client ID: <input type="text" name="client_id" value="{{ client_id }}" readonly="readonly"><br>
  State: <input type="text" name="state" value="{{ state }}" readonly="readonly"><br>
  Temp. AWS API Key ID: <input type="text" name="temporary_aws_api_key_id" value=""><br>
  Temp. AWS API Key: <input type="password" name="temporary_aws_api_key" value=""><br>
  Temp: AWS Session Token: <input type="text" name="temporary_aws_session_token" value=""><br>
  <input type="submit">
</form>
`;
