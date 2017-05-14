'use strict';

const indieauth = require('../index.js');

describe('test', function() {
  it('shows the login page', function(done) {
    indieauth.lambda(indexEvent.event, {}, (error, response) => {
      console.log(response);
      done();
    });
  });

  it('returns a redirect for the login event', function(done) {
    indieauth.lambda(loginEvent.event, {}, (error, response) => {
      console.log(response);
      done();
    });
  });
});

const indexEvent = {
  "event": {
    "path": "/indieauth/code",
    "httpMethod": "GET",
    "headers": {
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, sdch, br",
      "Accept-Language": "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4",
      "CloudFront-Forwarded-Proto": "https",
      "CloudFront-Is-Desktop-Viewer": "true",
      "CloudFront-Is-Mobile-Viewer": "false",
      "CloudFront-Is-SmartTV-Viewer": "false",
      "CloudFront-Is-Tablet-Viewer": "false",
      "CloudFront-Viewer-Country": "DE",
      "Upgrade-Insecure-Requests": "1",
      "X-Forwarded-Port": "443",
      "X-Forwarded-Proto": "https"
    },
    "queryStringParameters": {
      "me": "https://example.com/",
      "response_type": "id",
      "redirect_uri": "https://webapp.example.org/auth/callback",
      "state": "1234567890",
      "client_id": "https://webapp.example.org/"
    },
    "pathParameters": {
      "proxy": "index.html"
    },
    "stageVariables": null,
    "requestContext": {
      "path": "/prod/bla",
      "stage": "prod",
      "identity": {
        "cognitoIdentityPoolId": null,
        "accountId": null,
        "cognitoIdentityId": null,
        "caller": null,
        "apiKey": "",
        "accessKey": null,
        "cognitoAuthenticationType": null,
        "cognitoAuthenticationProvider": null,
        "userArn": null,
        "user": null
      },
      "resourcePath": "/{proxy+}",
      "httpMethod": "GET",
    },
    "body": null,
    "isBase64Encoded": false
  }
};

const loginEvent = {
  "event": {
    resource: '/indieauth/authorize',
    path: '/indieauth/authorize',
    httpMethod: 'POST',
    headers: {
      'Accept-Encoding': 'gzip, deflate, br',
      'content-type': 'application/x-www-form-urlencoded',
      Host: 'xxx.execute-api.eu-west-1.amazonaws.com',
      origin: 'https://example.com',
      pragma: 'no-cache',
      'upgrade-insecure-requests': '1',
      'User-Agent': 'Amazon CloudFront',
      'X-Forwarded-Port': '443',
      'X-Forwarded-Proto': 'https'
    },
    queryStringParameters: null,
    pathParameters: null,
    body: 'me=https%3A%2F%2Fwww.example.com%2F&response_type=id&redirect_uri=https%3A%2F%2Fwebapp.example.org%2Fauth%2Fcallback&state=1234567890&client_id=https%3A%2F%2Fasdsavd.example.org%2F&temporary_aws_api_key_id=afsdfasd&temporary_aws_api_key=sfdsfd&temporary_aws_session_token=dfhdfghfd',
    isBase64Encoded: false
  }
};
