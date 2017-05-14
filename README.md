# IAM-IndieAuth Bridge

A Lambda function to use IndieAuth with your AWS IAM API key credentials.

## Overview

This Lambda function implements an authorization endpoint for the IndieAuth protocol.

For details see:

https://indieweb.org/IndieAuthProtocol
https://indieweb.org/authorization-endpoint

This project was started at the IndieWebCamp 2017 in Düsseldorf, Germany.

## Installation

- Install the code as a Lambda function.
- Create a role that indicates that allows an IAM user to use IndieAuth if he can successfully assume that role.
- Create two environment variables for the Lambda function: "iamRole" (set the arn of the role as the value) and "hmacKey" (set a secure random 32 digit hex number as the value).
- Create an API Gateway with the resources "/indieauth/authorize" (method: POST) and "/indieauth/code" (methods: HEAD, GET, POST) and let the Lambda function handle all resources/methods with the Lambda Proxy Integration.
- Put the pointer to the endpoint into the html source of your website: `<link rel="authorization_endpoint" href="https://you.apigateway.name/indieauth/code">`

DISCLAIMER: Authentication/Authorization is a critical part of online security. Make sure that you understand the implications of the protocol and its implementation before you enter any credentials.

## TODO

- The test are not very useful
- The login form is ugly
- Temporary credentials should be requested from STS and they should be sent to the Lambda function
- a form field for MFA should be integrated
- HMAC variable should be encrypted
