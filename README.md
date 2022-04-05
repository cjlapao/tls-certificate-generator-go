# TLS Certificate Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) ![Build](https://github.com/cjlapao/go-template/workflows/Build/badge.svg) ![Release](https://github.com/cjlapao/go-template/workflows/Release/badge.svg) ![Security](https://github.com/cjlapao/go-template/workflows/CodeQL/badge.svg)  

This tool will generate self signed certificates with a chain of trust by creating and mimicking a trust chain using Root CA and Intermediate CA to sign.
This is useful for local development under HTTPS as we can after trusting the RootCA and IntermediateCA make the browsers trust it.

## Future work

The objective is also to create an api that will mimic the Root to remove certificates