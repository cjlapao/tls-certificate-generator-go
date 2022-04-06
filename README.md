# TLS Certificate Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) ![Build](https://github.com/cjlapao/go-template/workflows/Build/badge.svg) ![Release](https://github.com/cjlapao/go-template/workflows/Release/badge.svg) ![Security](https://github.com/cjlapao/go-template/workflows/CodeQL/badge.svg)  

This tool will generate self signed certificates with a chain of trust by creating and mimicking a trust chain using Root CA and Intermediate CA to sign.
This is useful for local development under HTTPS as we can after trusting the RootCA and IntermediateCA make the browsers trust it.

## How To Use

1. Create a ```config.yml``` file in the root of the tool and fill up the following settings

  ```yaml
  rootCertificates:
  - name: ACME Root CA # Configuration name, this will be used for the filename of the certificate
    config:
      country: Moon # Country
      state: Dark Side # State
      organization: ACME Inc. # Organization
      commonName: ACME Root CA # Certificate Common Name
      city: Bright # City
      fqdns: # the domain we are certifying like for example localhost
      - example.com 
      ipAddresses: # IP address to fix the certificate to, not mandatory
      - 127.0.0.1 
      organizationalUnit: ACME IT # Organizational unit for the root certificate
      adminEmailAddress: admin@example.com # Email address to use as an admin
      expiresInYears: 5 # number of years the certificate is valid
      keySize: 2048 # Certificate Key Size
      signatureAlgorithm: 4 # Certificate signature algorithm, 4. SHA256, 5. SHA384 6. SHA512
    intermediateCertificates:
    - name: ACME Intermediate CA # Configuration name, this will be used for the filename of the certificate
      config:
        country: Moon # Country
        state: Dark Side # State
        organization: ACME Inc. # Organization
        commonName: ACME Intermediate CA # Certificate Common Name
        city: Bright # City
        fqdns: # the domain we are certifying like for example localhost
        - example.com 
        ipAddresses: # IP address to fix the certificate to, not mandatory
        - 127.0.0.1
        organizationalUnit: ACME IT # Organizational unit for the root certificate
        adminEmailAddress: admin@example.com # Email address to use as an admin
        expiresInYears: 5 # number of years the certificate is valid
        keySize: 2048 # Certificate Key Size
        signatureAlgorithm: 4 # Certificate signature algorithm, 4. SHA256, 5. SHA384 6. SHA512
      certificates:
      - name: ACME Localhost
        config:
          country: Moon # Country
          state: Dark Side # State
          organization: ACME Inc. # Organization
          commonName: ACME Localhost # Certificate Common Name
          city: Bright # City
          fqdns: # the domain we are certifying like for example localhost
          - localhost
          - '*.localhost'
          organizationalUnit: ACME IT # Organizational unit for the root certificate
          adminEmailAddress: admin@example.com # Email address to use as an admin
          expiresInYears: 1 # number of years the certificate is valid
          keySize: 2048 # Certificate Key Size
          signatureAlgorithm: 4 # Certificate signature algorithm, 4. SHA256, 5. SHA384 6. SHA512
      - name: ACME example.com
        config:
          country: Moon # Country
          state: Dark Side # State
          organization: ACME Inc. # Organization
          commonName: ACME Example # Certificate Common Name
          city: Bright # City
          fqdns: # the domain we are certifying like for example localhost
          - example.com
          - '*.example.com'
          organizationalUnit: ACME IT # Organizational unit for the root certificate
          adminEmailAddress: admin@example.com # Email address to use as an admin
          expiresInYears: 1 # number of years the certificate is valid
          keySize: 2048 # Certificate Key Size
          signatureAlgorithm: 4 # Certificate signature algorithm, 4. SHA256, 5. SHA384 6. SHA512
          password: changeit # this will allow to create a pkcs12 certificate with this password, this is normally used in the IIS web hosting
  outputToFile: true # set this to true if you want to get the certificates into files, they will also be added to the file
  ```

2. Run the following command in command line in **Administrator**

    ```bash
    .\tls-certificate-generator.exe
    ```

this will output something similar to this notifying that everything went as expected

```
********************************************************************************
*                                                                              *
*                      TLS Certificate Generator 0.0.0.1                       *
*                                                                              *
* Author: Carlos Lapao                                                         *
* License: MIT                                                                 *
********************************************************************************

|- Root
|  |- ACME Root CA
|  |  |- ACME Intermediate CA
|  |  |  |- ACME Localhost
|  |  |  |- ACME example.com
```

## Future work

The objective is also to create an api that will mimic the Root to remove certificates