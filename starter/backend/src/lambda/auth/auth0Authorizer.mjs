import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const certificate =`-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJGEwQc0ZQ4hFTMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1nM3k4aWZiZ3ByNzZuZHp5LnVzLmF1dGgwLmNvbTAeFw0yNDEwMzAw
OTEwNDlaFw0zODA3MDkwOTEwNDlaMCwxKjAoBgNVBAMTIWRldi1nM3k4aWZiZ3By
NzZuZHp5LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAJUDeN8mxdmhfU8S5gemEhho/exg141WDtXXHYjZSXO2BsqZahpxtqeRWI6m
gPxUa7WpDenHO7ThwwXc4BXonTYF3lFi6U7vsJDU4yZr7rQdePoo/rYzmTkIUgDh
hcdVRcEqFIuQSIohLzb/6YN1eWFasllBbhfpso77qvttkP+BUulZNaPXmrXBiPMC
FTEuI5o7zNTFh2pjQwxvQdjVXWcuIlRscbkImTIx8ifvE5tvs1uGqqGIdUYq5YgL
l+ieB5EiGxDav2rwruAKx8JL2SUBPcVL39trAW8gOqYUf+TW+34qLPqyjOaMEkQj
wrNlK0xZbfNmzwDm4tnzlGk1OEsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUyNacAUOS56fKrOuRz/D8V6DXsCgwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBljO0IRHyf7DLb0V95cA7b7xiZEbKB2012A4tm+TMu
RWt2YAhPDR1mMQ33leDEGomHVsCFxI6zLeEYDvl+CCkXUlG90S7VIzLRxZtu7nIb
11K9Pg6L2Wws6j0pfe4BABUZ4AiYIFFCrmdpzklOXX/9gCDbtRCqoTFxS1YSUEPP
+PhXrcd6OS9z35lEMEOl2U1YwQ7ucGFX6fl91mJyRko422uWwbasCUDwlhOd/K6v
88vCaBt0VR14vNSjmAzq3DWnL12ZIhlioV7Byhy2ygfhDehuMHE89QiBoDHsgdBW
g5XNZuoXrGGBwAcKR1j9pFHwmhOtzBQ7D4qyQubm6TUs
-----END CERTIFICATE-----`
export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}