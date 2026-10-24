// SPDX-License-Identifier: AGPL-3.0-only

//! Tests of the CXF importer: the specification's own example (golden), the mapping, the
//! per-credential skips and their counts, and hostile or oversized documents.
//!
//! **Provenance of [`APPENDIX_A`].** The example payload of Appendix A of the FIDO Alliance
//! *Credential Exchange Format* 1.0, Proposed Standard with errata,
//! `cxf-v1.0-ps-errata-20260309` (`fidoalliance.org/specs/cx/`, fetched 2026-10-22), reproduced
//! for interoperability testing, re-indented, values unchanged. Its one passkey's `key` is
//! also a vector of `rizzy-core`'s PKCS#8 tests. It holds no real secret.

use std::collections::BTreeMap;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng as _;
use rizzy_core::encoding::b64url_encode;
use rizzy_core::item::schema::{
    ITEM_NAME, ITEM_TYPE, LOGIN_USERNAME, WriteMode, WriteSource, check_create,
};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::ValueRef;
use rizzy_core::passkey::pkcs8;
use rizzy_core::passkey::{EdDsaSigningKey, Es256SigningKey};

use super::{cose_key_ed25519, cose_key_es256};
use crate::limits::{MAX_ENTRIES, MAX_JSON_LEN};
use crate::{Counts, Format, Import, ImportError, ImportedItem, WarningKind, import};

/// CXF 1.0 PS errata, Appendix A (module docs).
const APPENDIX_A: &str = r#"{
  "version": {
    "major": 1,
    "minor": 0
  },
  "exporterRpId": "exporter.example.com",
  "exporterDisplayName": "Exporter app",
  "timestamp": 1705228800,
  "accounts": [
    {
      "id": "DZSXp7iBQY-Fg-OofakQtQ",
      "username": "jane_smith",
      "email": "jane.smith@example.com",
      "fullName": "Jane Smith",
      "items": [
        {
          "id": "9OF-QjVDQo2Wp2xWPw6ZhA",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "GitHub Login",
          "subtitle": "Work GitHub account",
          "scope": {
            "urls": [
              "https://github.com"
            ],
            "androidApps": []
          },
          "credentials": [
            {
              "type": "basic-auth",
              "username": {
                "id": "-eZX0Gw-TzOsBFwt67N7ZA",
                "fieldType": "string",
                "value": "johndoe",
                "label": "Username field"
              },
              "password": {
                "id": "wgu3wTcXSYawrGMWMtaANg",
                "fieldType": "concealed-string",
                "value": "securepassword123",
                "label": "Password field"
              }
            },
            {
              "type": "totp",
              "secret": "JBSWY3DPEHPK3PXP",
              "period": 30,
              "digits": 6,
              "issuer": "GitHub",
              "algorithm": "sha256",
              "username": "jane.smith@example.com"
            }
          ],
          "tags": [
            "development",
            "git",
            "work"
          ]
        },
        {
          "id": "akKA3Y0jQRuK7sKplB0Y9w",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "WebAuthn.io",
          "subtitle": "johndoe",
          "credentials": [
            {
              "type": "passkey",
              "credentialId": "Y3JlZGVudGlhbElkRXhhbXBsZQ",
              "rpId": "webauthn.io",
              "username": "johndoe",
              "userDisplayName": "John Doe",
              "userHandle": "cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY",
              "key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY",
              "fido2Extensions": {
                "hmacCredentials": {
                  "algorithm": "hmac-sha256",
                  "credWithUV": "j3N5T9qLpWz2rYf4vS6lDn1KpQx8E0fRc2a7Bm5nUsw",
                  "credWithoutUV": "y2R8tL3eWf5qBz0sK4hHn9rVgX7pD1cQm6uTj2aP8Fs"
                },
                "credBlob": "eyJ1c2VyTmFtZSI6ICJKb2huIERvZSIsICJ1c2VySWQiOiAiamRvZS0wMDEiLCAiZW1haWwiOiAiamRvZUBleGFtcGxlLmNvbSJ9",
                "largeBlob": {
                  "uncompressedSize": 129,
                  "data": "HYxBCoUwDESvMgcQT-Hqr71ATIMtlKQkkY-3twrDLIb3Zq8tMEMKUfZ7pBR08lNwdDtAEcaN3vXfsuJnVbGZrNhf82PYrl5ma1JTXCGOQkkLaAxETnmBOb53O51GbYwQdslYHw"
                },
                "payments": true
              }
            }
          ]
        },
        {
          "id": "iz0Q6JWoQ_CbDRboCPJ1Tg",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Visa Credit Card",
          "subtitle": "Personal Visa card",
          "credentials": [
            {
              "type": "credit-card",
              "number": {
                "id": "MTIz",
                "fieldType": "concealed-string",
                "value": "4111111111111111",
                "label": "Card Number"
              },
              "fullName": {
                "fieldType": "string",
                "value": "John Doe",
                "label": "Cardholder Name"
              },
              "cardType": {
                "fieldType": "string",
                "value": "Visa",
                "label": "Card Type"
              },
              "verificationNumber": {
                "fieldType": "concealed-string",
                "value": "123",
                "label": "CVV"
              },
              "pin": {
                "fieldType": "concealed-string",
                "value": "0000",
                "label": "PIN"
              },
              "expiryDate": {
                "fieldType": "year-month",
                "value": "2027-08",
                "label": "Expiry Date"
              },
              "validFrom": {
                "fieldType": "year-month",
                "value": "2024-02",
                "label": "Valid From"
              }
            }
          ],
          "tags": [
            "finance",
            "credit card",
            "personal"
          ]
        },
        {
          "id": "2cGy6PNOSQ2cW43NVxjGSg",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Wifi",
          "subtitle": "Home Wifi",
          "credentials": [
            {
              "type": "wifi",
              "ssid": {
                "fieldType": "string",
                "value": "Home_Network",
                "label": "Wi-Fi SSID"
              },
              "networkSecurityType": {
                "fieldType": "wifi-network-security-type",
                "value": "wpa2-personal",
                "label": "Security Type"
              },
              "passphrase": {
                "fieldType": "concealed-string",
                "value": "mypassword123",
                "label": "Wi-Fi Password"
              },
              "hidden": {
                "fieldType": "boolean",
                "value": "false",
                "label": "Hidden Network"
              }
            }
          ]
        },
        {
          "id": "s4TK1UNTRhG4j1DQawUz8g",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Home alarm",
          "subtitle": "instructions",
          "credentials": [
            {
              "type": "note",
              "content": {
                "fieldType": "string",
                "value": "some instructionts to enable/disable the alarm",
                "label": "alarm"
              }
            }
          ]
        },
        {
          "id": "BQzS9Ws3RnOabLzFuyOu7Q",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Driver License",
          "subtitle": "US",
          "credentials": [
            {
              "type": "drivers-license",
              "fullName": {
                "fieldType": "string",
                "value": "John Doe",
                "label": "Full Name"
              },
              "birthDate": {
                "fieldType": "date",
                "value": "1990-05-15",
                "label": "Date of Birth"
              },
              "issueDate": {
                "fieldType": "date",
                "value": "2020-06-01",
                "label": "Issue Date"
              },
              "expiryDate": {
                "fieldType": "date",
                "value": "2030-06-01",
                "label": "Expiry Date"
              },
              "issuingAuthority": {
                "fieldType": "string",
                "value": "Department of Motor Vehicles",
                "label": "Issuing Authority"
              },
              "territory": {
                "fieldType": "subdivision-code",
                "value": "US-CA",
                "label": "Territory"
              },
              "country": {
                "fieldType": "country-code",
                "value": "US",
                "label": "Country"
              },
              "licenseNumber": {
                "fieldType": "string",
                "value": "D12345678",
                "label": "License Number"
              },
              "licenseClass": {
                "fieldType": "string",
                "value": "C",
                "label": "License Class"
              }
            }
          ]
        },
        {
          "id": "HHl63ybfQG6GBRHlyrvKfg",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "House Address",
          "subtitle": "US",
          "credentials": [
            {
              "type": "address",
              "streetAddress": {
                "fieldType": "string",
                "value": "123 Main Street",
                "label": "Street Address"
              },
              "postalCode": {
                "fieldType": "string",
                "value": "12345",
                "label": "Postal Code"
              },
              "city": {
                "fieldType": "string",
                "value": "Springfield",
                "label": "City"
              },
              "territory": {
                "fieldType": "subdivision-code",
                "value": "US-CA",
                "label": "State"
              },
              "country": {
                "fieldType": "country-code",
                "value": "US",
                "label": "Country"
              },
              "tel": {
                "fieldType": "string",
                "value": "+1-555-123-4567",
                "label": "Telephone"
              }
            }
          ]
        },
        {
          "id": "Z4cFmc21Q5-vCVwd1wJx1g",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "SSH Key",
          "subtitle": "GitHub",
          "credentials": [
            {
              "type": "ssh-key",
              "keyType": "ssh-rsa",
              "privateKey": "MIIG_QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCn4-QiJojZ9mgc9KYJIvDWGaz4qFhf0CButg6L8zEoHKwuiN-mqcEciCCOa9BNiJmm8NTTehZvrrglGG59zIbqYtDAHjVn-vtb49xPzIv-M651Yqj08lIbR9tEIHKCq7aH8GlDm8NgG9EzJGjlL7okQym4TH1MHl-s4mUyr_qb2unlZBDixAQsphU8iCLftukWCIkmQg4CSj1Gh3WbBlZ-EX5eW0EXuAw4XsSbBTWV9CHRowVIpYqPvEYSpHsoCjEcd988p19hpiGknA0J4z7JfUlNgyT_1chb8GCTDT-2DCBRApbsIg6TOBVS-PR6emAQ3eZzUW0-3_oRM4ip0ujltQy8uU6gvYIAqx5wXGMThVpZcUgahKiSsVo_s4b84iMe4DG3W8jz4qi6yyNv0VedEzPUZ1lXd1GJFoy9uKNuSTe-1ksicAcluZN6LuNsPHcPxFCzOcmoNnVXEKAXInt-ys__5CDVasroZSAHZnDjUD4oNsLI3VIOnGxgXrkwSH0CAwEAAQKCAYAA2SDMf7OBHw1OGM9OQa1ZS4u-ktfQHhn31-FxbrhWGp-lDt8gYABVf6Y4dKN6rMtn7D9gVSAlZCAn3Hx8aWAvcXHaspxe9YXiZDTh-Kd8EIXxBQn-TiDA5LH0dryABqmMp20vYKtR7OS3lIIXfFBSrBMwdunKzLwmKwZLWq0SWf6vVbwpxRyR9CyByodF6DjmZK3QB2qQ3jqlL1HWXL0VnyArY7HLvUvfLLK4vMPqnsSH-FdHvhcEhwqMlWT44g-fhqWtCJNnjDgLK3FPbI8Pz9TF8dWJvOmp5Q6iSBua1e9x2LizVuNSqiFc7ZTLeoG4nDj7T2BtqB0E1rNUDEN1aBo-UZmHJK7LrzfW_B-ssi2WwIpfxYa1lO6HFod5_YQiXV1GunyH1chCsbvOFtXvAHASO4HTKlJNbWhRF1GXqnKpAaHDPCVuwp3eq6Yf0oLbXrL3KFZ3jwWiWbpQXRVvpqzaJwZn3CN1yQgYS9j17a9wrPky-BoJxXjZ_oImWLECgcEA0lkLwiHvmTYFTCC7PN938Agk9_NQs5PQ18MRn9OJmyfSpYqf_gNp-Md7xUgtF_MTif7uelp2J7DYf6fj9EYf9g4EuW-SQgFP4pfiJn1-zGFeTQq1ISvwjsA4E8ZSt-GIumjZTg6YiL1_A79u4wm24swt7iqnVViOPtPGOM34S1tAamjZzq2eZDmAF6pAfmuTMdinCMR1E1kNJYbxeqLiqQCXuwBBnHOOOJofN3AkvzjRUBB9udvniqYxH3PQcxPxAoHBAMxT5KwBhZhnJedYN87Kkcpl7xdMkpU8b-aXeZoNykCeoC-wgIQexnSWmFk4HPkCNxvCWlbkOT1MHrTAKFnaOww23Ob-Vi6A9n0rozo9vtoJig114GB0gUqEmtfLhO1P5AE8yzogE-ILHyp0BqXt8vGIfzpDnCkN-GKl8gOOMPrR4NAcLO-Rshc5nLs7BGB4SEi126Y6mSfp85m0--1QhWMz9HzqJEHCWKVcZYdCdEONP9js04EUnK33KtlJIWzZTQKBwAT0pBpGwmZRp35Lpx2gBitZhcVxrg0NBnaO2fNyAGPvZD8SLQLHAdAiov_a23Uc_PDbWLL5Pp9gwzj-s5glrssVOXdE8aUscr1b5rARdNNL1_Tos6u8ZUZ3sNqGaZx7a8U4gyYboexWyo9EC1C-AdkGBm7-AkM4euFwC9N6xsa_t5zKK5d676hc0m-8SxivYCBkgkrqlfeGuZCQxU-mVsC0it6U-va8ojUjLGkZ80OuCwBf4xZl3-acU7vx9o8_gQKBwB7BrhU6MWrsc-cr_1KQaXum9mNyckomi82RFYvb8Yrilcg38FBy9XqNRKeBa9MLw1HZYpHbzsXsVF7u4eQMloDTLVNUC5L6dKAI1owoyTa24uH90WWTg_a8mTZMe1jhgrew-AJq27NV6z4PswR9GenDmyshDDudz7rBsflZCQRoXUfWRelV7BHU6UPBsXn4ASF4xnRyM6WvcKy9coKZcUqqgm3fLM_9OizCCMJgfXHBrE-x7nBqst746qlEedSRrQKBwQCVYwwKCHNlZxl0_NMkDJ-hp7_InHF6mz_3VO58iCb19TLDVUC2dDGPXNYwWTT9PclefwV5HNBHcAfTzgB4dpQyNiDyV914HL7DFEGduoPnwBYjeFre54v0YjjnskjJO7myircdbdX__i-7LMUw5aZZXCC8a5BD_rdV6IKJWJG5QBXbe5fVf1XwOjBTzlhIPIqhNFfSu-mFikp5BRwHGBqsKMju6inYmW6YADeY_SvOQjDEB37RqGZxqyIx8V2ZYwU",
              "keyComment": "Work SSH Key",
              "creationDate": {
                "fieldType": "date",
                "value": "2023-01-01",
                "label": "Creation Date"
              },
              "expiryDate": {
                "fieldType": "date",
                "value": "2025-01-01",
                "label": "Expiry Date"
              },
              "keyGenerationSource": {
                "fieldType": "string",
                "value": "Generated using OpenSSH",
                "label": "Key Generation Source"
              }
            }
          ]
        },
        {
          "id": "EWM-4m3pSEi0ZBQbFVB92g",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "ID card",
          "subtitle": "US",
          "credentials": [
            {
              "type": "file",
              "id": "VGVzdEZpbGVJRA",
              "name": "example-file.txt",
              "decryptedSize": 21,
              "integrityHash": "crWLSYO8T2f3yGaHQlDrMVvSvuu1YdXZewkjps422lQ"
            }
          ]
        },
        {
          "id": "U9TPhd80SsWKKUtx3HxVsA",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "ID card",
          "subtitle": "US",
          "credentials": [
            {
              "type": "identity-document",
              "issuingCountry": {
                "fieldType": "country-code",
                "value": "US",
                "label": "Issuing Country"
              },
              "documentNumber": {
                "fieldType": "string",
                "value": "123456789",
                "label": "Document Number"
              },
              "identificationNumber": {
                "fieldType": "string",
                "value": "ID123456789",
                "label": "Identification Number"
              },
              "nationality": {
                "fieldType": "string",
                "value": "American",
                "label": "Nationality"
              },
              "fullName": {
                "fieldType": "string",
                "value": "Jane Doe",
                "label": "Full Name"
              },
              "birthDate": {
                "fieldType": "date",
                "value": "1990-04-15",
                "label": "Birth Date"
              },
              "birthPlace": {
                "fieldType": "string",
                "value": "New York, USA",
                "label": "Birth Place"
              },
              "sex": {
                "fieldType": "string",
                "value": "F",
                "label": "Sex"
              },
              "issueDate": {
                "fieldType": "date",
                "value": "2020-01-01",
                "label": "Issue Date"
              },
              "expiryDate": {
                "fieldType": "date",
                "value": "2030-01-01",
                "label": "Expiry Date"
              },
              "issuingAuthority": {
                "fieldType": "string",
                "value": "Department of State",
                "label": "Issuing Authority"
              }
            }
          ]
        },
        {
          "id": "K4BBlNWWTS21ZqzTUn0H6Q",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Passport",
          "subtitle": "US",
          "credentials": [
            {
              "type": "passport",
              "issuingCountry": {
                "fieldType": "country-code",
                "value": "US",
                "label": "Issuing Country"
              },
              "passportType": {
                "fieldType": "string",
                "value": "PP",
                "label": "Passport Type"
              },
              "passportNumber": {
                "fieldType": "string",
                "value": "A12345678",
                "label": "Passport Number"
              },
              "nationalIdentificationNumber": {
                "fieldType": "string",
                "value": "ID123456789",
                "label": "National Identification Number"
              },
              "nationality": {
                "fieldType": "string",
                "value": "American",
                "label": "Nationality"
              },
              "fullName": {
                "fieldType": "string",
                "value": "John Doe",
                "label": "Full Name"
              },
              "birthDate": {
                "fieldType": "date",
                "value": "1990-01-01",
                "label": "Birth Date"
              },
              "birthPlace": {
                "fieldType": "string",
                "value": "Los Angeles, USA",
                "label": "Birth Place"
              },
              "sex": {
                "fieldType": "string",
                "value": "M",
                "label": "Sex"
              },
              "issueDate": {
                "fieldType": "date",
                "value": "2015-06-15",
                "label": "Issue Date"
              },
              "expiryDate": {
                "fieldType": "date",
                "value": "2025-06-15",
                "label": "Expiry Date"
              },
              "issuingAuthority": {
                "fieldType": "string",
                "value": "U.S. Department of State",
                "label": "Issuing Authority"
              }
            }
          ]
        },
        {
          "id": "LmInpZjdRwKIKZFdbBz19g",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "John Doe",
          "subtitle": "personal name",
          "credentials": [
            {
              "type": "person-name",
              "title": {
                "fieldType": "string",
                "value": "Dr.",
                "label": "Title"
              },
              "given": {
                "fieldType": "string",
                "value": "John",
                "label": "Given Name"
              },
              "givenInformal": {
                "fieldType": "string",
                "value": "Johnny",
                "label": "Informal Given Name"
              },
              "given2": {
                "fieldType": "string",
                "value": "Michael",
                "label": "Second Given Name"
              },
              "surnamePrefix": {
                "fieldType": "string",
                "value": "van",
                "label": "Surname Prefix"
              },
              "surname": {
                "fieldType": "string",
                "value": "Doe",
                "label": "Surname"
              },
              "surname2": {
                "fieldType": "string",
                "value": "Smith",
                "label": "Second Surname"
              },
              "credentials": {
                "fieldType": "string",
                "value": "PhD",
                "label": "Credentials"
              },
              "generation": {
                "fieldType": "string",
                "value": "III",
                "label": "Generation"
              }
            }
          ]
        },
        {
          "id": "TMrjj3uIRtitVmIpiwXmyg",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "API key",
          "subtitle": "john_doe",
          "credentials": [
            {
              "type": "api-key",
              "key": {
                "fieldType": "concealed-string",
                "value": "AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk",
                "label": "API Key"
              },
              "username": {
                "fieldType": "string",
                "value": "john_doe",
                "label": "Username"
              },
              "keyType": {
                "fieldType": "string",
                "value": "Bearer",
                "label": "Key Type"
              },
              "url": {
                "fieldType": "string",
                "value": "https://api.example.com",
                "label": "API URL"
              },
              "validFrom": {
                "fieldType": "date",
                "value": "2025-01-01",
                "label": "Valid From"
              },
              "expiryDate": {
                "fieldType": "date",
                "value": "2026-01-01",
                "label": "Expiry Date"
              }
            }
          ]
        },
        {
          "id": "QtvgfXSgS8O6ukLNZZKMlw",
          "creationAt": 1705142400,
          "modifiedAt": 1705228800,
          "title": "Generated Password",
          "subtitle": "john_doe",
          "credentials": [
            {
              "type": "generated-password",
              "password": "KozyS!cf#Nc9C799"
            }
          ]
        }
      ],
      "collections": [
        {
          "id": "0dimBl7dRRyPLGKGxEEm5Q",
          "creationAt": 1705228800,
          "modifiedAt": 1705228800,
          "title": "Work Accounts",
          "subtitle": "A collection of pro accounts for various services",
          "items": [
            {
              "item": "TMrjj3uIRtitVmIpiwXmyg",
              "account": "DZSXp7iBQY-Fg-OofakQtQ"
            },
            {
              "item": "Z4cFmc21Q5-vCVwd1wJx1g",
              "account": "DZSXp7iBQY-Fg-OofakQtQ"
            },
            {
              "item": "9OF-QjVDQo2Wp2xWPw6ZhA",
              "account": "DZSXp7iBQY-Fg-OofakQtQ"
            }
          ]
        }
      ]
    }
  ]
}"#;

/// Runs a CXF import with a fixed seed.
fn run(input: &[u8]) -> Result<Import, ImportError> {
    import(Format::CxfJson, input, &mut ChaCha20Rng::seed_from_u64(74))
}

/// A decoded value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum V {
    /// Text.
    T(String),
    /// Bytes.
    Y(Vec<u8>),
    /// Bool.
    B(bool),
    /// U64.
    U(u64),
    /// Enum.
    E(u16),
}

/// An item's writes by key, element ids replaced by the element's position among its list's
/// elements in key order (one passkey per item here, so always `0`).
fn view(item: &ImportedItem) -> BTreeMap<String, V> {
    let mut elements: Vec<String> = Vec::new();
    item.writes()
        .iter()
        .map(|w| {
            let key = w.key().as_key();
            let key = match (key.list(), key.element(), key.attribute()) {
                (Some(list), Some(id), Some(attribute)) => {
                    let n = elements.iter().position(|e| e == id).unwrap_or_else(|| {
                        elements.push(id.to_owned());
                        elements.len() - 1
                    });
                    format!("{list}/{n}/{attribute}")
                }
                _ => key.as_str().to_owned(),
            };
            let value = match ValueRef::decode(w.value().expose_secret()).unwrap() {
                ValueRef::Text(t) => V::T(t.to_owned()),
                ValueRef::Bytes(b) => V::Y(b.to_vec()),
                ValueRef::Bool(b) => V::B(b),
                ValueRef::U64(u) => V::U(u),
                ValueRef::Enum(e) => V::E(e),
                other => panic!("unexpected value {other:?}"),
            };
            (key, value)
        })
        .collect()
}

/// Every warning as (entry, kind).
fn warnings(import: &Import) -> Vec<(Option<usize>, WarningKind)> {
    import.warnings.iter().map(|w| (w.entry, w.kind)).collect()
}

/// Decodes hex.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The Appendix A passkey's PKCS#8 scalar and public point.
const APPENDIX_SCALAR: &str = "011bbfd2c0addb4129815c5be0fbaadc66b95552e9b9363be6782f665caadd7e";
/// Its x coordinate.
const APPENDIX_X: &str = "a6764d712ec2b4a0e961c483e9d1dd59b92d2c4fd9dfe8166d49e961aaf2c15b";
/// Its y coordinate.
const APPENDIX_Y: &str = "47ce2f7de5fdb5e0b2bfd24d41e308b9fc97a81c449c1eece42f6d0b9b675758";

#[test]
fn appendix_a_imports_its_one_passkey_and_counts_the_rest() {
    let import = run(APPENDIX_A.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 1);
    let item = &import.items[0];
    // The WebAuthn.io item is the second of the account's items.
    assert_eq!(item.entry(), 1);
    assert_eq!(item.item_type(), ItemType::LOGIN);
    let x: [u8; 32] = hex(APPENDIX_X).try_into().unwrap();
    let y: [u8; 32] = hex(APPENDIX_Y).try_into().unwrap();
    let expected: BTreeMap<String, V> = [
        (ITEM_NAME.to_owned(), V::T("John Doe".to_owned())),
        (ITEM_TYPE.to_owned(), V::E(ItemType::LOGIN.id())),
        (LOGIN_USERNAME.to_owned(), V::T("johndoe".to_owned())),
        ("passkey/0/alg".to_owned(), V::E(1)),
        ("passkey/0/created_ms".to_owned(), V::U(1_705_228_800_000)),
        (
            "passkey/0/credential_id".to_owned(),
            V::Y(b"credentialIdExample".to_vec()),
        ),
        ("passkey/0/discoverable".to_owned(), V::B(true)),
        (
            "passkey/0/private_key".to_owned(),
            V::Y(hex(APPENDIX_SCALAR)),
        ),
        (
            "passkey/0/public_key_cose".to_owned(),
            V::Y(cose_key_es256(&x, &y)),
        ),
        ("passkey/0/rp_id".to_owned(), V::T("webauthn.io".to_owned())),
        (
            "passkey/0/user_handle".to_owned(),
            V::Y(hex(
                "72713368d1d67182b77285998efa1a5751e3f609c8d7698a7b674bd876551656",
            )),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(view(item), expected);
    // 14 items: 13 without a passkey; 14 credentials of other types (GitHub holds two); the
    // passkey's fido2Extensions are not imported.
    assert_eq!(
        import.counts,
        Counts {
            skipped_items: 13,
            skipped_credentials: 14,
            dropped_fields: 1,
            ..Counts::default()
        }
    );
    let w = warnings(&import);
    assert_eq!(w.len(), 15);
    assert!(w.contains(&(Some(1), WarningKind::FieldSkipped)));
    assert_eq!(
        w.iter()
            .filter(|(_, k)| *k == WarningKind::CredentialTypeSkipped)
            .count(),
        14
    );
    assert_eq!(
        w.iter().filter(|(e, _)| *e == Some(0)).count(),
        2,
        "GitHub's basic-auth and totp"
    );
}

#[test]
fn the_cose_maps_match_their_fixed_layouts() {
    let x = [0x11; 32];
    let y = [0x22; 32];
    let ec2 = cose_key_es256(&x, &y);
    assert_eq!(ec2.len(), 77);
    assert_eq!(
        &ec2[..10],
        &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
    );
    assert_eq!(&ec2[42..45], &[0x22, 0x58, 0x20]);
    let okp = cose_key_ed25519(&x);
    assert_eq!(okp.len(), 42);
    assert_eq!(
        &okp[..10],
        &[0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]
    );
    assert_eq!(&okp[10..], &x);
}

/// A passkey credential's JSON, with every member given.
fn passkey_json(rp_id: &str, credential_id: &[u8], user_handle: &[u8], key: &[u8]) -> String {
    format!(
        r#"{{"type":"passkey","credentialId":"{}","rpId":"{rp_id}","username":"alice","userDisplayName":"Alice","userHandle":"{}","key":"{}"}}"#,
        b64url_encode(credential_id),
        b64url_encode(user_handle),
        b64url_encode(key),
    )
}

/// A CXF document with one account holding `items` (JSON item objects).
fn document(items: &[String]) -> String {
    format!(
        r#"{{"version":{{"major":1,"minor":0}},"exporterRpId":"","exporterDisplayName":"test","timestamp":1700000000,"accounts":[{{"id":"AA","username":"","email":"","collections":[],"items":[{}]}}]}}"#,
        items.join(",")
    )
}

/// A CXF item holding `credentials`.
fn item(credentials: &[String]) -> String {
    format!(
        r#"{{"id":"AQ","title":"t","credentials":[{}]}}"#,
        credentials.join(",")
    )
}

/// An ES256 PKCS#8 key from a fixed scalar.
fn es256_key() -> Vec<u8> {
    let key = Es256SigningKey::from_bytes(&hex(APPENDIX_SCALAR)).unwrap();
    pkcs8::encode_es256(&key).expose_secret().to_vec()
}

#[test]
fn an_eddsa_passkey_gets_its_derived_okp_key_and_alg_2() {
    // RFC 8032 §7.1 TEST 1.
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let der = pkcs8::encode_eddsa_seed(&seed).unwrap();
    let doc = document(&[item(&[passkey_json(
        "example.com",
        b"cred",
        b"user",
        der.expose_secret(),
    )])]);
    let import = run(doc.as_bytes()).unwrap();
    let view = view(&import.items[0]);
    assert_eq!(view["passkey/0/alg"], V::E(2));
    assert_eq!(view["passkey/0/private_key"], V::Y(seed.clone()));
    let public = EdDsaSigningKey::from_seed(&seed)
        .unwrap()
        .verifying_key()
        .to_bytes();
    assert_eq!(
        public.as_slice(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    assert_eq!(
        view["passkey/0/public_key_cose"],
        V::Y(cose_key_ed25519(&public))
    );
    assert_eq!(view["passkey/0/created_ms"], V::U(1_700_000_000_000));
    assert_eq!(view[ITEM_NAME], V::T("Alice".to_owned()));
    assert_eq!(view[LOGIN_USERNAME], V::T("alice".to_owned()));
    assert_eq!(import.counts, Counts::default());
    assert!(import.warnings.is_empty());
}

#[test]
fn every_imported_item_passes_the_create_check() {
    let doc = document(&[
        item(&[passkey_json("a.example", b"c1", b"u1", &es256_key())]),
        item(&[
            passkey_json("b.example", b"c2", b"u2", &es256_key()),
            passkey_json("c.example", b"c3", b"u3", &es256_key()),
        ]),
    ]);
    let import = run(doc.as_bytes()).unwrap();
    // One Login item per passkey credential.
    assert_eq!(import.items.len(), 3);
    assert_eq!(
        import
            .items
            .iter()
            .map(ImportedItem::entry)
            .collect::<Vec<_>>(),
        [0, 1, 1]
    );
    for item in &import.items {
        check_create(
            item.item_type(),
            WriteMode::Import,
            item.writes().iter().map(|w| {
                (
                    WriteSource::Entered,
                    w.key().as_bytes(),
                    w.value().expose_secret(),
                )
            }),
        )
        .unwrap();
        assert!(
            item.writes()
                .windows(2)
                .all(|p| p[0].key().as_bytes() < p[1].key().as_bytes())
        );
    }
}

#[test]
fn names_fall_back_from_display_name_to_username_to_rp_id() {
    let key = b64url_encode(&es256_key());
    let credential = |username: &str, display: &str| {
        format!(
            r#"{{"type":"passkey","credentialId":"AQ","rpId":"rp.example","username":"{username}","userDisplayName":"{display}","userHandle":"AQ","key":"{key}"}}"#
        )
    };
    let doc = document(&[
        item(&[credential("bob", "")]),
        item(&[credential("", "Bob B")]),
        item(&[credential("", "")]),
    ]);
    let import = run(doc.as_bytes()).unwrap();
    let names: Vec<(V, Option<V>)> = import
        .items
        .iter()
        .map(|i| {
            let v = view(i);
            (v[ITEM_NAME].clone(), v.get(LOGIN_USERNAME).cloned())
        })
        .collect();
    assert_eq!(
        names,
        [
            (V::T("bob".to_owned()), Some(V::T("bob".to_owned()))),
            (V::T("Bob B".to_owned()), Some(V::T("Bob B".to_owned()))),
            (V::T("rp.example".to_owned()), None),
        ]
    );
}

#[test]
fn a_bad_credential_is_skipped_and_counted_never_the_file() {
    let good = passkey_json("ok.example", b"c", b"u", &es256_key());
    let mut p256_other_curve = es256_key();
    // prime256v1's last arc changed: an unsupported curve.
    let at = p256_other_curve
        .windows(8)
        .position(|w| w == hex("2a8648ce3d030107"))
        .unwrap();
    p256_other_curve[at + 7] = 0x06;
    let mut bad_point = es256_key();
    let last = bad_point.len() - 1;
    bad_point[last] ^= 1;
    let long_handle = vec![7u8; 65];
    let long_id = vec![7u8; 1025];
    let cases: Vec<(String, WarningKind)> = vec![
        (
            passkey_json("x.example", b"c", b"u", &p256_other_curve),
            WarningKind::UnsupportedKeyAlgorithm,
        ),
        (
            passkey_json("x.example", b"c", b"u", &bad_point),
            WarningKind::MalformedEntry,
        ),
        (
            passkey_json("x.example", b"c", &long_handle, &es256_key()),
            WarningKind::OversizeEntry,
        ),
        (
            passkey_json("x.example", &long_id, b"u", &es256_key()),
            WarningKind::OversizeEntry,
        ),
        (
            passkey_json("x.example", b"", b"u", &es256_key()),
            WarningKind::MalformedEntry,
        ),
        (
            passkey_json("", b"c", b"u", &es256_key()),
            WarningKind::MalformedEntry,
        ),
        (
            passkey_json(&"a".repeat(254), b"c", b"u", &es256_key()),
            WarningKind::OversizeEntry,
        ),
        (
            passkey_json("x.example", b"c", b"u", &[0u8; 256]),
            WarningKind::OversizeEntry,
        ),
        (
            passkey_json("x.example", b"c", b"u", b"not der"),
            WarningKind::MalformedEntry,
        ),
        (
            good.replace("\"key\":\"", "\"key\":\"="),
            WarningKind::MalformedEntry,
        ),
        (
            good.replace("\"credentialId\":\"Yw\"", "\"credentialId\":7"),
            WarningKind::MalformedEntry,
        ),
        (
            good.replace("\"type\":\"passkey\",", ""),
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":"basic-auth","username":{"fieldType":"string","value":"u"}}"#.to_owned(),
            WarningKind::CredentialTypeSkipped,
        ),
        ("17".to_owned(), WarningKind::MalformedEntry),
    ];
    for (credential, kind) in cases {
        let doc = document(&[item(&[credential.clone(), good.clone()])]);
        let import = run(doc.as_bytes()).unwrap();
        assert_eq!(import.items.len(), 1, "{credential}");
        assert_eq!(warnings(&import), [(Some(0), kind)], "{credential}");
        assert_eq!(import.counts.skipped_credentials, 1);
        assert_eq!(import.counts.skipped_items, 0);
    }
}

#[test]
fn an_item_without_a_passkey_or_a_credentials_array_is_skipped_and_counted() {
    let good = passkey_json("ok.example", b"c", b"u", &es256_key());
    let doc = document(&[
        item(&[]),
        r#"{"id":"AQ","title":"no credentials"}"#.to_owned(),
        "[]".to_owned(),
        item(&[good]),
    ]);
    let import = run(doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 1);
    assert_eq!(import.items[0].entry(), 3);
    assert_eq!(import.counts.skipped_items, 3);
    assert_eq!(
        warnings(&import),
        [
            (Some(1), WarningKind::MalformedEntry),
            (Some(2), WarningKind::MalformedEntry)
        ]
    );
}

#[test]
fn the_document_shape_is_checked() {
    for (doc, error) in [
        ("[]", ImportError::UnexpectedShape),
        ("{}", ImportError::UnexpectedShape),
        (
            r#"{"version":{"major":2,"minor":0},"timestamp":1,"accounts":[]}"#,
            ImportError::UpdateRequired,
        ),
        (
            r#"{"version":{"major":"1"},"timestamp":1,"accounts":[]}"#,
            ImportError::UnexpectedShape,
        ),
        (
            r#"{"version":{"major":1},"accounts":[]}"#,
            ImportError::UnexpectedShape,
        ),
        (
            r#"{"version":{"major":1},"timestamp":-1,"accounts":[]}"#,
            ImportError::UnexpectedShape,
        ),
        // A timestamp whose milliseconds overflow u64.
        (
            r#"{"version":{"major":1},"timestamp":18446744073709552,"accounts":[]}"#,
            ImportError::UnexpectedShape,
        ),
        (
            r#"{"version":{"major":1},"timestamp":1,"accounts":{}}"#,
            ImportError::UnexpectedShape,
        ),
        (
            r#"{"version":{"major":1},"timestamp":1,"accounts":[{"id":"AA"}]}"#,
            ImportError::UnexpectedShape,
        ),
        ("{", ImportError::Malformed),
        // A byte-order mark is skipped, as for every JSON format.
        ("\u{FEFF}{}", ImportError::UnexpectedShape),
    ] {
        assert_eq!(run(doc.as_bytes()).unwrap_err(), error, "{doc}");
    }
    // An unknown minor version, and members this reader does not know, are fine.
    let doc = r#"{"version":{"major":1,"minor":9},"timestamp":1,"accounts":[],"future":true}"#;
    let import = run(doc.as_bytes()).unwrap();
    assert!(import.items.is_empty());
}

#[test]
fn oversized_and_overfull_documents_are_refused_before_importing() {
    let mut big = vec![b' '; MAX_JSON_LEN + 1];
    big[0] = b'{';
    assert_eq!(run(&big).unwrap_err(), ImportError::TooLarge);

    let too_many = |n: usize| {
        let mut s = String::from(r#"{"version":{"major":1},"timestamp":1,"accounts":["#);
        for i in 0..n {
            if i > 0 {
                s.push(',');
            }
            s.push_str(r#"{"items":[]}"#);
        }
        s.push_str("]}");
        s
    };
    assert_eq!(
        run(too_many(MAX_ENTRIES + 1).as_bytes()).unwrap_err(),
        ImportError::TooMany
    );

    let mut items = String::new();
    for i in 0..=MAX_ENTRIES {
        if i > 0 {
            items.push(',');
        }
        items.push_str("{}");
    }
    let doc =
        format!(r#"{{"version":{{"major":1}},"timestamp":1,"accounts":[{{"items":[{items}]}}]}}"#);
    assert_eq!(run(doc.as_bytes()).unwrap_err(), ImportError::TooMany);

    let credentials = items.replace("{}", "0");
    let doc = format!(
        r#"{{"version":{{"major":1}},"timestamp":1,"accounts":[{{"items":[{{"credentials":[{credentials}]}}]}}]}}"#
    );
    assert_eq!(run(doc.as_bytes()).unwrap_err(), ImportError::TooMany);

    // Nesting deeper than the reader's cap.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert_eq!(run(deep.as_bytes()).unwrap_err(), ImportError::TooDeep);
}

#[test]
fn warnings_and_debug_carry_no_secret() {
    let doc = document(&[item(&[passkey_json("a.example", b"c", b"u", &es256_key())])]);
    let import = run(doc.as_bytes()).unwrap();
    let debug = format!("{import:?}");
    assert!(!debug.contains("011bbf"));
    assert!(!debug.contains("a.example"));
    assert!(!debug.to_lowercase().contains("alice"));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    /// Any well-formed passkey credential comes back field for field, its public key derived.
    #[test]
    fn any_valid_passkey_maps_field_for_field(
        rp_id in "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,3}",
        credential_id in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=1024),
        user_handle in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        seed in proptest::prelude::any::<[u8; 32]>(),
        eddsa in proptest::prelude::any::<bool>(),
        timestamp in 0u64..=u64::MAX / 1000,
    ) {
        let (der, alg, cose, private) = if eddsa {
            let public = EdDsaSigningKey::from_seed(&seed).unwrap().verifying_key().to_bytes();
            let der = pkcs8::encode_eddsa_seed(&seed).unwrap().expose_secret().to_vec();
            (der, 2, cose_key_ed25519(&public), seed.to_vec())
        } else {
            // A seed that is not a valid P-256 scalar (probability ~2^-32) falls back to a fixed
            // one.
            let key = Es256SigningKey::from_bytes(&seed)
                .unwrap_or_else(|_| Es256SigningKey::from_bytes(&hex(APPENDIX_SCALAR)).unwrap());
            let public = key.verifying_key();
            let der = pkcs8::encode_es256(&key).expose_secret().to_vec();
            (der, 1, cose_key_es256(&public.x(), &public.y()), key.to_bytes().expose_secret().to_vec())
        };
        let doc = document(&[item(&[passkey_json(&rp_id, &credential_id, &user_handle, &der)])])
            .replace("1700000000", &timestamp.to_string());
        let import = run(doc.as_bytes()).unwrap();
        proptest::prop_assert_eq!(import.items.len(), 1);
        let view = view(&import.items[0]);
        proptest::prop_assert_eq!(&view["passkey/0/rp_id"], &V::T(rp_id));
        proptest::prop_assert_eq!(&view["passkey/0/credential_id"], &V::Y(credential_id));
        proptest::prop_assert_eq!(&view["passkey/0/user_handle"], &V::Y(user_handle));
        proptest::prop_assert_eq!(&view["passkey/0/private_key"], &V::Y(private));
        proptest::prop_assert_eq!(&view["passkey/0/public_key_cose"], &V::Y(cose));
        proptest::prop_assert_eq!(&view["passkey/0/alg"], &V::E(alg));
        proptest::prop_assert_eq!(&view["passkey/0/created_ms"], &V::U(timestamp * 1000));
        proptest::prop_assert_eq!(import.counts, Counts::default());
    }

    /// Arbitrary bytes never panic the reader.
    #[test]
    fn arbitrary_input_never_panics(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
        let _ = run(&input);
    }
}
