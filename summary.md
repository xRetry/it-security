## Introduction

### Challenges

- Complex systems
- Interaction between components
- Creativity of attackers
- Security vs. Usabillity

### Security

.. is a situation, where the risk is smaller than the risk-tolerance (Grenzrisiko).

- Risk = damage * probability
- Security goals: CIA-Triad (Confidentiality, Integrity, Availability)

### Categories

#### Unallowed Access
- Sniffing
- Man in the middle

#### Deception
- Spoofing
- Man in the middle

#### Functionality Interruption
- Denial of Service (DoS)
- Distributed Denial of Service (DDoS)

#### Unallowed Usage
- Command Injection

### Attacking Steps
1. Collecting information
2. Exploiting security problems
3. Using the access
4. Hiding steps

### Risk Analysis

..contains:

- Thread groups (target, source, motivation, probability, costs)
- Threads
- Risk analysis/evaluation
- Actions
- Estimation of rest risk

## Cryptography

### Symmetric Cryptography
- Same key for encoding and decoding
- Sharing keys can be problematic

### Asymmetric Cryptography
- Encoding with pubilc key -> only private key can decode
- Signing with private key -> can be decoded with public key
- Requires more computing resources

### Hybrid Cryptography
- Encode document with symmetric key
- Encode symmetric key with asymmetric key
- Send encrypted document and symmetric key
- Decrypt symmetric key with asymetic key
- Decrypt document with symmetic key

### Challenges
- Methods are complex
- Methods become out-of-date
- Compromised private keys
- Key contains no information about owner

### Chipcards
- Storage cards: No access restriction
- Processor cards: OS manages access (e.g. PIN)
- Attacks: side channel attacks, physical, man in the middle, social engineering

### Public Key Infrastructure (PKI)

#### Registration Authority (RA)
- Registers new users
- Blocks user

#### Certification Authority (CA)
- Creates and manages certificates
- Storage of private keys -> special safety requirements

#### Directory Service (DIR)
- Manages access to public certificates
- Multiple connetors possible (LDAP, OCSP)

#### Certificate Revocation
- Handles the case, when a private key is compromised
- Invalidates all compromised signatures
- Distribution of information over Certificate Revocation List (CRL) or Online Certificate Protocol (OCSP)
- Applications need to check the validity of received certificates

#### Time Stamp Services (TSA)
- Ensures the ihtegrity of time information
- Client sends hash of document -> TSA adds timestamp and signs combination -> client adds timestamp to document

#### Hierarchical Structure
- Tree of CAs
- Root CA signs children CA and so on

### Certificates
- Adds an identity to private keys
- Is public
- Additional information: expiration time, creator (CA), intended usage, ...
- Validity models: chain model, peel model and hybrid models
 
### Transport Layer Security (TLS)
- For one or two directional authentification and encrytped communication
- Encryption only on Layer 4 possible
- Replaced SSL
- HTTPS = HTTP over TLS
- Cipher Suite: Defines the cryptographic methods for communication, which gets negotiated between both partners
