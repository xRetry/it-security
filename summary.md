## Introduction

### Challenges

- Complex systems
- Interaction between components
- Creativity of attackers
- Security vs. Usability

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
- Encoding with public key -> only private key can decode
- Signing with private key -> can be decoded with public key
- Requires more computing resources

### Hybrid Cryptography
- Encode document with symmetric key
- Encode symmetric key with asymmetric key
- Send encrypted document and symmetric key
- Decrypt symmetric key with asymmetric key
- Decrypt document with symmetric key

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
- Multiple connectors possible (LDAP, OCSP)

#### Certificate Revocation
- Handles the case, when a private key is compromised
- Invalidates all compromised signatures
- Distribution of information over Certificate Revocation List (CRL) or Online Certificate Protocol (OCSP)
- Applications need to check the validity of received certificates

#### Time Stamp Services (TSA)
- Ensures the integrity of time information
- Client sends hash of document -> TSA adds time stamp and signs combination -> client adds time stamp to document

#### Hierarchical Structure
- Tree of CAs
- Root CA signs children CA and so on

### Certificates
- Adds an identity to private keys
- Is public
- Additional information: expiration time, creator (CA), intended usage, ...
- Validity models: chain model, peel model and hybrid models
 
### Transport Layer Security (TLS)
- For one or two directional authentication and encrypted communication
- Encryption only on Layer 4 possible
- Replaced SSL
- HTTPS = HTTP over TLS
- Cipher Suite: Defines the cryptographic methods for communication, which gets negotiated between both partners

## Network Security

### TCP/IP model:
- Application Layer (HTTP)
- Transport Layer (TCP, UDP)
- Network Layer (IP)
- Data Link Layer (Ethernet)
- Physical Layer (LAN)

### Example Attacks

#### ARP - Address Resolution Protocol
- Translates between hardware and IP addresses
- Spoofing: Man in the Middle can catch and alter ARP messages

#### IP - Internet Protocol
- Address Spoofing: Changing source and destination address in IP header

#### ICMP - Internet Control Message Protocol
- Smurf attack: Attacker can use smurf machines to overwhelm target with ICMP requests

#### TCP - Transmission Control Protocol
- SYN Flooding: Target gets overwhelmed by SYN requests

### WLAN
- Potentially unsafe networks
- Attacks: Sniffing, Spoofing of access point or client, DoS

#### Safety measurements
General:
- No WEP (unsafe)
- Good passwords for WPA, WPA2 
- WPA3
- VPNs
- Application layer encryption
- Change default passwords
- SSID
- Change keys regularly

Sniffing:
- Network segmentation
- Securing the transport (VPN, TLS)
- Limiting access (Firewall)
- Encryption of data
- Intrusion detection systems

### Firewalls
- Goal: Restricting un-allowed access
- Types: packet filtering, stateful inspection, proxy firewall
- Placement: at network borders

### Intrusion Detection Systems
- Detection of attacks (signatures, anomalies)
- Sending alarms
- E.g. Snort, Zeek
- Intrusion Prevention System: Additionally enact countermeasures (e.g. activation of firewall rules)

### Honeypots
- Fake instance of real system
- Are an complementary safety mechanism
- Honeynet = network of honeypots

