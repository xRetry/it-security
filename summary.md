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

#### Safety measures
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

## Identity, Authentification, Access Controll

### Authentification Methods

#### Categories
- Knowledge:
    - Passwords
    - PINs
- Ownership
    - Tokens
    - Chip cards
- Biometric
    - Fingerprint
    - Voice

#### Passwords

Rules:
- No defaults
- Never write down
- Changeable by user
- Restrict number of trails
- Handling forgotten passwords

Attacks:
- Guess
- Brute force
- Dictionary attacks
- Rainbow tables
- Social Engineering, Phishing
- Observation
- Passwords in script files
- Sniffing (e.g. bluetooth keyboard)

Security Measurements:
- Never store unencrypted
- Usage of specific hashing algorithms
- Pro-active password checking
- User training
- Lockout mechanisms
- Password changes after security incidents
- Password safes

#### Chip cards
- Ownership
- Usage of cryptographic keys
- Private key never leaves card
- Usage: banks, healthcare

Attacks:
- Social engineering
- Man in the Middle
- Side channel attacks
- Physical

#### Biometric
- Biological property
- Hard to replace
- Hard to pass on
- Not perfect accuracy (False Acceptance Rate, False Rejection Rate)
- More expensive
- Can work worse for specific people

Attacks:
- Not 100% safe
- Spoofing
- Replay attacks
- Bypassing of sensors
- Brute force

#### FIDO2 - Fast Identity Online 2
- W3C as web API
TODO: Finish

#### Access Control
- Deny access of unwanted actors or at least detect
- Key Question: Hwo can access what and how?
- Auditioning
- Implementaiton of a security policy
- Usage: OS, databases, web servers

Dicretionary Access Controll (DAC):
- Each object has an owner
- Owner manages access

Role-Based Access Control (RBAC)
- Access determined by roles
- Users have roles

Mandatory Access Control (MAC)
- Objects and users have assigned rights
- Access only possible if rights of user are at least equal to object
- Usage: Military

Challenges:
- Concept of Least Privilege
- Single Sign On
- Who manages access control?
- Where is access checked?
- Technical implementation
- Technical separation

## Security in Software Development

Development methods for secure software:
- Comprehensive Lightweight Application Security Process (CLASP)
- Microsoft Security Development Lifecycle (SDL)
- Software Assurance Maturity Model (SAMM)

### Analysis Phase
- Requirements:
    - Functional and non-functional
    - Stakeholders
    - Norms, laws and standards
- Determination of:
    - Threats and risks
    - Attack vectors
    - Safety targets
- Tools:
    - Attack Tress: Representation of events as tree, with edges as probabilities
    - Threat Modeling: Identifying threats by "thinking as the attacker"

### Drafting Phase
- Robust architecture as foundation
- Best practices:
    - Security Patterns: of common security challenges
    - Attack Patterns: Description of attacks and conditions
    - UML Modelling: e.g. UMLsec

#### Design Principles
- Simplicity
- Fail-safe defaults: Each default state should be secure; Return to default state if attack
- Complete access validation (Complete Meditation)
- Open Design: Security should not rely on secrecy
- Separation of Privilege (4-Augen-Prinzip)
- Least Privilege: Don't allow more right than necessary
- Least Common Mechanism: Avoid shared variables/files
- Psychological Acceptability: Simple usability

### Implementation Phase
To make code safe:
- Avoid common security mistakes 
- Follow programming guidelines
- Follow language specific security methods
- Use code review
- Avoid Penetrate and Patch

#### Attacks
- SQL injection
- Command injection
- Cross-Site-Scripting: Inputs put into DOM -> Script insertion
    - Reflected XSS: Attacker sends manipulated link
    - Stored XSS: Attacker changes the server itself
- Cross-Site-Request-Forgery: TODO: Explain
- Buffer Overflows

### Production Phase
- Detection of incidents
- Reactive countermeasures
- Service Level Agreement (SLA)
- Information Technology Infrastructure Library (ITIL)

## Testing
- Validation: Do we build the correct product?
- Verification: Do we build the product correct?

### Characteristics (Merkmalsräume)

#### Testing criterion
- Question: What gets tested?
- Functional tests: Specification/Use cases as basis, Independent
- Non-functional tests: Abuse cases as basis, Not independent

#### Testing layer
- Question: Which phase of the life cycle gets tested
- Earlier is better but mistakes can be more severe
- Abuse cases: In drafting phase
- Static code analysis: In implementation phase
- Penetration tests: In deployment phase
- Risk analysis: In design and deployment phase

#### Testing Methodology
- Question: Which testing methods should be used
- White-Box-Tests: Use system knowledge
- Black-Box-Tests: Don't use system knowledge, just check inputs/outputs
- Gray-Box-Tests: Combination both

### Techniques

#### Static Code Analysis
- Check code without running, Manual or Automatic (Compiler)
- Secure code review: Expensive but effective
- Automatic analysis: 
    - Signature based: Check for patterns
    - Control flow based: Check execution order
    - Data flow based: ?

#### Fuzzing
- Test randomly generated inputs
- For different formats/protocols
- Distinction:
    - Input creation: Generation based vs Mutation based
    - Smartness: Random vs Template vs Block vs Evolution based
- Error detection: Changes in performance, log entries, ...

#### Penetration Testing
- Testing under "real" conditions
- Showing weaknesses on the running system
- Late in life cycle (expensive to fix)
- Phases:
    - Pre-Engagement
    - Intelligence Gathering
    - Threat Modelling
    - Vulnerability Analysis
    - Exploitation
    - Post-Exploitation
    - Reporting

#### Ethical Hacking
- Finding weaknesses without exploitation for personal profit

### Vulnerability Disclosure
- Responsible Disclosure: Only tell company and wait for a while for them to fix it
- Full Disclosure: Tell public as soon as possible to make sure everyone is aware and company is under pressure to fix it

## Organisational Security

### Security Measurements
- Teaching employees
- Regular backups
- Safe deletion of sensible data
- Updates
- Documentation of processes, security requirements, configurations, service numbers, SLAs, user rights, ...
- Definition of a IT security manager

### Security Policy
- Contains IT Goals and security strategy and prescriptions (How to handle specific components)
- Employees are one of the biggest risks
- Continuous updates

### Security Management Process (PDCA)
- Plan: Create security policy/management
- Do: Implement the policies and collect data/information
- Check: Regularly perform tests, audits, exercises and create reports
- Act: Identify issues and update the policies/management accordingly

### Norms and Standards
- Certifications allow trust in IT security
- Can be basis contracts

#### ISO 27k Series
- Selection of appropriate security checks
- Everything related to ISMS

#### Information Technology Infrastructure Library (ITIL)
- Based on ISO 27001
- Best practices
- Guidelines and how to implement them
- Process oriented

#### IT-Grundschutz

### IT Security Concept
- Contents: Measures to implement and maintain a defined security level
- What do I want to protect?
- Against whom?
- How?
- Can I afford that?

### Business Continuity
- Measures to allow business to continue in case of an active threat

## Risk Management

### Risk Management Process
Steps:
- Preparation: Determination of responsibilities, risk tolerance and analysis methods
- Risk identification
- Risk evaluation: Estimation of severity and frequency
- Risk handling: Acceptance, avoidance, mitigation, transfer
- Risk control: Continous analysis, documtation and reporting to leadership

### IT Grundschutz

#### Initialization
- Responsibility
- Panning the approach
- Creating guidelines

#### Organization
- Integration in processes
- Distribution of responsibilties and roles

#### Documentation
- Classification of information
- Reports to leadership

#### Security Concepts
- Basic Protection: Implementation of basic requirements
- Core Protection: Focus on essential assets first
- Standard Protection: Complete implementation of the IT Grundschutz

- IT Grundschutz Check: Soll-Ist Vergleich + Dokumentation

#### Implementation
- Cost-value estimation
- Determination of implementation order
- Implementation related measures

#### Maintenance and Improvement
- Monitoring the implementation
- Re-evalutation of the strategy

## Factor Human
- Interdisciplinary cybersecurity approach
- Identification of a wider set of vulnerabilities
- Allows the creation of a trusworthy digital environment

### Threats
- Malicious insider
- Phishing
- Identity spoofing
- Social engineering
