# vscan-http-response-size-analyzer
Analyzes HTTP response sizes to detect anomalies that might indicate data exfiltration or denial-of-service vulnerabilities. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-http-response-size-analyzer`

## Usage
`./vscan-http-response-size-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided
- `-w`: Path to a wordlist for directory brute-forcing.
- `-d`: Attempt to detect the technology stack used by the website.

## License
Copyright (c) ShadowGuardAI

## Failure behaviour
If the primary URL cannot be fetched, or a wordlist given with -w cannot be opened, the run prints a failure summary and exits non-zero. Directory brute-force records the status and size of error responses (such as 401, 403, and 404) as results, because those responses are the data this analyzer reports.
