## ByteBait
## Summary
ByteBait is a honeypot solution that leverages automated tools within its honeypot environment to analyze the attacker's behaviours/attack patterns.

It is built on HellPot

The main idea of ByteBait is to bait hackers into attacking a fake website that mimics the real website. This will not only divert them from the actual website, it will also allow us to capture the behaviour of the attackers in a controlled environment.

## Setup
git clone https://github.com/NowShut/ICT2214_17.git

cd HellPot

make

Generate config file using ./HellPot --genconfig

Edit your newly generated HellPot.toml as desired.

Run the honeypot using ./HellPot -c config.toml

## Features
ML analysis of attack patterns
Dashboard
For demonstration purposes, the dashboard is integrated into the honeypot web server.

Bring up the dashboard by adding /dashboard at the back of the URL. All malicious traffic coming into the honeypot will be displayed here and can be monitored in real-time.

Any user interaction with the honeypot will be logged and monitored by the honeypot followed by analysis and prediction of any potential attack which may be carried out. The code makes use a pre-trained model to predict what attacks the user is trying to do based on their inputs in the input fields. Once the attack is predicted it will be sent over as a post request to the HTTP server in order with the attack type and source IP address shown. Which we will proceed to block the IP address and further undergo mitigation and or prevention of the potential attack.
