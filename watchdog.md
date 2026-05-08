# Step 1: Build target list
subfinder -d target.com -silent > targets.txt

# Step 2: Baseline (first run stores current state)
python3 watchdog.py scan -f targets.txt

# Step 3: Monitor forever (60min intervals)
python3 watchdog.py watch -f targets.txt --interval 60

# Step 4: Alerts fire → verify with nuclei
python3 watchdog.py export -o ready.txt
nuclei -l ready.txt -t takeovers/

# Step 5: Full pipeline (alerts go directly to nuclei)
python3 watchdog.py watch -f targets.txt | \
  jq -r '.nuclei_target' | \
  nuclei -t takeovers/

# Step 6: With Slack
python3 watchdog.py watch -f targets.txt \
  --webhook https://hooks.slack.com/services/YOUR/HOOK

# Inspect what changed on a domain
python3 watchdog.py history api.target.com

# See all pending alerts
python3 watchdog.py alerts


# TITE
# Install
sudo dnf install -y golang && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && export PATH=$PATH:~/go/bin

# Generate targets.txt
subfinder -d target.com -silent -o targets.txt

# Multiple domains at once
subfinder -d target.com -d target2.com -silent -o targets.txt
