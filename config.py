IS_TEST=False

if IS_TEST==False:
    NMAP_PATH = '/usr/bin/nmap'
    MASSCAN_PATH = '/usr/bin/masscan'
    WEBANALYZE_PATH = '/opt/fingerprint/webanalyze'
    DISMAP_PATH = '/opt/fingerprint/dismap-0.4-linux-amd64'
    OBSERVER_PATH = '/opt/fingerprint/observer_ward'
    DALFOX_PATH = '/opt/fingerprint/dalfox'
else:
    NMAP_PATH = '/usr/local/bin/nmap'
    MASSCAN_PATH = '/opt/homebrew/bin/masscan'
    WEBANALYZE_PATH = '/Users/thirdScan/webanalyze'
    DISMAP_PATH = '/Users/thirdScan/dismap-0.4-darwin-arm64'
    OBSERVER_PATH = '/Users/thirdScan/observer_ward'
    DALFOX_PATH = '/opt/homebrew/bin/dalfox'



NMAP_USE_CACHE=False
MASSCAN_USE_CACHE=False

# NMAP_USE_CACHE=True
# MASSCAN_USE_CACHE=True

