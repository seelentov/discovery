#!/bin/sh
# Same logic as ../debian/prerm.
set -e

systemctl stop discovery-agent.service || true
systemctl disable discovery-agent.service || true

exit 0
