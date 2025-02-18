if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>"
  exit 1
fi

INTERFACE_NAME="$1"

sudo ip link delete "$INTERFACE_NAME" 