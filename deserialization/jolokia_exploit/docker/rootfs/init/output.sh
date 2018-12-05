
RED='\033[38;5;202m'
GREEN='\033[38;5;70m'
BLUE='\033[38;5;141m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

log_output() {

  level="${1}"
  message="${2}"
  printf "$(date +"[%Y-%m-%d %H:%M:%S %z]") %b %b\n" "${level}"  "${message}"
}

log_info() {
  message="${1}"
  log_output "${NC}" "${message}"
}

log_warn() {
  message="${1}"
  log_output "${BLUE}${BOLD}WARNING${NC}" "${message}"
}

log_WARN() {
  message="${1}"
  log_output "${RED}${BOLD}WARNING${NC}" "${RED}${BOLD}${message}${NC}"
}

log_error() {
  message="${1}"
  log_output "${RED}${BOLD}ERROR${NC}" "${message}"
}

