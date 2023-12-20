#!/usr/bin/env bash
set -e
export AEOLUS_INITIAL_DIRECTORY=$(pwd)

maven () {
  echo '⚙️ executing maven'
  mvn clean test -Pcoverage
}

movereportfile () {
  echo '⚙️ executing move_report_file'
  mv target/tia/reports/*/testwise-coverage-*.json target/tia/reports/tiaTests.json
  mkdir -p /var/tmp/aeolus-results
  shopt -s extglob
  local _sources="target/tia/reports/tiaTests.json"
  local _directory
  _directory=$(dirname "${_sources}")
  mkdir -p /var/tmp/aeolus-results/"${_directory}"
  cp -a "${_sources}" /var/tmp/aeolus-results/target/tia/reports/tiaTests.json
}

junit () {
  echo '⚙️ executing junit'
  #empty script action, just for the results
  mkdir -p /var/tmp/aeolus-results
  shopt -s extglob
  local _sources="**/target/surefire-reports/*.xml"
  local _directory
  _directory=$(dirname "${_sources}")
  mkdir -p /var/tmp/aeolus-results/"${_directory}"
  cp -a "${_sources}" /var/tmp/aeolus-results/**/target/surefire-reports/*.xml
}

final_aeolus_post_action () {
  set +e # from now on, we don't exit on errors
  echo '⚙️ executing final_aeolus_post_action'
  cd "${AEOLUS_INITIAL_DIRECTORY}"
  junit "${_current_lifecycle}"
  cd "${AEOLUS_INITIAL_DIRECTORY}"
}

main () {
  local _current_lifecycle="${1}"
    if [[ "${_current_lifecycle}" == "aeolus_sourcing" ]]; then
    # just source to use the methods in the subshell, no execution
    return 0
  fi
  local _script_name
  _script_name=$(realpath "${0}")
  trap final_aeolus_post_action EXIT
  bash -c "source ${_script_name} aeolus_sourcing;maven ${_current_lifecycle}"
  cd "${AEOLUS_INITIAL_DIRECTORY}"
  bash -c "source ${_script_name} aeolus_sourcing;movereportfile ${_current_lifecycle}"
  cd "${AEOLUS_INITIAL_DIRECTORY}"
}

main "${@}"
