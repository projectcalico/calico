unset -f pause-for-debug

function pause-for-debug() {
  # Stop for debug
  echo "Check for pause file..."
  while [ -f /home/semaphore/pause-for-debug ];
  do
    echo "#"
    sleep 30
  done
}

pause-for-debug

