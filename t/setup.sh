function clean_db {
  /etc/init.d/postgresql restart
  su - postgres -c $PWD/t/reset_db.sh
}

#psql -c 'CREATE TABLE users (id INTEGER, name VARCHAR(100), password VARCHAR(200));' testdb

function setup_nginx {
  FILE=/etc/nginx/modules-enabled/77-mod-http-test.conf
  echo "" > $FILE
  files=$(ls *.so)
  echo "found files $files"
  if [[ -n $files ]]; then
    for lib in $files; do
      echo "load_module $PWD/$lib;" 
      echo "load_module $PWD/$lib;" >> $FILE
    done
  fi
  cp $PWD/conf/nginx.conf /etc/nginx/sites-enabled/test.conf
  echo "<body>success!</body>" >> /var/www/html/test.html
  /etc/init.d/nginx restart
}

function check_http {
  local response_code=$(curl --write-out "%{response_code}" -s -o /dev/null -u "$1" localhost:8123/test.html)
  if [[ $response_code -eq $3 ]]; then
    echo "ok $2 returned $response_code"
  else
    echo "not ok $2 returned $response_code expected $3"
  fi
}

