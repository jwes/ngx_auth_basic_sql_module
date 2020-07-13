#!/bin/bash
# this test checks successful login using pgsql

# cleans db and starts nginx
. t/setup.sh
clean_db

psql "host=localhost dbname=testdb user=tester password=secretPassword" -c "CREATE TABLE users (id INTEGER, name VARCHAR(100), password VARCHAR(200));"

# add users
psql "host=localhost dbname=testdb user=tester password=secretPassword" -c "INSERT INTO users VALUES(1, 'alice@foo.ba', '\$apr1\$1qGJ6LJz\$3bAL/UIph6wDD.JCyyJcX/');"
psql "host=localhost dbname=testdb user=tester password=secretPassword" -c "INSERT INTO users VALUES(2, 'bob@foo.ba', '\$apr1\$AjxfsVys\$/YXk7b3aMjrmzYBDC14Xs0');"

psql "host=localhost dbname=testdb user=tester password=secretPassword" -c "INSERT INTO users VALUES(3, 'a2@foo.ba', '\$apr1\$1qGJ6LJz\$3bAL/UIph6wDD.JCyyJcX/');"
psql "host=localhost dbname=testdb user=tester password=secretPassword" -c "INSERT INTO users VALUES(4, 'a2@foo.ba', '\$apr1\$CiZHF6ss\$ibwCc6IyXd/NKNDVYOJqe/');"


setup_nginx

echo "1..6"
#ok
check_http alice@foo.ba:alice 1 200

#ok
check_http bob@foo.ba:bob 2 200

#not in db
check_http eve@foo.ba:eve 3 401

#duplicate pw entries
check_http a2@foo.ba:alice 4 401

#just pw in db
check_http zack:alice 5 401

#wrong combo
check_http bob:alice 6 401

