dropdb testdb
createdb testdb
psql -c "CREATE USER tester PASSWORD 'secretPassword';" testdb
psql -c "GRANT ALL ON database testdb  TO tester;" testdb
exit
