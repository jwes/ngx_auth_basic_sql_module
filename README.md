About
=====

ngx_basic_auth_sql_module is a `nginx` module that provides basic authentication with an sql backend

It is a fork of the `nginx` auth_basic module. 

[![Actions Status](https://github.com/jwes/ngx_auth_basic_sql_module/workflows/CI/badge.svg)](https://github.com/jwes/ngx_auth_basic_sql_module/actions)


Configuration directives
========================
auth_basic_sql
---------------
* **syntax**: `auth_basic_sql realm | off
* **default**: `off`
* **context**: `http, server, location, limit_except'


Enables validation of user name and password using the “HTTP Basic Authentication” protocol. The specified parameter is used as a realm. Parameter value can contain variables (1.3.10, 1.2.7). The special value off allows cancelling the effect of the auth_basic directive inherited from the previous configuration level.

auth_basic_sql_connection_string
--------------------------------
* **syntax**: `auth_basic_sql_connection_string "dbname testdb"
* **context**: `http, server, location, limit_except'

Specifies connection parameters used to connect to your database system.
See: https://www.postgresql.org/docs/9.3/libpq-connect.html#LIBPQ-CONNSTRING for `PostgreSQL` examples 

auth_basic_sql_query
--------------------
* **syntax**: `auth_basic_sql_query "SELECT password FROM users WHERE name=%user%"
* **context**: `http, server, location, limit_except'

Specifies a SQL query to fetch the password hash that the given credentiales can be matched with.
`%user%` will be replaced with the entered username
You need to ensure, that the query returns just one result column with exactly one result row. 
If you fail to do so, the authentication will be declined, due to the ambiguity.

Example Configuration #1
========================

```
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
        server_name _;

        location / {
                auth_basic_sql "realm";
                auth_basic_sql_connection_string "dbname=testdb user=testuser";
                auth_basic_sql_query "SELECT password FROM users WHERE name=%user%";
                try_files $uri $uri/ =404;
        }
}
```

TODO
====

At the moment only `PostgreSQL` is supported.
* extract driver interface
* support more sql backends  

LICENSE
=======

BSD License: see LICENSE file
