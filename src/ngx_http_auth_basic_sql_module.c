
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Johannes Westhuis
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_crypt.h>
#include <ngx_http.h>
#include <postgresql/libpq-fe.h>

#define NGX_HTTP_AUTH_BUF_SIZE 2048

typedef struct
{
  ngx_http_complex_value_t* realm;
  ngx_http_complex_value_t* connstring;
  ngx_http_complex_value_t* query;
} ngx_http_auth_basic_sql_loc_conf_t;

static ngx_int_t
ngx_http_auth_basic_sql_handler(ngx_http_request_t* r);
static ngx_int_t
ngx_http_auth_basic_sql_crypt_handler(ngx_http_request_t* r,
                                      ngx_str_t* passwd,
                                      ngx_str_t* realm);
static ngx_int_t
ngx_http_auth_basic_sql_set_realm(ngx_http_request_t* r, ngx_str_t* realm);
static void*
ngx_http_auth_basic_sql_create_loc_conf(ngx_conf_t* cf);
static char*
ngx_http_auth_basic_sql_merge_loc_conf(ngx_conf_t* cf,
                                       void* parent,
                                       void* child);
static ngx_int_t
ngx_http_auth_basic_sql_init(ngx_conf_t* cf);

static ngx_command_t ngx_http_auth_basic_sql_commands[] = {

  { ngx_string("auth_basic_sql"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
    ngx_http_set_complex_value_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_sql_loc_conf_t, realm),
    NULL },

  { ngx_string("auth_basic_sql_connection_string"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
    ngx_http_set_complex_value_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_sql_loc_conf_t, connstring),
    NULL },

  { ngx_string("auth_basic_sql_query"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
    ngx_http_set_complex_value_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_sql_loc_conf_t, query),
    NULL },

  ngx_null_command
};

static ngx_http_module_t ngx_http_auth_basic_sql_module_ctx = {
  NULL,                         /* preconfiguration */
  ngx_http_auth_basic_sql_init, /* postconfiguration */

  NULL, /* create main configuration */
  NULL, /* init main configuration */

  NULL, /* create server configuration */
  NULL, /* merge server configuration */

  ngx_http_auth_basic_sql_create_loc_conf, /* create location configuration */
  ngx_http_auth_basic_sql_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_basic_sql_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_basic_sql_module_ctx, /* module context */
  ngx_http_auth_basic_sql_commands,    /* module directives */
  NGX_HTTP_MODULE,                     /* module type */
  NULL,                                /* init master */
  NULL,                                /* init module */
  NULL,                                /* init process */
  NULL,                                /* init thread */
  NULL,                                /* exit thread */
  NULL,                                /* exit process */
  NULL,                                /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_basic_sql_handler(ngx_http_request_t* r)
{
  ngx_int_t rc, num;
  ngx_str_t pwd, realm, connstring, query;
  ngx_uint_t pos, len, remaining;
  ngx_http_auth_basic_sql_loc_conf_t* alcf;
  unsigned char querybuf[4096];
  unsigned char* match;
  char *m, *buf, *value;

  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_sql_module);

  if (alcf->realm == NULL) {
    return NGX_DECLINED;
  }
  if (alcf->connstring == NULL) {
    return NGX_DECLINED;
  }
  if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
    return NGX_ERROR;
  }
  if (ngx_http_complex_value(r, alcf->connstring, &connstring) != NGX_OK) {
    return NGX_ERROR;
  }
  if (ngx_http_complex_value(r, alcf->query, &query) != NGX_OK) {
    return NGX_ERROR;
  }
  match = ngx_strnstr(query.data, "%user%", query.len);
  if (!match) {
    ngx_log_error(NGX_LOG_ERR,
                  r->connection->log,
                  0,
                  "no user marker in query: %V",
                  &query);
    return NGX_ERROR;
  }

  pos = len = match - query.data;
  ngx_memcpy(querybuf,
             query.data,
             pos); // copy everything up until the user part
  querybuf[pos++] = '$';
  querybuf[pos++] = '1';
  len = query.len - (len + 6); // 6 for %user%
  remaining = query.len - len;

  ngx_memcpy(querybuf + pos, query.data + remaining, len);
  querybuf[pos + len] = '\0';

  if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
    return NGX_DECLINED;
  }

  rc = ngx_http_auth_basic_user(r);

  if (rc == NGX_DECLINED) {
    ngx_log_error(NGX_LOG_INFO,
                  r->connection->log,
                  0,
                  "no user/password was provided for basic authentication");

    return ngx_http_auth_basic_sql_set_realm(r, &realm);
  }

  if (rc == NGX_ERROR) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  m = ngx_strchr(r->headers_in.user.data, ':');
  if (!m) {
    ngx_log_error(NGX_LOG_ERR,
                  r->connection->log,
                  0,
                  "no match in user str %s",
                  r->headers_in.user.data);
    return NGX_ERROR;
  }
  len = ((u_char*)m) - r->headers_in.user.data;

  pwd.len = 0;
  PGconn* pgconn = PQconnectdb((char*)connstring.data);
  if (pgconn) {
    buf = (char*)malloc(len + 1);
    ngx_memcpy(buf, r->headers_in.user.data, len);
    buf[len] = '\0';

    PGresult* result = PQexecParams(pgconn,
                                    (const char*)querybuf,
                                    1,
                                    NULL,
                                    (const char* const*)&buf,
                                    NULL,
                                    NULL,
                                    0);
    free(buf);
    if (result) {
      num = PQntuples(result);
      if (num == 1) {
        value = PQgetvalue(result, 0, 0);
        if (value) {
          pwd.len = strlen(value);
          pwd.data = (u_char*)value;
        }
      } else {
        ngx_log_error(NGX_LOG_ERR,
                      r->connection->log,
                      0,
                      "db query should return 1 result, but returned %d rows",
                      num);
      }
      PQclear(result);
    }
    PQfinish(pgconn);
  }

  if (pwd.len) {
    rc = ngx_http_auth_basic_sql_crypt_handler(r, &pwd, &realm);
  } else {
    rc = ngx_http_auth_basic_sql_set_realm(r, &realm);
  }

  return rc;
}

static ngx_int_t
ngx_http_auth_basic_sql_crypt_handler(ngx_http_request_t* r,
                                      ngx_str_t* passwd,
                                      ngx_str_t* realm)
{
  ngx_int_t rc;
  u_char* encrypted;

  rc = ngx_crypt(r->pool, r->headers_in.passwd.data, passwd->data, &encrypted);

  ngx_log_debug3(NGX_LOG_DEBUG_HTTP,
                 r->connection->log,
                 0,
                 "rc: %i user: \"%V\" salt: \"%s\"",
                 rc,
                 &r->headers_in.user,
                 passwd->data);

  if (rc != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (ngx_strcmp(encrypted, passwd->data) == 0) {
    return NGX_OK;
  }

  ngx_log_debug1(
    NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "encrypted: \"%s\"", encrypted);

  ngx_log_error(NGX_LOG_ERR,
                r->connection->log,
                0,
                "user \"%V\": password mismatch",
                &r->headers_in.user);

  return ngx_http_auth_basic_sql_set_realm(r, realm);
}

static ngx_int_t
ngx_http_auth_basic_sql_set_realm(ngx_http_request_t* r, ngx_str_t* realm)
{
  size_t len;
  u_char *basic, *p;

  r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
  if (r->headers_out.www_authenticate == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  len = sizeof("Basic realm=\"\"") - 1 + realm->len;

  basic = ngx_pnalloc(r->pool, len);
  if (basic == NULL) {
    r->headers_out.www_authenticate->hash = 0;
    r->headers_out.www_authenticate = NULL;
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
  p = ngx_cpymem(p, realm->data, realm->len);
  *p = '"';

  r->headers_out.www_authenticate->hash = 1;
  ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
  r->headers_out.www_authenticate->value.data = basic;
  r->headers_out.www_authenticate->value.len = len;

  return NGX_HTTP_UNAUTHORIZED;
}

static void*
ngx_http_auth_basic_sql_create_loc_conf(ngx_conf_t* cf)
{
  ngx_http_auth_basic_sql_loc_conf_t* conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_sql_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  return conf;
}

static char*
ngx_http_auth_basic_sql_merge_loc_conf(ngx_conf_t* cf,
                                       void* parent,
                                       void* child)
{
  ngx_http_auth_basic_sql_loc_conf_t* prev = parent;
  ngx_http_auth_basic_sql_loc_conf_t* conf = child;

  if (conf->realm == NULL) {
    conf->realm = prev->realm;
  }

  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_basic_sql_init(ngx_conf_t* cf)
{
  ngx_http_handler_pt* h;
  ngx_http_core_main_conf_t* cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_basic_sql_handler;

  return NGX_OK;
}
