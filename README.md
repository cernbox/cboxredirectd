# CERNBox Reverse Proxy for EOSHOME migration

This daemon is the brain for the EOSHOME migration. Its state is stored in a Redis database that is consulted every time a request arrives.
Depending on the state stored in the database, the server forwards the request to the old proxy (--old-proxy) or to the new proxy (--new-proxy).


There are 4 default configuration keys in Redis to control the default behaviour on known corner cases, all these keys can only have the values *old-proxy* or *new-proxy*.
Any other value for the default keys will abort the incoming request and respond with 500 (Internal Server Error).

- default-non-dav-request: sets the default behaviour for non WebDAV requests, like the ones for the web ui (index.php/apps ...) 
- default-generic-or-unauthenticated-dav-request: sets the default behaviour for WebDAV paths that point to other areas outside /eos/user and /eos/project, like /eos/atlas or /eos/notfound. It also applies for unauthenticated WebDAV requests.
- default-user-not-found: sets the default behaviour when the user key is not found in Redis
- default-project-not-found: sets the default behaviour when the project key is not found in Redis

For the CERNBox Reverse Proxy to work, these 4 keys must be set in Redis, else the server will abort with 500 (Internal Server Error).

To control the migration state of individual users and projects, it is necessary to set a key in Redis with the homedirectory of the user or the project area, like /eos/user/l/labradorsvc or /eos/project/c/cbox.
The value of the key can only be *migrated* or *not-migrated*, any other value will abort with 500 (Internal Server Error).


## Redis commands
set default-non-dav-request old-proxy
set default-generic-or-unauthenticated-dav-request old-proxy
set default-user-not-found old-proxy
set default-project-not-found old-proxy

set /eos/user/g/gonzalhu not-migrated
set /eos/user/g/gonzalhu migrated
set /eos/user/g/gonzalhu migrating



