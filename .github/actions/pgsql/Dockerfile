# Container image that runs your code
FROM debian:bullseye-slim

COPY entrypoint.sh /entrypoint.sh

RUN apt-get update && apt-get install -y \
	nginx \
	postgresql-client \
	postgresql \
	perl \
	curl



ENTRYPOINT ["/entrypoint.sh"]

