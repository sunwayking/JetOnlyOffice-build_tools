#!/bin/sh
set -eu

secret=${JWT_SECRET:-}
case "$secret" in
  ""|secret|default|changeme|change-me|onlyoffice|jetonlyoffice)
    echo "JWT_SECRET must be supplied and must not use a placeholder value" >&2
    exit 78
    ;;
esac

if [ "${JWT_ENABLED:-true}" != "true" ]; then
  echo "JWT_ENABLED must remain true for a release image" >&2
  exit 78
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

for candidate in \
  /app/ds/run-document-server.sh \
  /opt/jetonlyoffice/server/start.sh \
  /opt/jetonlyoffice/bin/start \
  /var/www/onlyoffice/documentserver/server/scripts/docservice; do
  if [ -x "$candidate" ]; then
    exec "$candidate"
  fi
done

echo "release image has no runtime command" >&2
exit 78
